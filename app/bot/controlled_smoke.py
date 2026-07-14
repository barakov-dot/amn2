import asyncio
import hashlib
import math
import os
import sqlite3
import stat
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aiogram.exceptions import TelegramAPIError

from app.bot.handlers import handle_start
from app.config import Settings
from app.main import create_bot, create_workflow_from_settings


REQUIRED_SMOKE_TABLES = {
    "admin_actions",
    "devices",
    "orders",
    "users",
}


class ControlledSmokeError(RuntimeError):
    pass


@dataclass(frozen=True)
class ControlledStartSmokeConfig:
    admin_id: int
    configured_admin_ids: frozenset[int]
    expected_bot_username: str
    production_database_path: Path
    clone_database_path: Path
    timeout_seconds: float = 120


@dataclass(frozen=True)
class ControlledStartSmokeResult:
    bot_identity: str
    pending_update_count: int
    production_database_unchanged: bool
    clone_database_changed: bool
    clone_counts_unchanged: bool

    def render(self) -> str:
        return "\n".join(
            [
                "controlled_start_smoke=pass",
                f"bot_identity={self.bot_identity}",
                "webhook_configured=false",
                f"pending_update_count={self.pending_update_count}",
                "accepted_update=selected_admin_exact_start",
                "allowed_updates=message_only",
                "callback_routes_registered=false",
                "accepted_update_acknowledged=true",
                f"production_database_unchanged={_bool_text(self.production_database_unchanged)}",
                f"clone_database_changed={_bool_text(self.clone_database_changed)}",
                f"clone_counts_unchanged={_bool_text(self.clone_counts_unchanged)}",
            ]
        )


async def run_controlled_start_smoke_from_settings(
    settings: Settings,
    *,
    admin_id: int,
    expected_bot_username: str,
    clone_database_path: Path,
    timeout_seconds: float = 120,
) -> ControlledStartSmokeResult:
    if settings.vps_apply_enabled or settings.operator_device_create_enabled:
        raise ControlledSmokeError("Both VPS write gates must be disabled")

    config = ControlledStartSmokeConfig(
        admin_id=admin_id,
        configured_admin_ids=frozenset(settings.admin_ids),
        expected_bot_username=expected_bot_username,
        production_database_path=Path(settings.database_path),
        clone_database_path=Path(clone_database_path),
        timeout_seconds=timeout_seconds,
    )
    return await run_controlled_start_smoke(
        config,
        bot_factory=lambda: create_bot(
            telegram_bot_token=settings.telegram_bot_token,
            telegram_proxy_url=settings.telegram_proxy_url,
        ),
        workflow_factory=lambda database_path: create_workflow_from_settings(
            settings,
            database_path=database_path,
        ),
    )


async def run_controlled_start_smoke(
    config: ControlledStartSmokeConfig,
    *,
    bot_factory: Callable[[], Any],
    workflow_factory: Callable[[Path], Any],
    start_handler: Callable[..., Awaitable[None]] = handle_start,
) -> ControlledStartSmokeResult:
    production_path, clone_path, expected_username = _validate_config(config)
    production_digest_before = _safe_database_digest(production_path)
    clone_digest_before = _safe_database_digest(clone_path)
    clone_counts_before = _safe_database_counts(clone_path)

    try:
        bot = bot_factory()
    except Exception:
        raise ControlledSmokeError("Telegram bot client creation failed") from None
    failure: ControlledSmokeError | None = None
    bot_identity = ""
    pending_update_count = -1

    try:
        async with asyncio.timeout(config.timeout_seconds):
            me = await bot.get_me()
            actual_username = str(getattr(me, "username", "") or "").strip()
            if actual_username.casefold() != expected_username.casefold():
                raise ControlledSmokeError("Telegram bot identity mismatch")
            bot_identity = f"@{actual_username}"

            webhook = await bot.get_webhook_info()
            if str(getattr(webhook, "url", "") or "").strip():
                raise ControlledSmokeError("Telegram webhook is configured")
            pending_update_count = int(
                getattr(webhook, "pending_update_count", 0) or 0
            )
            if pending_update_count != 0:
                raise ControlledSmokeError("Telegram pending update count is nonzero")

            workflow = workflow_factory(clone_path)
            update = await _wait_for_first_message(
                bot,
                timeout_seconds=config.timeout_seconds,
            )
            message, update_id = _validate_selected_admin_start(update, config.admin_id)
            await start_handler(message, workflow=workflow)
            pre_ack_webhook = await bot.get_webhook_info()
            pre_ack_pending_update_count = int(
                getattr(pre_ack_webhook, "pending_update_count", 0) or 0
            )
            if (
                str(getattr(pre_ack_webhook, "url", "") or "").strip()
                or pre_ack_pending_update_count != 1
            ):
                raise ControlledSmokeError(
                    "Telegram webhook or backlog changed before acknowledgement"
                )
            await bot.get_updates(
                offset=update_id + 1,
                limit=1,
                timeout=0,
                allowed_updates=["message"],
            )
            final_webhook = await bot.get_webhook_info()
            pending_update_count = int(
                getattr(final_webhook, "pending_update_count", 0) or 0
            )
            if (
                str(getattr(final_webhook, "url", "") or "").strip()
                or pending_update_count != 0
            ):
                raise ControlledSmokeError(
                    "Telegram webhook or backlog changed during controlled smoke"
                )
    except ControlledSmokeError as exc:
        failure = exc
    except TimeoutError:
        failure = ControlledSmokeError(
            "Timed out waiting for the selected administrator /start"
        )
    except (OSError, TelegramAPIError):
        failure = ControlledSmokeError("Telegram controlled smoke network failure")
    except Exception:
        failure = ControlledSmokeError("Telegram controlled smoke failed safely")
    finally:
        close = getattr(getattr(bot, "session", None), "close", None)
        if close is not None:
            try:
                await close()
            except Exception:
                if failure is None:
                    failure = ControlledSmokeError("Telegram session close failed")

    production_unchanged = (
        production_digest_before == _safe_database_digest(production_path)
    )
    if not production_unchanged:
        raise ControlledSmokeError("Production database changed during controlled smoke")
    if failure is not None:
        raise failure

    clone_digest_after = _safe_database_digest(clone_path)
    clone_counts_after = _safe_database_counts(clone_path)
    return ControlledStartSmokeResult(
        bot_identity=bot_identity,
        pending_update_count=pending_update_count,
        production_database_unchanged=production_unchanged,
        clone_database_changed=clone_digest_before != clone_digest_after,
        clone_counts_unchanged=clone_counts_before == clone_counts_after,
    )


async def _wait_for_first_message(bot: Any, *, timeout_seconds: float) -> Any:
    request_timeout = min(20, max(1, math.ceil(timeout_seconds)))
    while True:
        updates = await bot.get_updates(
            limit=1,
            timeout=request_timeout,
            allowed_updates=["message"],
        )
        if updates:
            return updates[0]


def _validate_selected_admin_start(update: Any, admin_id: int) -> tuple[Any, int]:
    message = getattr(update, "message", None)
    sender = getattr(message, "from_user", None)
    text = str(getattr(message, "text", "") or "").strip()
    update_id = getattr(update, "update_id", None)
    if (
        message is None
        or sender is None
        or int(getattr(sender, "id", 0) or 0) != admin_id
        or text != "/start"
        or not isinstance(update_id, int)
        or update_id < 0
    ):
        raise ControlledSmokeError(
            "Unexpected first update; no Telegram update was acknowledged"
        )
    return message, update_id


def _validate_config(
    config: ControlledStartSmokeConfig,
) -> tuple[Path, Path, str]:
    if config.admin_id not in config.configured_admin_ids:
        raise ControlledSmokeError("Selected administrator is not configured")
    if not 0 < config.timeout_seconds <= 120:
        raise ControlledSmokeError("Controlled smoke timeout must be in (0, 120]")

    expected_username = config.expected_bot_username.strip().removeprefix("@").strip()
    if not expected_username:
        raise ControlledSmokeError("Expected Telegram bot username is required")

    clone_input_path = config.clone_database_path
    if clone_input_path.is_symlink() or clone_input_path.parent.is_symlink():
        raise ControlledSmokeError("SQLite clone path must not use symlinks")

    try:
        production_path = config.production_database_path.resolve(strict=True)
        clone_path = clone_input_path.resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:
        raise ControlledSmokeError("Production database and clone must exist") from exc

    if os.path.samefile(production_path, clone_path):
        raise ControlledSmokeError("Controlled smoke refuses the production database")

    _validate_private_clone(clone_path)
    try:
        _validate_database(production_path)
        _validate_database(clone_path)
    except ControlledSmokeError:
        raise
    except (OSError, sqlite3.Error):
        raise ControlledSmokeError("SQLite validation failed") from None
    return production_path, clone_path, expected_username


def _validate_private_clone(path: Path) -> None:
    if os.name != "posix":
        return
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise ControlledSmokeError("SQLite clone must have mode 0600")
    if stat.S_IMODE(path.parent.stat().st_mode) != 0o700:
        raise ControlledSmokeError("SQLite clone directory must have mode 0700")
    current_uid = os.geteuid()
    if path.stat().st_uid != current_uid or path.parent.stat().st_uid != current_uid:
        raise ControlledSmokeError("SQLite clone and directory must be process-owned")


def _validate_database(path: Path) -> None:
    connection = _connect_read_only(path)
    try:
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        if integrity != "ok":
            raise ControlledSmokeError("SQLite integrity check failed")
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        if not REQUIRED_SMOKE_TABLES.issubset(tables):
            raise ControlledSmokeError("SQLite clone is missing required tables")
    finally:
        connection.close()


def _database_digest(path: Path) -> str:
    digest = hashlib.sha256()
    connection = _connect_read_only(path)
    try:
        for statement in connection.iterdump():
            digest.update(statement.encode("utf-8"))
            digest.update(b"\n")
    finally:
        connection.close()
    return digest.hexdigest()


def _database_counts(path: Path) -> tuple[int, int, int, int]:
    connection = _connect_read_only(path)
    try:
        return tuple(
            int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            for table in ("users", "orders", "devices", "admin_actions")
        )
    finally:
        connection.close()


def _safe_database_digest(path: Path) -> str:
    try:
        return _database_digest(path)
    except (OSError, sqlite3.Error):
        raise ControlledSmokeError("SQLite digest check failed") from None


def _safe_database_counts(path: Path) -> tuple[int, int, int, int]:
    try:
        return _database_counts(path)
    except (OSError, sqlite3.Error):
        raise ControlledSmokeError("SQLite aggregate check failed") from None


def _connect_read_only(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)


def _bool_text(value: bool) -> str:
    return "true" if value else "false"
