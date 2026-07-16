import asyncio
import errno
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

from aiogram.exceptions import (
    TelegramAPIError,
    TelegramConflictError,
)


PERSISTENT_ALLOWED_UPDATES = ("message", "callback_query")
PERSISTENT_TASKS_CONCURRENCY_LIMIT = 8
_EXPECTED_USERNAME_PLACEHOLDERS = {
    "change_me",
    "replace-with-bot-username",
}


class PersistentBotAdmissionError(RuntimeError):
    pass


@dataclass(frozen=True)
class PersistentBotAdmissionConfig:
    expected_bot_username: str
    timeout_seconds: float = 30
    allowed_updates: tuple[str, ...] = PERSISTENT_ALLOWED_UPDATES


@dataclass(frozen=True)
class PersistentBotAdmissionResult:
    bot_identity: str
    pending_update_count: int
    allowed_updates: tuple[str, ...]

    def render(self) -> str:
        return " ".join(
            (
                "telegram_persistent_admission=pass",
                f"bot_identity={self.bot_identity}",
                "webhook_configured=false",
                f"pending_update_count={self.pending_update_count}",
                f"allowed_updates={','.join(self.allowed_updates)}",
            )
        )


class PersistentBotInstanceLock:
    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._handle: BinaryIO | None = None

    def __enter__(self) -> "PersistentBotInstanceLock":
        try:
            handle = self._path.open("a+b")
        except OSError:
            raise PersistentBotAdmissionError(
                "Persistent Telegram runtime lock unavailable"
            ) from None

        try:
            _lock_handle(handle)
        except BlockingIOError:
            handle.close()
            raise PersistentBotAdmissionError(
                "Persistent Telegram bot instance is already running"
            ) from None
        except OSError as exc:
            handle.close()
            if exc.errno in {errno.EACCES, errno.EAGAIN}:
                raise PersistentBotAdmissionError(
                    "Persistent Telegram bot instance is already running"
                ) from None
            raise PersistentBotAdmissionError(
                "Persistent Telegram runtime lock unavailable"
            ) from None

        self._handle = handle
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        handle = self._handle
        self._handle = None
        if handle is None:
            return
        try:
            _unlock_handle(handle)
        finally:
            handle.close()


async def admit_persistent_bot(
    bot: Any,
    config: PersistentBotAdmissionConfig,
) -> PersistentBotAdmissionResult:
    expected_username = _validate_config(config)
    try:
        async with asyncio.timeout(config.timeout_seconds):
            result = await _check_state(bot, config, expected_username)
            updates = await bot.get_updates(
                limit=1,
                timeout=0,
                allowed_updates=list(config.allowed_updates),
            )
            if updates:
                raise PersistentBotAdmissionError(
                    "Telegram poll ownership probe returned an update"
                )
            return result
    except PersistentBotAdmissionError:
        raise
    except TimeoutError:
        raise PersistentBotAdmissionError(
            "Telegram persistent admission timed out"
        ) from None
    except TelegramConflictError:
        raise PersistentBotAdmissionError(
            "Telegram long-poll ownership conflict"
        ) from None
    except (OSError, TelegramAPIError):
        raise PersistentBotAdmissionError(
            "Telegram persistent admission network failure"
        ) from None
    except Exception:
        raise PersistentBotAdmissionError(
            "Telegram persistent admission failed safely"
        ) from None


async def recheck_persistent_bot_state(
    bot: Any,
    config: PersistentBotAdmissionConfig,
) -> None:
    expected_username = _validate_config(config)
    try:
        async with asyncio.timeout(config.timeout_seconds):
            await _check_state(bot, config, expected_username)
    except PersistentBotAdmissionError:
        raise
    except TimeoutError:
        raise PersistentBotAdmissionError(
            "Telegram persistent admission timed out"
        ) from None
    except TelegramConflictError:
        raise PersistentBotAdmissionError(
            "Telegram long-poll ownership conflict"
        ) from None
    except (OSError, TelegramAPIError):
        raise PersistentBotAdmissionError(
            "Telegram persistent admission network failure"
        ) from None
    except Exception:
        raise PersistentBotAdmissionError(
            "Telegram persistent admission failed safely"
        ) from None


async def _check_state(
    bot: Any,
    config: PersistentBotAdmissionConfig,
    expected_username: str,
) -> PersistentBotAdmissionResult:
    me = await bot.get_me()
    actual_username = str(getattr(me, "username", "") or "").strip()
    if actual_username.casefold() != expected_username.casefold():
        raise PersistentBotAdmissionError("Telegram bot identity mismatch")

    webhook = await bot.get_webhook_info()
    if str(getattr(webhook, "url", "") or "").strip():
        raise PersistentBotAdmissionError("Telegram webhook is configured")

    pending_update_count = _pending_update_count(webhook)
    if pending_update_count != 0:
        raise PersistentBotAdmissionError(
            "Telegram pending update count is nonzero"
        )

    return PersistentBotAdmissionResult(
        bot_identity=f"@{actual_username}",
        pending_update_count=pending_update_count,
        allowed_updates=config.allowed_updates,
    )


def _validate_config(config: PersistentBotAdmissionConfig) -> str:
    expected_username = (
        config.expected_bot_username.strip().removeprefix("@").strip()
    )
    if (
        not expected_username
        or expected_username.casefold() in _EXPECTED_USERNAME_PLACEHOLDERS
    ):
        raise PersistentBotAdmissionError(
            "Telegram expected username is required"
        )
    if not 0 < config.timeout_seconds <= 120:
        raise PersistentBotAdmissionError(
            "Telegram admission timeout must be in (0, 120]"
        )
    if tuple(config.allowed_updates) != PERSISTENT_ALLOWED_UPDATES:
        raise PersistentBotAdmissionError(
            "Telegram persistent allowed updates are invalid"
        )
    return expected_username


def _pending_update_count(webhook: Any) -> int:
    raw_value = getattr(webhook, "pending_update_count", 0)
    if isinstance(raw_value, bool):
        raise PersistentBotAdmissionError(
            "Telegram pending update count is invalid"
        )
    try:
        value = int(raw_value)
    except (TypeError, ValueError):
        raise PersistentBotAdmissionError(
            "Telegram pending update count is invalid"
        ) from None
    if value < 0:
        raise PersistentBotAdmissionError(
            "Telegram pending update count is invalid"
        )
    return value


def _lock_handle(handle: BinaryIO) -> None:
    if os.name == "nt":
        import msvcrt

        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"\0")
            handle.flush()
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        return

    import fcntl

    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


def _unlock_handle(handle: BinaryIO) -> None:
    if os.name == "nt":
        import msvcrt

        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        return

    import fcntl

    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
