import asyncio
import shutil
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.bot.controlled_smoke import ControlledSmokeError
from app.bot.controlled_smoke import ControlledStartSmokeConfig
from app.bot.controlled_smoke import run_controlled_start_smoke
from app.bot.controlled_smoke import run_controlled_start_smoke_from_settings
from app.cli import build_parser
from app.config import Settings
from app.db.schema import initialize_schema


ADMIN_ID = 9001


class FakeSession:
    def __init__(self) -> None:
        self.closed = False

    async def close(self) -> None:
        self.closed = True


class FakeBot:
    def __init__(
        self,
        *,
        username: str = "amn_test_bot",
        webhook_url: str = "",
        pending_update_count: int = 0,
        pre_ack_webhook_url: str | None = None,
        pre_ack_pending_update_count: int | None = None,
        final_webhook_url: str | None = None,
        final_pending_update_count: int | None = None,
        updates: list[object] | None = None,
        wait_forever: bool = False,
    ) -> None:
        self.username = username
        self.webhook_url = webhook_url
        self.pending_update_count = pending_update_count
        self.pre_ack_webhook_url = pre_ack_webhook_url
        self.pre_ack_pending_update_count = pre_ack_pending_update_count
        self.final_webhook_url = final_webhook_url
        self.final_pending_update_count = final_pending_update_count
        self.updates = list(updates or [])
        self.wait_forever = wait_forever
        self.session = FakeSession()
        self.get_updates_calls: list[dict[str, object]] = []
        self.webhook_info_calls = 0

    async def get_me(self) -> object:
        return SimpleNamespace(username=self.username, id=123)

    async def get_webhook_info(self) -> object:
        self.webhook_info_calls += 1
        if self.webhook_info_calls == 2:
            return SimpleNamespace(
                url=self.pre_ack_webhook_url
                if self.pre_ack_webhook_url is not None
                else self.webhook_url,
                pending_update_count=self.pre_ack_pending_update_count
                if self.pre_ack_pending_update_count is not None
                else 1,
            )
        if self.webhook_info_calls > 2:
            return SimpleNamespace(
                url=self.final_webhook_url
                if self.final_webhook_url is not None
                else self.webhook_url,
                pending_update_count=self.final_pending_update_count
                if self.final_pending_update_count is not None
                else self.pending_update_count,
            )
        return SimpleNamespace(
            url=self.webhook_url,
            pending_update_count=self.pending_update_count,
        )

    async def get_updates(self, **kwargs: object) -> list[object]:
        self.get_updates_calls.append(dict(kwargs))
        if "offset" in kwargs:
            return []
        if self.updates:
            return [self.updates.pop(0)]
        if self.wait_forever:
            await asyncio.sleep(60)
        return []


def test_cli_accepts_controlled_start_smoke_command() -> None:
    parser = build_parser()

    args = parser.parse_args(
        [
            "bot",
            "controlled-start-smoke",
            "--admin-id",
            str(ADMIN_ID),
            "--expected-bot-username",
            "@amn_test_bot",
            "--database-clone",
            "runtime-smoke/test.sqlite3",
            "--timeout-seconds",
            "90",
        ]
    )

    assert args.command == "bot"
    assert args.bot_command == "controlled-start-smoke"
    assert args.admin_id == ADMIN_ID
    assert args.expected_bot_username == "@amn_test_bot"
    assert args.database_clone == "runtime-smoke/test.sqlite3"
    assert args.timeout_seconds == 90


def test_controlled_smoke_accepts_one_exact_admin_start_on_clone(tmp_path: Path) -> None:
    production_path, clone_path = _database_pair(tmp_path)
    update = _update(update_id=77, sender_id=ADMIN_ID, text="/start")
    bot = FakeBot(updates=[update])
    handled: list[object] = []

    async def start_handler(message: object, *, workflow: object) -> None:
        handled.append(message)
        with sqlite3.connect(workflow) as connection:
            connection.execute(
                "UPDATE users SET username = ?, updated_at = ? WHERE telegram_id = ?",
                ("smoke-admin", "2099-01-01 00:00:00", ADMIN_ID),
            )

    result = asyncio.run(
        run_controlled_start_smoke(
            _config(production_path, clone_path),
            bot_factory=lambda: bot,
            workflow_factory=lambda path: path,
            start_handler=start_handler,
        )
    )

    assert handled == [update.message]
    assert bot.get_updates_calls == [
        {"limit": 1, "timeout": 20, "allowed_updates": ["message"]},
        {
            "offset": 78,
            "limit": 1,
            "timeout": 0,
            "allowed_updates": ["message"],
        },
    ]
    assert bot.session.closed is True
    assert result.bot_identity == "@amn_test_bot"
    assert result.pending_update_count == 0
    assert result.production_database_unchanged is True
    assert result.clone_database_changed is True
    assert result.clone_counts_unchanged is True
    assert "callback_routes_registered=false" in result.render()
    assert str(ADMIN_ID) not in result.render()
    assert "/start" not in result.render()


def test_controlled_smoke_rejects_unconfigured_admin_before_bot_creation(
    tmp_path: Path,
) -> None:
    production_path, clone_path = _database_pair(tmp_path)
    config = ControlledStartSmokeConfig(
        admin_id=42,
        configured_admin_ids=frozenset({ADMIN_ID}),
        expected_bot_username="amn_test_bot",
        production_database_path=production_path,
        clone_database_path=clone_path,
    )

    with pytest.raises(ControlledSmokeError, match="not configured"):
        asyncio.run(
            run_controlled_start_smoke(
                config,
                bot_factory=lambda: pytest.fail("bot must not be created"),
                workflow_factory=lambda _: object(),
            )
        )


def test_controlled_smoke_refuses_production_database_path(tmp_path: Path) -> None:
    production_path = _create_database(tmp_path / "production.sqlite3")
    config = _config(production_path, production_path)

    with pytest.raises(ControlledSmokeError, match="refuses the production"):
        asyncio.run(
            run_controlled_start_smoke(
                config,
                bot_factory=lambda: pytest.fail("bot must not be created"),
                workflow_factory=lambda _: object(),
            )
        )


@pytest.mark.parametrize(
    ("webhook_url", "pending_count", "message"),
    [
        ("https://example.invalid/hook", 0, "webhook is configured"),
        ("", 3, "pending update count is nonzero"),
    ],
)
def test_controlled_smoke_rejects_webhook_or_backlog_before_waiting(
    tmp_path: Path,
    webhook_url: str,
    pending_count: int,
    message: str,
) -> None:
    production_path, clone_path = _database_pair(tmp_path)
    bot = FakeBot(webhook_url=webhook_url, pending_update_count=pending_count)

    with pytest.raises(ControlledSmokeError, match=message):
        asyncio.run(
            run_controlled_start_smoke(
                _config(production_path, clone_path),
                bot_factory=lambda: bot,
                workflow_factory=lambda _: object(),
            )
        )

    assert bot.get_updates_calls == []
    assert bot.session.closed is True


@pytest.mark.parametrize(
    ("sender_id", "text"),
    [
        (42, "/start"),
        (ADMIN_ID, "/admin_grant"),
        (ADMIN_ID, "/start payload"),
    ],
)
def test_controlled_smoke_preserves_unexpected_first_update(
    tmp_path: Path,
    sender_id: int,
    text: str,
) -> None:
    production_path, clone_path = _database_pair(tmp_path)
    bot = FakeBot(updates=[_update(update_id=88, sender_id=sender_id, text=text)])

    with pytest.raises(ControlledSmokeError, match="no Telegram update was acknowledged"):
        asyncio.run(
            run_controlled_start_smoke(
                _config(production_path, clone_path),
                bot_factory=lambda: bot,
                workflow_factory=lambda _: object(),
            )
        )

    assert len(bot.get_updates_calls) == 1
    assert "offset" not in bot.get_updates_calls[0]
    assert bot.session.closed is True


def test_controlled_smoke_rejects_bot_identity_mismatch(tmp_path: Path) -> None:
    production_path, clone_path = _database_pair(tmp_path)
    bot = FakeBot(username="different_bot")

    with pytest.raises(ControlledSmokeError, match="identity mismatch"):
        asyncio.run(
            run_controlled_start_smoke(
                _config(production_path, clone_path),
                bot_factory=lambda: bot,
                workflow_factory=lambda _: object(),
            )
        )

    assert bot.get_updates_calls == []
    assert bot.session.closed is True


def test_controlled_smoke_stops_when_backlog_appears_after_ack(
    tmp_path: Path,
) -> None:
    production_path, clone_path = _database_pair(tmp_path)
    bot = FakeBot(
        updates=[_update(update_id=91, sender_id=ADMIN_ID, text="/start")],
        final_pending_update_count=1,
    )

    async def start_handler(message: object, *, workflow: object) -> None:
        assert message is not None
        assert workflow == clone_path

    with pytest.raises(ControlledSmokeError, match="backlog changed"):
        asyncio.run(
            run_controlled_start_smoke(
                _config(production_path, clone_path),
                bot_factory=lambda: bot,
                workflow_factory=lambda path: path,
                start_handler=start_handler,
            )
        )

    assert bot.get_updates_calls[-1]["offset"] == 92
    assert bot.webhook_info_calls == 3
    assert bot.session.closed is True


def test_controlled_smoke_preserves_backlog_that_appears_before_ack(
    tmp_path: Path,
) -> None:
    production_path, clone_path = _database_pair(tmp_path)
    bot = FakeBot(
        updates=[_update(update_id=93, sender_id=ADMIN_ID, text="/start")],
        pre_ack_pending_update_count=2,
    )

    async def start_handler(message: object, *, workflow: object) -> None:
        assert message is not None
        assert workflow == clone_path

    with pytest.raises(ControlledSmokeError, match="before acknowledgement"):
        asyncio.run(
            run_controlled_start_smoke(
                _config(production_path, clone_path),
                bot_factory=lambda: bot,
                workflow_factory=lambda path: path,
                start_handler=start_handler,
            )
        )

    assert len(bot.get_updates_calls) == 1
    assert "offset" not in bot.get_updates_calls[0]
    assert bot.webhook_info_calls == 2
    assert bot.session.closed is True


def test_controlled_smoke_sanitizes_bot_client_creation_failure(
    tmp_path: Path,
) -> None:
    production_path, clone_path = _database_pair(tmp_path)

    def fail_with_secret() -> object:
        raise RuntimeError("sensitive-diagnostic-detail")

    with pytest.raises(ControlledSmokeError) as exc_info:
        asyncio.run(
            run_controlled_start_smoke(
                _config(production_path, clone_path),
                bot_factory=fail_with_secret,
                workflow_factory=lambda _: object(),
            )
        )

    assert str(exc_info.value) == "Telegram bot client creation failed"
    assert "sensitive-diagnostic-detail" not in str(exc_info.value)


def test_controlled_smoke_has_internal_timeout_and_closes_session(
    tmp_path: Path,
) -> None:
    production_path, clone_path = _database_pair(tmp_path)
    bot = FakeBot(wait_forever=True)
    config = _config(production_path, clone_path, timeout_seconds=0.01)

    with pytest.raises(ControlledSmokeError, match="Timed out"):
        asyncio.run(
            run_controlled_start_smoke(
                config,
                bot_factory=lambda: bot,
                workflow_factory=lambda _: object(),
            )
        )

    assert bot.session.closed is True


def test_controlled_smoke_rejects_enabled_write_gate(tmp_path: Path) -> None:
    production_path, clone_path = _database_pair(tmp_path)
    settings = Settings(
        telegram_bot_token="123:abc",
        app_secret_key="app-secret-value-with-more-than-thirty-two-characters",
        admin_telegram_ids=str(ADMIN_ID),
        database_path=str(production_path),
        vps_apply_enabled=True,
    )

    with pytest.raises(ControlledSmokeError, match="write gates"):
        asyncio.run(
            run_controlled_start_smoke_from_settings(
                settings,
                admin_id=ADMIN_ID,
                expected_bot_username="amn_test_bot",
                clone_database_path=clone_path,
            )
        )


def _config(
    production_path: Path,
    clone_path: Path,
    *,
    timeout_seconds: float = 120,
) -> ControlledStartSmokeConfig:
    return ControlledStartSmokeConfig(
        admin_id=ADMIN_ID,
        configured_admin_ids=frozenset({ADMIN_ID}),
        expected_bot_username="@amn_test_bot",
        production_database_path=production_path,
        clone_database_path=clone_path,
        timeout_seconds=timeout_seconds,
    )


def _database_pair(tmp_path: Path) -> tuple[Path, Path]:
    production_path = _create_database(tmp_path / "production.sqlite3")
    clone_dir = tmp_path / "private-smoke"
    clone_dir.mkdir(mode=0o700)
    clone_path = clone_dir / "clone.sqlite3"
    shutil.copy2(production_path, clone_path)
    clone_path.chmod(0o600)
    return production_path, clone_path


def _create_database(path: Path) -> Path:
    connection = sqlite3.connect(path)
    try:
        initialize_schema(connection)
        connection.execute(
            """
            INSERT INTO users (telegram_id, username, first_name, last_name)
            VALUES (?, ?, ?, ?)
            """,
            (ADMIN_ID, "admin", "Admin", "User"),
        )
        connection.commit()
    finally:
        connection.close()
    path.chmod(0o600)
    return path


def _update(*, update_id: int, sender_id: int, text: str) -> object:
    message = SimpleNamespace(
        from_user=SimpleNamespace(
            id=sender_id,
            username="admin",
            first_name="Admin",
            last_name="User",
        ),
        text=text,
    )
    return SimpleNamespace(update_id=update_id, message=message)
