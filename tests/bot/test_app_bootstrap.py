import asyncio

import pytest

from app.bot.persistent_runtime import (
    PERSISTENT_ALLOWED_UPDATES,
    PersistentBotAdmissionError,
    PersistentBotAdmissionResult,
)
from app.config import Settings
from app.bot.main import create_dispatcher
from app.main import create_bot, create_workflow, run_persistent_bot
from app.services.access import AccessService
from app.systemd_notify import SystemdNotifyError
from tests.server_config.test_loader import VALID_YAML


def test_create_workflow_wires_access_service_for_admin_approval(tmp_path):
    workflow = create_workflow(
        database_path=tmp_path / "app.sqlite3",
        app_secret_key="app-bootstrap-secret-value-with-more-than-32-chars",
        admin_telegram_ids={9001},
        default_vpn_network_cidr="10.8.0.0/24",
        max_devices_per_user=5,
        default_plan_days=7,
    )

    assert workflow.is_admin(9001) is True
    assert isinstance(workflow._access_service, AccessService)
    assert workflow._default_server_id is not None
    assert [plan["id"] for plan in workflow._repo.list_active_plans()] == [
        "days_3",
        "days_7",
        "days_10",
        "days_14",
        "days_30",
        "days_60",
        "days_90",
        "days_180",
    ]


def test_dispatcher_registers_admin_issue_and_safe_resend_commands():
    dispatcher = create_dispatcher(workflow=object())
    router = dispatcher.sub_routers[0]

    message_handler_names = {
        handler.callback.__name__ for handler in router.message.handlers
    }

    assert "admin_issue_config" in message_handler_names
    assert "admin_resend_issued_config" in message_handler_names


def test_create_workflow_wires_device_name_sequence_settings(tmp_path):
    workflow = create_workflow(
        database_path=tmp_path / "app.sqlite3",
        app_secret_key="app-bootstrap-secret-value-with-more-than-32-chars",
        admin_telegram_ids={9001},
        default_vpn_network_cidr="10.8.0.0/24",
        max_devices_per_user=5,
        default_plan_days=7,
        bot_device_name_prefix="Custom-AMNZ",
        bot_device_name_sequence_seed=12,
    )

    assert workflow._device_name_prefix == "Custom-AMNZ"
    assert workflow._device_name_sequence_seed == 12


def test_create_workflow_can_enable_vps_peer_apply_from_server_config(tmp_path):
    server_config_path = tmp_path / "servers.yml"
    server_config_path.write_text(
        VALID_YAML.replace("allowed_ips: 0.0.0.0/0", "allowed_ips: 0.0.0.0/0\n      server_public_key: real-server-public-key"),
        encoding="utf-8",
    )

    workflow = create_workflow(
        database_path=tmp_path / "app.sqlite3",
        app_secret_key="app-bootstrap-secret-value-with-more-than-32-chars",
        admin_telegram_ids={9001},
        default_vpn_network_cidr="10.8.0.0/24",
        max_devices_per_user=5,
        default_plan_days=7,
        vps_apply_enabled=True,
        server_config_path=server_config_path,
        server_name="debian-vps-1",
    )

    server = workflow._repo.get_server(workflow._default_server_id)
    assert workflow._access_service._peer_applier is not None
    assert server["name"] == "debian-vps-1"
    assert server["host"] == "203.0.113.10"
    assert server["endpoint_host"] == "203.0.113.10"
    assert server["vpn_port"] == 30001
    assert server["vpn_network_cidr"] == "10.8.0.0/24"
    assert server["server_address"] == "10.8.0.1"
    assert server["server_public_key"] == "real-server-public-key"


def test_create_workflow_syncs_server_address_prefix_network_from_server_config(tmp_path):
    server_config_path = tmp_path / "servers.yml"
    server_config_path.write_text(
        VALID_YAML.replace(
            "server_address: 10.8.0.1/24",
            "server_address: 10.8.1.1/24",
        ).replace(
            "allowed_ips: 0.0.0.0/0",
            "allowed_ips: 0.0.0.0/0\n      server_public_key: real-server-public-key",
        ),
        encoding="utf-8",
    )

    workflow = create_workflow(
        database_path=tmp_path / "app.sqlite3",
        app_secret_key="app-bootstrap-secret-value-with-more-than-32-chars",
        admin_telegram_ids={9001},
        default_vpn_network_cidr="10.8.0.0/24",
        max_devices_per_user=5,
        default_plan_days=7,
        vps_apply_enabled=True,
        server_config_path=server_config_path,
        server_name="debian-vps-1",
    )

    server = workflow._repo.get_server(workflow._default_server_id)
    assert server["vpn_network_cidr"] == "10.8.1.0/24"
    assert server["server_address"] == "10.8.1.1"


def test_create_workflow_passes_vps_ssh_password_to_peer_applier(tmp_path):
    server_config_path = tmp_path / "servers.yml"
    server_config_path.write_text(
        VALID_YAML.replace(
            "allowed_ips: 0.0.0.0/0",
            "allowed_ips: 0.0.0.0/0\n      server_public_key: real-server-public-key",
        ).replace("type: key", "type: password"),
        encoding="utf-8",
    )

    workflow = create_workflow(
        database_path=tmp_path / "app.sqlite3",
        app_secret_key="app-bootstrap-secret-value-with-more-than-32-chars",
        admin_telegram_ids={9001},
        default_vpn_network_cidr="10.8.0.0/24",
        max_devices_per_user=5,
        default_plan_days=7,
        vps_apply_enabled=True,
        server_config_path=server_config_path,
        server_name="debian-vps-1",
        vps_ssh_password="ssh-secret",
    )

    peer_applier = workflow._access_service._peer_applier
    assert peer_applier is not None
    assert peer_applier._ssh_client._password == "ssh-secret"


def test_create_bot_uses_proxy_session_when_proxy_url_is_configured(monkeypatch):
    created_sessions = []
    created_bots = []

    class FakeSession:
        def __init__(self, *, proxy):
            self.proxy = proxy
            created_sessions.append(self)

    class FakeBot:
        def __init__(self, *, token, session=None):
            self.token = token
            self.session = session
            created_bots.append(self)

    monkeypatch.setattr("app.main.AiohttpSession", FakeSession)
    monkeypatch.setattr("app.main.Bot", FakeBot)

    bot = create_bot(
        telegram_bot_token="123:abc",
        telegram_proxy_url="socks5://127.0.0.1:1080",
    )

    assert bot is created_bots[0]
    assert bot.token == "123:abc"
    assert bot.session is created_sessions[0]
    assert bot.session.proxy == "socks5://127.0.0.1:1080"


class _FakeSession:
    def __init__(self, events):
        self._events = events

    async def close(self):
        self._events.append("session_close")


class _FakePersistentBot:
    def __init__(self, events):
        self.session = _FakeSession(events)


class _FakeDispatcher:
    def __init__(self, events):
        self.events = events
        self.started = asyncio.Event()
        self.stop = asyncio.Event()

    async def start_polling(self, bot, **kwargs):
        self.events.append(("poll", kwargs))
        self.started.set()
        try:
            await self.stop.wait()
        except asyncio.CancelledError:
            self.events.append("poll_cancelled")
            raise


class _RecordingLock:
    def __init__(self, events, *, enter_error=None):
        self.events = events
        self.enter_error = enter_error

    def __enter__(self):
        self.events.append("lock_enter")
        if self.enter_error is not None:
            raise self.enter_error
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.events.append("lock_exit")


class _FakeNotifier:
    def __init__(self, events, *, watchdog_error=None):
        self.events = events
        self.watchdog_error = watchdog_error

    def ready(self, status):
        self.events.append(("ready", status))

    def stopping(self, status):
        self.events.append(("stopping", status))

    def watchdog_interval_seconds(self):
        return 1.0 if self.watchdog_error is not None else None

    async def run_watchdog(self):
        self.events.append("watchdog_start")
        if self.watchdog_error is not None:
            raise self.watchdog_error


def _persistent_settings(tmp_path):
    return Settings(
        _env_file=None,
        telegram_bot_token="123:secret-token-marker",
        telegram_proxy_url="socks5://user:proxy-secret@127.0.0.1:1080",
        telegram_expected_bot_username="@expected_bot",
        telegram_admission_timeout_seconds=30,
        telegram_polling_timeout_seconds=20,
        telegram_runtime_lock_path=str(tmp_path / "polling.lock"),
        app_secret_key="app-bootstrap-secret-value-with-more-than-32-chars",
        admin_telegram_ids="9001",
    )


def _passing_admission(events):
    async def check(bot, config):
        events.append("admission")
        assert config.expected_bot_username == "@expected_bot"
        return PersistentBotAdmissionResult(
            bot_identity="@expected_bot",
            pending_update_count=0,
            allowed_updates=PERSISTENT_ALLOWED_UPDATES,
        )

    return check


def _passing_recheck(events):
    async def check(bot, config):
        events.append("recheck")

    return check


def test_persistent_bootstrap_orders_admission_before_workflow_and_explicit_polling(
    tmp_path,
):
    async def scenario():
        events = []
        dispatcher = _FakeDispatcher(events)
        notifier = _FakeNotifier(events)
        task = asyncio.create_task(
            run_persistent_bot(
                _persistent_settings(tmp_path),
                bot_factory=lambda **kwargs: events.append("bot")
                or _FakePersistentBot(events),
                workflow_factory=lambda settings: events.append("workflow")
                or object(),
                dispatcher_factory=lambda **kwargs: events.append("dispatcher")
                or dispatcher,
                admission_checker=_passing_admission(events),
                state_checker=_passing_recheck(events),
                lock_factory=lambda path: _RecordingLock(events),
                notifier=notifier,
                receipt_writer=lambda value: events.append(("receipt", value)),
            )
        )
        await dispatcher.started.wait()
        await asyncio.sleep(0)
        dispatcher.stop.set()
        await task
        return events

    events = asyncio.run(scenario())

    assert events.index("lock_enter") < events.index("bot")
    assert events.index("admission") < events.index("workflow")
    assert events.index("workflow") < events.index("recheck")
    poll = next(item for item in events if isinstance(item, tuple) and item[0] == "poll")
    assert poll[1]["allowed_updates"] == ["message", "callback_query"]
    assert poll[1]["polling_timeout"] == 20
    assert poll[1]["close_bot_session"] is False
    assert poll[1]["handle_as_tasks"] is True
    assert poll[1]["tasks_concurrency_limit"] == 8
    assert events.index("recheck") < events.index(poll)
    assert events.index(poll) < events.index(("ready", "Telegram polling admitted"))
    receipt = next(item[1] for item in events if isinstance(item, tuple) and item[0] == "receipt")
    assert receipt.startswith("telegram_persistent_admission=pass")
    assert "secret-token-marker" not in receipt
    assert "proxy-secret" not in receipt
    assert "9001" not in receipt
    assert events[-3:] == [
        ("stopping", "Telegram polling stopped"),
        "session_close",
        "lock_exit",
    ]


def test_persistent_bootstrap_admission_failure_precedes_workflow_and_closes_session(
    tmp_path,
):
    async def failing_admission(bot, config):
        events.append("admission")
        raise PersistentBotAdmissionError("Telegram bot identity mismatch")

    events = []

    with pytest.raises(PersistentBotAdmissionError, match="identity mismatch"):
        asyncio.run(
            run_persistent_bot(
                _persistent_settings(tmp_path),
                bot_factory=lambda **kwargs: events.append("bot")
                or _FakePersistentBot(events),
                workflow_factory=lambda settings: events.append("workflow")
                or object(),
                dispatcher_factory=lambda **kwargs: events.append("dispatcher")
                or _FakeDispatcher(events),
                admission_checker=failing_admission,
                state_checker=_passing_recheck(events),
                lock_factory=lambda path: _RecordingLock(events),
                notifier=_FakeNotifier(events),
                receipt_writer=lambda value: events.append(("receipt", value)),
            )
        )

    assert "workflow" not in events
    assert "dispatcher" not in events
    assert not any(isinstance(item, tuple) and item[0] == "ready" for item in events)
    assert events[-2:] == ["session_close", "lock_exit"]


def test_persistent_bootstrap_recheck_failure_prevents_polling_and_readiness(tmp_path):
    events = []

    async def failing_recheck(bot, config):
        events.append("recheck")
        raise PersistentBotAdmissionError("Telegram pending update count is nonzero")

    with pytest.raises(PersistentBotAdmissionError, match="pending update count"):
        asyncio.run(
            run_persistent_bot(
                _persistent_settings(tmp_path),
                bot_factory=lambda **kwargs: _FakePersistentBot(events),
                workflow_factory=lambda settings: events.append("workflow")
                or object(),
                dispatcher_factory=lambda **kwargs: events.append("dispatcher")
                or _FakeDispatcher(events),
                admission_checker=_passing_admission(events),
                state_checker=failing_recheck,
                lock_factory=lambda path: _RecordingLock(events),
                notifier=_FakeNotifier(events),
                receipt_writer=lambda value: events.append(("receipt", value)),
            )
        )

    assert not any(isinstance(item, tuple) and item[0] == "poll" for item in events)
    assert not any(isinstance(item, tuple) and item[0] == "ready" for item in events)
    assert events[-2:] == ["session_close", "lock_exit"]


def test_persistent_bootstrap_applies_one_timeout_to_all_pre_poll_startup(tmp_path):
    async def scenario():
        events = []
        settings = _persistent_settings(tmp_path).model_copy(
            update={"telegram_admission_timeout_seconds": 1}
        )

        async def stalled_recheck(bot, config):
            events.append("recheck")
            await asyncio.Event().wait()

        with pytest.raises(
            PersistentBotAdmissionError,
            match="Telegram persistent startup timed out",
        ):
            await asyncio.wait_for(
                run_persistent_bot(
                    settings,
                    bot_factory=lambda **kwargs: _FakePersistentBot(events),
                    workflow_factory=lambda current_settings: events.append("workflow")
                    or object(),
                    dispatcher_factory=lambda **kwargs: events.append("dispatcher")
                    or _FakeDispatcher(events),
                    admission_checker=_passing_admission(events),
                    state_checker=stalled_recheck,
                    lock_factory=lambda path: _RecordingLock(events),
                    notifier=_FakeNotifier(events),
                    receipt_writer=lambda value: events.append(("receipt", value)),
                ),
                timeout=2.0,
            )
        return events

    events = asyncio.run(scenario())

    assert events[:5] == [
        "lock_enter",
        "admission",
        "workflow",
        "dispatcher",
        "recheck",
    ]
    assert not any(isinstance(item, tuple) and item[0] == "poll" for item in events)
    assert not any(isinstance(item, tuple) and item[0] == "ready" for item in events)
    assert events[-2:] == ["session_close", "lock_exit"]


def test_persistent_bootstrap_lock_failure_precedes_bot_and_network(tmp_path):
    events = []
    lock_error = PersistentBotAdmissionError(
        "Persistent Telegram bot instance is already running"
    )

    with pytest.raises(PersistentBotAdmissionError, match="already running"):
        asyncio.run(
            run_persistent_bot(
                _persistent_settings(tmp_path),
                bot_factory=lambda **kwargs: events.append("bot"),
                workflow_factory=lambda settings: events.append("workflow"),
                dispatcher_factory=lambda **kwargs: events.append("dispatcher"),
                admission_checker=_passing_admission(events),
                state_checker=_passing_recheck(events),
                lock_factory=lambda path: _RecordingLock(
                    events,
                    enter_error=lock_error,
                ),
                notifier=_FakeNotifier(events),
                receipt_writer=lambda value: events.append(("receipt", value)),
            )
        )

    assert events == ["lock_enter"]


def test_persistent_bootstrap_watchdog_failure_cancels_polling_and_cleans_up(tmp_path):
    async def scenario():
        events = []
        dispatcher = _FakeDispatcher(events)
        with pytest.raises(SystemdNotifyError, match="watchdog failed"):
            await run_persistent_bot(
                _persistent_settings(tmp_path),
                bot_factory=lambda **kwargs: _FakePersistentBot(events),
                workflow_factory=lambda settings: object(),
                dispatcher_factory=lambda **kwargs: dispatcher,
                admission_checker=_passing_admission(events),
                state_checker=_passing_recheck(events),
                lock_factory=lambda path: _RecordingLock(events),
                notifier=_FakeNotifier(
                    events,
                    watchdog_error=SystemdNotifyError("watchdog failed"),
                ),
                receipt_writer=lambda value: events.append(("receipt", value)),
            )
        return events

    events = asyncio.run(scenario())

    assert "watchdog_start" in events
    assert "poll_cancelled" in events
    assert events[-4:] == [
        ("stopping", "Telegram polling stopped"),
        "poll_cancelled",
        "session_close",
        "lock_exit",
    ]
