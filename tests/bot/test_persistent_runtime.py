import asyncio
from types import SimpleNamespace

import pytest
from aiogram.exceptions import TelegramConflictError

from app.bot.persistent_runtime import (
    PERSISTENT_ALLOWED_UPDATES,
    PersistentBotAdmissionConfig,
    PersistentBotAdmissionError,
    PersistentBotInstanceLock,
    admit_persistent_bot,
    recheck_persistent_bot_state,
)


class FakeBot:
    def __init__(
        self,
        *,
        username="expected_bot",
        webhook_url="",
        pending_update_count=0,
        updates=None,
        get_me_error=None,
        get_updates_error=None,
        wait_forever=False,
    ):
        self.username = username
        self.webhook_url = webhook_url
        self.pending_update_count = pending_update_count
        self.updates = [] if updates is None else list(updates)
        self.get_me_error = get_me_error
        self.get_updates_error = get_updates_error
        self.wait_forever = wait_forever
        self.get_updates_calls = []
        self.webhook_calls = 0
        self.delete_webhook_calls = 0

    async def get_me(self):
        if self.wait_forever:
            await asyncio.Event().wait()
        if self.get_me_error is not None:
            raise self.get_me_error
        return SimpleNamespace(username=self.username)

    async def get_webhook_info(self):
        self.webhook_calls += 1
        return SimpleNamespace(
            url=self.webhook_url,
            pending_update_count=self.pending_update_count,
        )

    async def get_updates(self, **kwargs):
        self.get_updates_calls.append(kwargs)
        if self.get_updates_error is not None:
            raise self.get_updates_error
        return list(self.updates)

    async def delete_webhook(self, **kwargs):
        self.delete_webhook_calls += 1


def _config(**overrides):
    values = {
        "expected_bot_username": "@Expected_Bot",
        "timeout_seconds": 30,
    }
    values.update(overrides)
    return PersistentBotAdmissionConfig(**values)


def test_admission_accepts_exact_identity_empty_webhook_and_zero_backlog():
    async def scenario():
        bot = FakeBot()
        result = await admit_persistent_bot(bot, _config())
        return bot, result

    bot, result = asyncio.run(scenario())

    assert result.bot_identity == "@expected_bot"
    assert result.pending_update_count == 0
    assert result.allowed_updates == PERSISTENT_ALLOWED_UPDATES
    assert bot.get_updates_calls == [
        {
            "limit": 1,
            "timeout": 0,
            "allowed_updates": ["message", "callback_query"],
        }
    ]
    assert bot.delete_webhook_calls == 0
    assert result.render() == (
        "telegram_persistent_admission=pass bot_identity=@expected_bot "
        "webhook_configured=false pending_update_count=0 "
        "allowed_updates=message,callback_query"
    )


@pytest.mark.parametrize(
    "expected_username",
    ["", "   ", "CHANGE_ME", "@change_me", "replace-with-bot-username"],
)
def test_admission_rejects_missing_or_placeholder_expected_identity_before_network(
    expected_username,
):
    bot = FakeBot()

    with pytest.raises(PersistentBotAdmissionError, match="expected username"):
        asyncio.run(
            admit_persistent_bot(
                bot,
                _config(expected_bot_username=expected_username),
            )
        )

    assert bot.webhook_calls == 0
    assert bot.get_updates_calls == []


def test_admission_rejects_identity_mismatch():
    with pytest.raises(PersistentBotAdmissionError, match="identity mismatch"):
        asyncio.run(admit_persistent_bot(FakeBot(username="other_bot"), _config()))


def test_admission_rejects_configured_webhook_without_mutating_it():
    bot = FakeBot(webhook_url="https://example.invalid/hook")

    with pytest.raises(PersistentBotAdmissionError, match="webhook is configured"):
        asyncio.run(admit_persistent_bot(bot, _config()))

    assert bot.delete_webhook_calls == 0
    assert bot.get_updates_calls == []


@pytest.mark.parametrize("pending", [1, -1, "not-an-integer"])
def test_admission_rejects_nonzero_or_invalid_backlog(pending):
    with pytest.raises(PersistentBotAdmissionError, match="pending update count"):
        asyncio.run(
            admit_persistent_bot(
                FakeBot(pending_update_count=pending),
                _config(),
            )
        )


def test_admission_rejects_update_racing_into_ownership_probe_without_acknowledging():
    bot = FakeBot(updates=[SimpleNamespace(update_id=7)])

    with pytest.raises(PersistentBotAdmissionError, match="ownership probe returned"):
        asyncio.run(admit_persistent_bot(bot, _config()))

    assert "offset" not in bot.get_updates_calls[0]


def test_admission_maps_remote_poll_conflict_without_raw_error_text():
    conflict = TelegramConflictError(
        method=None,
        message="raw-conflict-secret-marker",
    )

    with pytest.raises(
        PersistentBotAdmissionError,
        match="long-poll ownership conflict",
    ) as error:
        asyncio.run(
            admit_persistent_bot(
                FakeBot(get_updates_error=conflict),
                _config(),
            )
        )

    assert "raw-conflict-secret-marker" not in str(error.value)


def test_admission_maps_network_failure_without_raw_error_text():
    with pytest.raises(
        PersistentBotAdmissionError,
        match="admission network failure",
    ) as error:
        asyncio.run(
            admit_persistent_bot(
                FakeBot(get_me_error=OSError("raw-network-secret-marker")),
                _config(),
            )
        )

    assert "raw-network-secret-marker" not in str(error.value)


def test_admission_timeout_is_bounded_and_sanitized():
    with pytest.raises(PersistentBotAdmissionError, match="admission timed out"):
        asyncio.run(
            admit_persistent_bot(
                FakeBot(wait_forever=True),
                _config(timeout_seconds=0.01),
            )
        )


def test_recheck_repeats_identity_webhook_and_backlog_without_poll_probe():
    async def scenario():
        bot = FakeBot()
        await recheck_persistent_bot_state(bot, _config())
        return bot

    bot = asyncio.run(scenario())

    assert bot.webhook_calls == 1
    assert bot.get_updates_calls == []


def test_recheck_fails_when_backlog_changes():
    with pytest.raises(PersistentBotAdmissionError, match="pending update count"):
        asyncio.run(
            recheck_persistent_bot_state(
                FakeBot(pending_update_count=1),
                _config(),
            )
        )


def test_instance_lock_rejects_duplicate_and_can_be_reacquired(tmp_path):
    path = tmp_path / "polling.lock"

    with PersistentBotInstanceLock(path):
        with pytest.raises(PersistentBotAdmissionError, match="already running"):
            with PersistentBotInstanceLock(path):
                pass

    with PersistentBotInstanceLock(path):
        pass


def test_instance_lock_fails_safely_when_parent_is_missing(tmp_path):
    path = tmp_path / "missing" / "polling.lock"

    with pytest.raises(PersistentBotAdmissionError, match="lock unavailable") as error:
        with PersistentBotInstanceLock(path):
            pass

    assert str(path) not in str(error.value)
