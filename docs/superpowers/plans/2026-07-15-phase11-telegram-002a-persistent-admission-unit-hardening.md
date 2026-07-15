# Phase 11 TELEGRAM-002A Persistent Admission and Unit Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a fail-closed persistent Telegram admission path and hardened systemd unit without activating the production bot or touching production AWG.

**Architecture:** `app.bot.persistent_runtime` owns pure admission state checks and the process-lifetime single-instance lock. `app.systemd_notify` owns dependency-free readiness/watchdog datagrams. `app.main.run_persistent_bot` composes those units so Telegram admission completes before workflow/DB initialization, repeats state validation before explicit polling, and closes every owned resource.

**Tech Stack:** Python 3.12, asyncio, aiogram 3, pydantic-settings 2, native `fcntl`/`msvcrt`, native UNIX datagram sockets, systemd service directives, pytest 8.

## Global Constraints

- Production bot remains inactive and disabled; no `systemctl enable/start` is executed or added.
- No production `.env`, Telegram profile, provider, VPS, database, web or AWG mutation is authorized.
- Persistent allowed updates are exactly `message` and `callback_query`.
- Admission never deletes a webhook, drains backlog or acknowledges an update.
- Initial admission failure occurs before workflow/DB initialization.
- Stable failures never include token, proxy credentials, raw Telegram response or exception text.
- Python remains `>=3.12,<3.13`; add no dependency.
- Every implementation task follows RED test, observed failure, minimal GREEN implementation, focused regression and diff check.

---

### Task 1: Settings and runtime registry contract

**Files:**
- Modify: `app/config/settings.py`
- Modify: `.env.example`
- Modify: `deploy/runtime/manifest.yml`
- Modify: `tests/config/test_settings.py`
- Modify: `tests/deploy/test_runtime_registry.py`

**Interfaces:**
- Produces: `Settings.telegram_expected_bot_username: str`
- Produces: `Settings.telegram_admission_timeout_seconds: int`
- Produces: `Settings.telegram_polling_timeout_seconds: int`
- Produces: `Settings.telegram_runtime_lock_path: str`

- [ ] **Step 1: Write failing settings and manifest tests**

Add tests that assert defaults, overrides and invalid bounds:

```python
def test_settings_reads_persistent_telegram_runtime_defaults_and_overrides():
    defaults = Settings(
        _env_file=None,
        telegram_bot_token="CHANGE_ME",
        app_secret_key="test-secret",
    )
    custom = Settings(
        _env_file=None,
        telegram_bot_token="CHANGE_ME",
        app_secret_key="test-secret",
        telegram_expected_bot_username="@expected_bot",
        telegram_admission_timeout_seconds=45,
        telegram_polling_timeout_seconds=25,
        telegram_runtime_lock_path="/tmp/amn2-bot.lock",
    )

    assert defaults.telegram_expected_bot_username == ""
    assert defaults.telegram_admission_timeout_seconds == 30
    assert defaults.telegram_polling_timeout_seconds == 20
    assert defaults.telegram_runtime_lock_path == "/run/amn2-bot/polling.lock"
    assert custom.telegram_expected_bot_username == "@expected_bot"
    assert custom.telegram_admission_timeout_seconds == 45
    assert custom.telegram_polling_timeout_seconds == 25
    assert custom.telegram_runtime_lock_path == "/tmp/amn2-bot.lock"
```

Parametrize admission values `0, 121`, polling values `0, 51`, and blank lock
path; each must raise `ValidationError` with its environment key. Extend the
runtime registry test to require a `telegram_persistent` block with the four
setting names, exact allowed updates and `activation: separate_exact_gate`.

- [ ] **Step 2: Run RED tests**

Run:

```text
.venv/Scripts/python.exe -m pytest tests/config/test_settings.py tests/deploy/test_runtime_registry.py -q
```

Expected: new tests fail because fields and manifest block do not exist.

- [ ] **Step 3: Add minimal Settings fields and validation**

Add fields next to the existing Telegram settings:

```python
telegram_expected_bot_username: str = Field(
    default="", alias="TELEGRAM_EXPECTED_BOT_USERNAME"
)
telegram_admission_timeout_seconds: int = Field(
    default=30, alias="TELEGRAM_ADMISSION_TIMEOUT_SECONDS"
)
telegram_polling_timeout_seconds: int = Field(
    default=20, alias="TELEGRAM_POLLING_TIMEOUT_SECONDS"
)
telegram_runtime_lock_path: str = Field(
    default="/run/amn2-bot/polling.lock", alias="TELEGRAM_RUNTIME_LOCK_PATH"
)
```

In the existing model validator, enforce admission `1..120`, polling `1..50`,
strip expected username, strip the lock path and reject a blank lock path.
Add exact defaults to `.env.example`. Add this manifest block:

```yaml
telegram_persistent:
  activation: separate_exact_gate
  allowed_updates:
    - message
    - callback_query
  settings:
    expected_bot_username: TELEGRAM_EXPECTED_BOT_USERNAME
    admission_timeout_seconds: TELEGRAM_ADMISSION_TIMEOUT_SECONDS
    polling_timeout_seconds: TELEGRAM_POLLING_TIMEOUT_SECONDS
    runtime_lock_path: TELEGRAM_RUNTIME_LOCK_PATH
```

- [ ] **Step 4: Run GREEN tests and diff check**

Run the Step 2 command and `git diff --check`. Expected: PASS.

---

### Task 2: Fail-closed admission and single-instance lock

**Files:**
- Create: `app/bot/persistent_runtime.py`
- Create: `tests/bot/test_persistent_runtime.py`

**Interfaces:**
- Produces: `PERSISTENT_ALLOWED_UPDATES: tuple[str, str]`
- Produces: `PersistentBotAdmissionConfig`
- Produces: `PersistentBotAdmissionResult.render() -> str`
- Produces: `PersistentBotAdmissionError`
- Produces: `PersistentBotInstanceLock`
- Produces: `admit_persistent_bot(bot, config) -> PersistentBotAdmissionResult`
- Produces: `recheck_persistent_bot_state(bot, config) -> None`

- [ ] **Step 1: Write RED admission tests**

Build a `FakeBot` with `get_me`, `get_webhook_info` and `get_updates`. Cover:

```python
def test_admission_accepts_exact_identity_empty_webhook_and_zero_backlog():
    async def scenario():
        bot = FakeBot(username="expected_bot", webhook_url="", pending=0, updates=[])
        result = await admit_persistent_bot(
            bot,
            PersistentBotAdmissionConfig(
                expected_bot_username="@Expected_Bot",
                timeout_seconds=30,
            ),
        )
        return bot, result

    bot, result = asyncio.run(scenario())
    assert result.bot_identity == "@expected_bot"
    assert result.pending_update_count == 0
    assert bot.allowed_updates == ["message", "callback_query"]
    assert "token" not in result.render().casefold()
```

Add separate tests for blank/placeholder expected username, identity mismatch,
configured webhook, nonzero backlog, non-integer/negative backlog, ownership
probe returning an update, `TelegramConflictError`, `TelegramNetworkError`,
timeout, raw exception text redaction and repeated state recheck. Assert no
`delete_webhook` call and no acknowledgement offset.

Add a real temporary-path lock test:

```python
def test_instance_lock_rejects_duplicate_and_can_be_reacquired(tmp_path):
    path = tmp_path / "polling.lock"
    with PersistentBotInstanceLock(path):
        with pytest.raises(PersistentBotAdmissionError, match="already running"):
            with PersistentBotInstanceLock(path):
                pass
    with PersistentBotInstanceLock(path):
        pass
```

- [ ] **Step 2: Run RED test**

Run:

```text
.venv/Scripts/python.exe -m pytest tests/bot/test_persistent_runtime.py -q
```

Expected: collection fails because the module does not exist.

- [ ] **Step 3: Implement admission types and validation**

Use these exact public shapes:

```python
PERSISTENT_ALLOWED_UPDATES = ("message", "callback_query")

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
        return " ".join((
            "telegram_persistent_admission=pass",
            f"bot_identity={self.bot_identity}",
            "webhook_configured=false",
            f"pending_update_count={self.pending_update_count}",
            f"allowed_updates={','.join(self.allowed_updates)}",
        ))
```

`admit_persistent_bot` validates configuration before network, wraps the full
check in `asyncio.timeout`, maps `TelegramConflictError` to
`Telegram long-poll ownership conflict`, maps network/API failures to
`Telegram persistent admission network failure`, and maps every other
unexpected exception to `Telegram persistent admission failed safely`.
`recheck_persistent_bot_state` repeats identity/webhook/backlog validation but
does not issue another ownership probe.

- [ ] **Step 4: Implement cross-platform process-lifetime lock**

Open the configured existing-parent path as binary append/update. On POSIX use
`fcntl.flock(fd, LOCK_EX | LOCK_NB)`; on Windows lock one initialized byte with
`msvcrt.locking(fd, LK_NBLCK, 1)`. Map path/lock failures to stable admission
errors and release/unlock/close in `__exit__` even after exceptions.

- [ ] **Step 5: Run GREEN tests and focused regressions**

Run:

```text
.venv/Scripts/python.exe -m pytest tests/bot/test_persistent_runtime.py tests/bot/test_controlled_smoke.py -q
```

Expected: PASS; the controlled smoke contract remains unchanged.

---

### Task 3: Dependency-free systemd readiness and watchdog

**Files:**
- Create: `app/systemd_notify.py`
- Create: `tests/test_systemd_notify.py`

**Interfaces:**
- Produces: `SystemdNotifyError`
- Produces: `SystemdNotifier.from_environment()`
- Produces: `SystemdNotifier.ready(status: str) -> None`
- Produces: `SystemdNotifier.stopping(status: str) -> None`
- Produces: `SystemdNotifier.watchdog_interval_seconds() -> float | None`
- Produces: `SystemdNotifier.run_watchdog() -> Awaitable[None]`

- [ ] **Step 1: Write RED notifier tests**

Use injected `env`, `socket_factory` and `sleep` to assert:

- missing `NOTIFY_SOCKET` is no-op;
- filesystem and abstract `@name` sockets are normalized correctly;
- READY payload is `READY=1\nSTATUS=<sanitized>`;
- STOPPING payload is equivalent;
- watchdog interval is half `WATCHDOG_USEC` and sends `WATCHDOG=1` repeatedly;
- zero, negative, non-integer watchdog values raise `SystemdNotifyError`;
- status rejects newline/NUL, and constant status payloads do not include
  unrelated environment values such as a Telegram token;
- socket send failure raises stable `SystemdNotifyError` without raw path/error.

- [ ] **Step 2: Run RED test**

Run `.venv/Scripts/python.exe -m pytest tests/test_systemd_notify.py -q`.
Expected: module-not-found failure.

- [ ] **Step 3: Implement the notifier**

Use a dataclass storing an optional socket address, watchdog microseconds,
socket factory and async sleep callable. Send UTF-8 datagrams through a fresh
`socket(AF_UNIX, SOCK_DGRAM)` context. `run_watchdog` loops forever, sleeps for
half the configured interval and sends `WATCHDOG=1`; it returns immediately
when watchdog is not configured. Do not read or log any unrelated environment
value.

- [ ] **Step 4: Run GREEN tests**

Run the Step 2 command and `git diff --check`. Expected: PASS.

---

### Task 4: Compose admission, DB bootstrap, explicit polling and cleanup

**Files:**
- Modify: `app/main.py`
- Modify: `tests/bot/test_app_bootstrap.py`

**Interfaces:**
- Consumes: Task 1 Settings fields
- Consumes: Task 2 admission/lock interfaces
- Consumes: Task 3 notifier interfaces
- Produces: `run_persistent_bot(settings, *, ...) -> None`

- [ ] **Step 1: Write RED bootstrap ordering tests**

Add async tests with injected factories and event recording:

```python
def test_persistent_bootstrap_admits_before_workflow_and_polls_explicit_updates(tmp_path):
    events = []

    asyncio.run(run_persistent_bot(
        make_settings(tmp_path),
        bot_factory=lambda **kwargs: FakeBot(events),
        workflow_factory=lambda settings: events.append("workflow") or object(),
        dispatcher_factory=lambda **kwargs: FakeDispatcher(events),
        admission_checker=passing_admission(events),
        state_checker=passing_recheck(events),
        lock_factory=recording_lock(events),
        notifier=FakeNotifier(events),
        receipt_writer=lambda value: events.append(("receipt", value)),
    ))
    assert events.index("admission") < events.index("workflow")
    assert ("poll", ["message", "callback_query"], 20, False) in events
```

Add tests proving local lock failure and admission failure create no workflow;
recheck failure creates no polling/readiness; readiness occurs after polling
task starts; watchdog failure cancels polling and exits; network failure is
sanitized; cancellation closes session and releases lock; receipt contains no
token/admin ID/proxy credential.

- [ ] **Step 2: Run RED tests**

Run `.venv/Scripts/python.exe -m pytest tests/bot/test_app_bootstrap.py -q`.
Expected: imports/signatures fail because `run_persistent_bot` is absent.

- [ ] **Step 3: Implement the coordinator**

Change `run()` to instantiate Settings and delegate. Add a testable
`run_persistent_bot` with keyword-injected factories/checkers/notifier. The
coordinator must:

```python
with lock_factory(settings.telegram_runtime_lock_path):
    bot = bot_factory(
        telegram_bot_token=settings.telegram_bot_token,
        telegram_proxy_url=settings.telegram_proxy_url,
    )
    try:
        config = PersistentBotAdmissionConfig(
            expected_bot_username=settings.telegram_expected_bot_username,
            timeout_seconds=settings.telegram_admission_timeout_seconds,
        )
        result = await admission_checker(bot, config)
        workflow = workflow_factory(settings)
        dispatcher = dispatcher_factory(workflow=workflow)
        await state_checker(bot, config)
        polling = asyncio.create_task(dispatcher.start_polling(
            bot,
            polling_timeout=settings.telegram_polling_timeout_seconds,
            allowed_updates=list(PERSISTENT_ALLOWED_UPDATES),
            close_bot_session=False,
        ))
        await asyncio.sleep(0)
        if polling.done():
            await polling
        receipt_writer(result.render())
        notifier.ready("Telegram polling admitted")
        await _wait_for_polling_and_watchdog(polling, notifier)
    finally:
        notifier.stopping("Telegram polling stopped")
        await _close_bot_session(bot)
```

The helper awaiting polling/watchdog uses `asyncio.wait(...,
FIRST_COMPLETED)`, cancels the sibling task and awaits cancellation so no task
exception is lost. Preserve the existing actionable `TelegramNetworkError`
mapping for post-admission polling failures without raw exception text.

- [ ] **Step 4: Run GREEN bootstrap and network tests**

Run:

```text
.venv/Scripts/python.exe -m pytest tests/bot/test_app_bootstrap.py tests/bot/test_network_check.py tests/bot/test_persistent_runtime.py -q
```

Expected: PASS.

---

### Task 5: Harden the systemd template

**Files:**
- Modify: `deploy/systemd/amneziya-bot.service.example`
- Modify: `tests/deploy/test_systemd_templates.py`

**Interfaces:**
- Consumes: Task 1 default lock path and Task 3 notify/watchdog protocol
- Produces: copy-ready but disabled systemd unit template

- [ ] **Step 1: Write RED unit-template assertions**

Assert exact presence of `Type=notify`, `NotifyAccess=main`, `WatchdogSec=60s`,
`TimeoutStartSec=45s`, `TimeoutStopSec=30s`, `RuntimeDirectory=amn2-bot`,
`RuntimeDirectoryMode=0750`, `StartLimitIntervalSec=300s`,
`StartLimitBurst=3`, `RestartSec=30s`, `UMask=0077`, empty capability sets,
all design sandbox directives, exact restricted address families and the four
AMN2 writable paths. Assert absence of `systemctl enable`, `systemctl start`,
`IPAddressDeny=any`, broad `/opt/amn2` write access and AWG service commands.

- [ ] **Step 2: Run RED template test**

Run `.venv/Scripts/python.exe -m pytest tests/deploy/test_systemd_templates.py -q`.
Expected: new assertions fail against the current simple unit.

- [ ] **Step 3: Add bounded restart/readiness/sandbox directives**

Keep the existing user, group, working directory, environment file and
`python -m app.main` command. Add the exact directives from the design. Place
start-limit directives in `[Unit]`, readiness/watchdog/runtime/security/write
directives in `[Service]`, and leave `[Install]` declarative only.

- [ ] **Step 4: Run GREEN deployment tests**

Run:

```text
.venv/Scripts/python.exe -m pytest tests/deploy/test_systemd_templates.py tests/deploy/test_runtime_registry.py -q
```

Expected: PASS.

---

### Task 6: Verification, security review and source commit

**Files:**
- Review: every file changed by Tasks 1-5
- Update only if required by evidence: design/plan documents

**Interfaces:**
- Produces: clean tested source commit with no production activation

- [ ] **Step 1: Run the full scoped Telegram/runtime suite**

Run:

```text
.venv/Scripts/python.exe -m pytest tests/bot/test_persistent_runtime.py tests/bot/test_app_bootstrap.py tests/bot/test_network_check.py tests/config/test_settings.py tests/deploy/test_systemd_templates.py tests/deploy/test_runtime_registry.py tests/bot/test_controlled_smoke.py -q
```

Expected: all pass.

- [ ] **Step 2: Run full regression and static checks**

Run:

```text
.venv/Scripts/python.exe -m pytest -q
.venv/Scripts/python.exe -m app.toolchain check
.venv/Scripts/python.exe -m compileall -q app tests
git diff --check
```

Expected: full suite PASS, CPython 3.12 PASS, compile PASS and empty diff-check output.

- [ ] **Step 3: Perform security diff review**

Review every changed source/config/unit/test file for token/raw-exception leaks,
Telegram update acknowledgement, webhook mutation, lock bypass, watchdog task
loss, systemd writable-path expansion, restart loop and unintended production
activation. No reportable finding may remain before commit.

- [ ] **Step 4: Commit and push implementation**

Stage only planned AMN2 source files and commit:

```text
git commit -m "Harden Telegram persistent bot admission"
git push origin codex-vps-test-prep
```

Verify local HEAD equals `origin/codex-vps-test-prep`.

---

### Task 7: Root Phase 11 evidence/status sync

**Files:**
- Modify: root `docs/PROJECT_STATUS_CURRENT.ru.md`
- Modify: root `docs/AMN2_PHASE_11_CURRENT_PRIORITY_PLAN.ru.md`
- Modify: root `docs/AMN2_PHASE_11_CONTROLLED_LAUNCH_AND_OPERATIONS_ENTRY.ru.md`
- Modify: root `docs/NEXT_CHAT_AMN2_PHASE_11_CONTROLLED_LAUNCH_AND_OPERATIONS.ru.md`
- Create: root `research/amn2/phase-11-telegram-002a-local-persistent-admission-unit-hardening-2026-07-15.md`

**Interfaces:**
- Consumes: exact source commit SHA and fresh verification/security evidence
- Produces: current Phase 11 handoff and next exact activation/package gate

- [ ] **Step 1: Record sanitized evidence**

Record architecture, RED/GREEN counts, full regression count, security result,
exact source SHA and explicit live exclusions. Do not include token, bot numeric
ID, configured admin IDs, proxy credential, provider/server identity or raw log.

- [ ] **Step 2: Update authoritative top overrides and recommendations**

Mark TELEGRAM-002A local hardening complete but production bot
inactive/disabled. Preserve production overlay until a separately approved
package/live transaction. Include `Одиночная`, `Двойная`, `Тройная`,
`Четверная`, and `Более — рекомендовано` exact next chains.

- [ ] **Step 3: Run root tests and diff/security review**

Run `python -m pytest tests -q` and `git diff --check`; review the sanitized
evidence/status diff and confirm
`docs/CLIENT_RELEASE_MONITOR_BASELINE.ru.md` remains untouched/untracked.

- [ ] **Step 4: Commit, push and verify root sync**

Commit only the five planned status/evidence paths, push
`codex-spark-phase9-docs-sync`, and verify local/origin SHA equality.
