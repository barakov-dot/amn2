# Phase 11 TELEGRAM-002A: persistent admission and unit hardening design

Дата: 2026-07-15

Статус: approved for local implementation by the operator command
`REVIEW_PHASE11_TELEGRAM_002A_FAIL_CLOSED_DESIGN -> APPROVE_TELEGRAM_002A_DESIGN`.

## Цель

Подготовить persistent private Telegram bot к отдельному будущему activation
gate. Запуск должен fail closed до инициализации production workflow, если
identity, webhook, backlog, poll ownership или single-instance contract не
доказаны. Systemd unit должен ограничивать restart loop, сообщать readiness и
watchdog state и работать с минимально необходимыми filesystem/device правами.

Этот slice только локальный. Он не включает `systemctl enable/start`, изменение
production `.env`, вызов Telegram API с production token, upload package,
перезапуск production web/AWG или изменение Telegram profile photo.

## Рассмотренные варианты

### A. Строгий двухступенчатый admission — выбран

До workflow/DB initialization процесс получает local exclusive lock, затем в
bounded timeout проверяет `getMe`, expected username, отсутствие webhook,
нулевой backlog и выполняет non-consuming zero-time `getUpdates` probe. После
создания workflow/dispatcher webhook/backlog проверяются повторно, и только
затем начинается polling с явным update allowlist.

Плюсы: fail closed, не очищает updates, не мутирует webhook, не пишет DB при
admission failure, обнаруживает local duplicate и активного remote poller.
Минус: реальный update, пришедший в узком startup window, намеренно остановит
startup и потребует operator review.

### B. Автоматически очищать webhook или backlog — отклонён

Такой startup был бы более автономным, но подтверждал бы или терял updates и
превращал admission в скрытую live mutation. Это несовместимо с exact-gate
моделью Phase 11.

### C. Только systemd single-unit и Telegram conflict retry — отклонён

Systemd предотвращает второй local unit, но не доказывает bot identity,
webhook/backlog state и remote poll ownership. Aiogram retry также может
превратить persistent conflict в долгий restart/retry loop.

## Компоненты

### `app/bot/persistent_runtime.py`

Новый изолированный модуль содержит:

- `PersistentBotAdmissionError` со стабильными sanitized сообщениями;
- immutable admission config/result;
- normalizer expected bot username;
- local non-blocking instance lock на configured runtime path;
- bounded Telegram admission и повторную pre-poll проверку;
- explicit `PERSISTENT_ALLOWED_UPDATES = ("message", "callback_query")`;
- sanitized startup receipt без token, numeric admin IDs или raw API payload.

Local lock держится открытым весь polling lifetime. На Linux используется
advisory exclusive non-blocking `flock`; невозможность создать/захватить lock
является startup failure. Lock path по умолчанию
`/run/amn2-bot/polling.lock`, а systemd создаёт process-owned runtime directory.

### `app/systemd_notify.py`

Малый dependency-free адаптер отправляет datagrams в `NOTIFY_SOCKET`:

- `READY=1` только после успешных admission checks;
- `WATCHDOG=1` с интервалом не более половины `WATCHDOG_USEC`;
- `STOPPING=1` при штатном завершении;
- status text без секретов.

Если process запущен не systemd, отсутствие `NOTIFY_SOCKET`/`WATCHDOG_USEC`
является нормальным no-op. Некорректное positive watchdog environment fail
closed до polling; transient notify send failure завершает runtime, чтобы
systemd не считал зависший процесс healthy.

### `app/main.py`

Persistent bootstrap меняется на следующий порядок:

1. Parse and validate `Settings`.
2. Acquire and hold the local instance lock.
3. Create the Telegram client.
4. Run bounded initial admission.
5. Create workflow and dispatcher only after admission passed.
6. Repeat webhook/backlog check immediately before polling.
7. Emit one sanitized pass receipt and systemd readiness.
8. Run dispatcher with explicit `message,callback_query` allowlist and explicit
   polling timeout.
9. Run watchdog task for the polling lifetime.
10. On every exit, stop watchdog, close bot session and release lock.

Telegram/network/timeouts are mapped to stable errors. The token and raw API
exception text are never logged. Existing `check_bot_network` behavior remains
separate and unchanged.

## Settings contract

Добавляются backward-compatible defaults:

- `TELEGRAM_EXPECTED_BOT_USERNAME=` — optional for settings parsing, but
  mandatory and non-placeholder when `app.main` persistent runtime starts;
- `TELEGRAM_ADMISSION_TIMEOUT_SECONDS=30`, allowed range `1..120`;
- `TELEGRAM_POLLING_TIMEOUT_SECONDS=20`, allowed range `1..50`;
- `TELEGRAM_RUNTIME_LOCK_PATH=/run/amn2-bot/polling.lock`, non-blank.

Они добавляются в `.env.example` и runtime manifest. Existing web/CLI/tests can
still instantiate `Settings` without starting persistent polling.

## Telegram admission contract

Initial and repeated checks require:

- configured expected username after trimming whitespace and optional `@`;
- `getMe.username` exact case-insensitive match;
- `getWebhookInfo.url` blank;
- `pending_update_count == 0`;
- zero-time `getUpdates` ownership probe returns no updates and uses only the
  explicit persistent update allowlist;
- API/network/timeout/conflict failures do not initialize workflow or polling.

The probe does not pass an acknowledgement offset and therefore does not drain
or acknowledge backlog. If an update appears during admission, startup fails
closed rather than consuming it.

## Systemd unit contract

`deploy/systemd/amneziya-bot.service.example` changes to:

- `Type=notify`, `NotifyAccess=main`;
- bounded `TimeoutStartSec`, `TimeoutStopSec` and `WatchdogSec`;
- `Restart=on-failure`, longer `RestartSec`, `StartLimitIntervalSec` and
  `StartLimitBurst` to prevent a tight loop;
- `RuntimeDirectory=amn2-bot`, private mode and matching lock path;
- `UMask=0077`, empty capability sets, `NoNewPrivileges`, `PrivateTmp`,
  `PrivateDevices`, `ProtectSystem=strict`, `ProtectHome=true`;
- kernel/control-group/clock/hostname protection, native syscall architecture,
  namespace/SUID/personality/realtime restrictions;
- only `AF_UNIX`, `AF_INET`, `AF_INET6` address families;
- writable paths limited to AMN2 runtime data/log/backup/template directories.

The unit stays disabled in source/package and no install-time enable action is
added.

## Error and cleanup behavior

- Duplicate local lock: fail before Telegram network or DB access.
- Missing/placeholder expected username: fail before Telegram network.
- Identity/webhook/backlog/probe mismatch: close session, release lock, no DB
  initialization and no polling.
- Second check failure: close initialized workflow resources where exposed,
  close session, release lock and do not signal readiness.
- Polling/network failure after readiness: send stopping status, close session,
  release lock and exit non-zero for bounded systemd retry.
- Cancellation/shutdown: cancel watchdog, ask dispatcher to stop through normal
  aiogram lifecycle, close session once and release lock.

## Tests

### RED/GREEN unit tests

- valid identity + empty webhook + backlog 0 + empty probe passes;
- missing/mismatched identity fails;
- configured webhook fails;
- nonzero or malformed backlog fails;
- probe returning an update or raising conflict fails;
- timeout/network failure is sanitized;
- local duplicate lock fails and release permits a later acquisition;
- workflow/dispatcher are not created before admission pass;
- repeated pre-poll check is required;
- polling receives only `message,callback_query` and configured timeout;
- readiness/watchdog/stopping datagrams are bounded and secret-free;
- bot session and lock cleanup run on pass, failure and cancellation.

### Settings/systemd tests

- new defaults and bounds;
- expected username/runtime lock validation at persistent start;
- unit asserts notify/watchdog/start limits/runtime directory/sandbox/writable
  path contracts and confirms no enable/start command.

### Regression scope

At minimum:

```text
tests/bot/test_persistent_runtime.py
tests/bot/test_app_bootstrap.py
tests/bot/test_network_check.py
tests/config/test_settings.py
tests/deploy/test_systemd_templates.py
tests/deploy/test_runtime_registry.py
tests/bot/test_controlled_smoke.py
```

Then run the full source test suite, toolchain check, compile check,
`git diff --check` and security diff review.

## Acceptance

- Every admission failure precedes polling; initial failures also precede
  workflow/DB initialization.
- No admission path drains updates or changes webhook state.
- Duplicate local/remote polling is rejected with stable sanitized evidence.
- Systemd readiness and watchdog reflect a successfully admitted live event
  loop, not merely process creation.
- Unit hardening preserves outbound Telegram/proxy/DNS access and required AMN2
  runtime writes while denying broad filesystem/device/capability access.
- Production bot remains inactive/disabled and production AWG is untouched.
