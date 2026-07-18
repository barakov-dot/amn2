# POST-RELEASE-API-001: current-overlay transient loopback acceptance design

Дата: 2026-07-18.

Статус: `design-approved|written-spec-pending-review`.

Утверждение дизайна:

```text
APPROVE_API_001_DESIGN
```

Полная пользовательская последовательность:

```text
APPROVE_API_001_DESIGN -> WRITE_AND_COMMIT_BILINGUAL_SPEC -> WRITE_TDD_PLAN -> IMPLEMENT_FAIL_CLOSED_CLONE_DB_EXECUTOR -> RUN_SCOPED_AND_FULL_TESTS -> RUN_DIFF_AND_SECURITY_REVIEW -> SYNC_STATUS_COMMIT_AND_PUSH -> ISSUE_SEPARATE_EXACT_LIVE_APPROVAL_PHRASE
```

Это утверждение разрешает записать и закоммитить bilingual design spec. Оно не
разрешает SSH, live preflight, запуск API на VPS или иной production action.
Переход к TDD-плану и реализации требует отдельного подтверждения именно
письменной спецификации.

## 1. Исходное состояние

```text
amn2_branch=codex-vps-test-prep
production_overlay=0b858c5cdbc5b565cc265966a2edfe2d339d65e0
phase11_release=completed-controlled-private-release
api_code_delta_0b858c5_to_current=none
production_api_3040_listener=absent_by_default
public_write_config_peer_self_service=closed
```

`API-001` уже имеет в `0b858c5` scoped bearer-token ядро, TTL/revoke/rotate,
safe audit metadata, шесть aggregate read-only route, CLI smoke-cycle и
loopback-only bind contract. Phase 11 combined rollout намеренно не запускал
API smoke. Поэтому этот slice не добавляет API routes или scopes: он создаёт
воспроизводимый current-overlay acceptance gate для уже существующего private
API lane.

## 2. Цель

Доказать на production source overlay `0b858c5`, что private scoped API:

- поднимается только на `127.0.0.1:3040`;
- принимает только правильно scoped, неистёкший и неотозванный bearer token;
- различает `server:read` и `metrics:read`;
- проходит существующий six-route smoke-cycle;
- пишет ожидаемые token lifecycle и `api_read` audit данные только в clone DB;
- не вызывает `api_write`, remote operation, config/peer delivery или mutation;
- полностью удаляет временный listener, process, token material и clone DB;
- оставляет production bot, web, database и AWG в исходном состоянии.

Результат — operational acceptance receipt. Постоянный API service, public
listener и новый integration consumer в этот slice не входят.

## 3. Рассмотренные подходы

### A. Transient API с SQLite clone — выбран

Создать private consistent clone production SQLite через read-only source
connection и SQLite backup API, направить transient API и smoke-cycle на clone,
затем удалить clone.

Плюсы: проверяются реальные current schema/data и production bytes; token и
audit writes не попадают в production DB; cleanup имеет простой fail-closed
контракт.

Ограничение: это acceptance private API lane, а не постоянного API service.

### B. Smoke непосредственно на production DB — отклонён

Даёт прямую runtime-проверку, но оставляет revoked token, `last_used_at` и
audit rows. Такой production delta не нужен для read-only acceptance.

### C. Только исторические receipts — отклонён

Не создаёт live risk, но последние API receipts относятся к более ранним
overlay. Они не доказывают current-overlay acceptance `0b858c5`.

## 4. Компоненты

### Remote executor

Новый Bash executor выполняется как exact bytes через `bash -s --` и имеет два
режима:

```text
preflight
run
```

`preflight` выполняет только read-only проверки и не создаёт clone, token,
listener или state receipt. `run` требует отдельной literal approval,
проверенной локальным runner до SSH.

Executor не устанавливается на VPS и не сохраняется в `/opt/amn2`.

### Local trusted-transport runner

PowerShell runner:

- использует только absolute Windows OpenSSH path;
- требует dedicated AMN2 key и one-target known-host binding;
- вычисляет SHA-256 над теми же remote bytes, которые передаёт `bash -s`;
- сравнивает approval ordinal/exact;
- не принимает shell fragment или произвольный remote command;
- не печатает target host, raw token, DB content или secret path;
- создаёт single-use local approval receipt только для `run`.

### Tests

Static/TDD tests проверяют source binding, mode separation, exact approval,
trusted transport, clone-only DB path, listener lifecycle, cleanup trap,
watchdog, token/audit assertions и AWG no-mutation contract без SSH/network.

## 5. Source и policy preflight

Оба режима обязаны fail closed, если не выполнен любой пункт:

1. `/opt/amn2/.amn2_source_overlay_commit` равен `0b858c5`.
2. Exact SHA-256 совпадают для файлов, необходимых API smoke: CLI, API app,
   settings, schema, repositories, token service и smoke validator.
3. Python/venv, `sqlite3`/SQLite Python module, `curl`, `ss`, `systemctl`,
   `docker`, `sha256sum`, `setsid` и process tools доступны.
4. `.env` — regular non-symlink file; `VPS_APPLY_ENABLED=false` и
   `OPERATOR_DEVICE_CREATE_ENABLED=false`.
5. Production DB — regular non-symlink file; `PRAGMA integrity_check=ok` и
   `PRAGMA foreign_key_check` возвращает `0` строк.
6. `amneziya-bot.service` active/enabled, один expected process, restart count
   валиден и watchdog health проходит существующий bounded contract.
7. `amneziya-web.service` active/enabled, `/login=200`, protected route
   redirect и listener `3030` loopback-only.
8. Listener `3040` отсутствует до run.
9. AWG container/interface running; restart count, container ID, peer set и
   config hashes можно снять без mutation.
10. Достаточно свободного места для private clone и state dir.

Ни один preflight failure не запускает remediation.

## 6. Clone DB contract

`run` создаёт root-owned `0700` state dir под фиксированным base path и
root-owned `0600` SQLite clone. Имя включает bounded run ID и не зависит от
пользовательского shell input.

Clone создаётся через Python SQLite backup API:

- source URI открывается `mode=ro`;
- `initialize_schema` не вызывается;
- destination создаётся только внутри private state dir;
- после backup выполняются integrity/FK checks;
- production DB path никогда не передаётся token issue/revoke или API server;
- production `api_tokens` и API-related `admin_actions` fingerprint снимается
  до и после run и обязан совпасть.

Любая ошибка закрывает gate и запускает только mandatory cleanup. Blind DB
restore, delete production row или production schema migration запрещены.

## 7. Transient listener и watchdog

API запускается отдельной process group с environment, в котором
`DATABASE_PATH` указывает на clone, write gates равны `false`, host/port exact:

```text
127.0.0.1:3040
```

Обязательные свойства:

- listener появляется только на IPv4 loopback;
- `0.0.0.0`, public interface и IPv6 wildcard запрещены;
- PID/process group записывается только в private state dir;
- cleanup trap вооружён до старта process;
- независимый watchdog ограничивает весь run 180 секундами;
- обычный success сначала останавливает API, затем доказывает отсутствие
  listener/process и только после этого удаляет clone/state;
- failure/timeout делает ту же cleanup-последовательность и возвращает общий
  redacted `gate_rejected` без секретов.

Firewall, reverse proxy, systemd units и persistent services не меняются.

## 8. Smoke и auth acceptance

Используется существующий `python -m app.cli api smoke-cycle` с clone DB,
`http://127.0.0.1:3040`, server name из exact existing production registry и
TTL не более 7 дней.

Обязательные проверки:

1. Missing bearer возвращает `401`.
2. Invalid bearer возвращает `401` без echo.
3. `server:read` не открывает metrics/users routes (`403`).
4. `metrics:read` не открывает server routes (`403`).
5. Combined scoped token проходит ровно шесть expected GET routes.
6. Response validator не находит forbidden secret/personal markers.
7. Clone содержит один новый token lifecycle: issued, used, revoked.
8. Clone содержит expected safe `api_read` audit rows для шести route.
9. Clone не содержит нового `api_write` event.
10. Raw token, Authorization header и token hash не попадают в stdout,
    stderr, evidence или persistent local files.

Raw token может существовать только в памяти существующего smoke-cycle и
должен исчезнуть вместе с process.

## 9. Postflight

После обязательного cleanup executor независимо повторяет:

- `3040` listener/process absent;
- web active/enabled/http ok/loopback-only;
- bot active/enabled/single instance, PID/restart/watchdog invariants;
- production DB integrity/FK и API-token/API-audit fingerprint unchanged;
- AWG running, container ID/restart count/peer set/config hashes unchanged;
- clone, PID, output и state paths absent;
- public/write/config/peer/self-service gates closed.

Если invariant не совпал, gate возвращает failure и не выполняет blind
remediation. AWG нельзя останавливать, перезапускать, reconfigure или вызывать
для тестовой peer/config операции.

## 10. Exact live authority

Design/spec/plan/implementation approvals не разрешают `preflight` или `run`.
После local tests, diff/security review, commit, push и exact origin readback
выдаётся отдельная фраза, включающая final remote SHA-256 и source overlay:

```text
APPROVE POST_RELEASE_API_001_REMOTE_SHA_<SHA256>_SOURCE_0B858C5_TRANSIENT_LOOPBACK_3040_CLONE_DB_SCOPED_TOKEN_TTL_REVOKE_AUDIT_SIX_ROUTE_SMOKE_MANDATORY_CLEANUP_PRODUCTION_BOT_WEB_DB_AND_AWG_UNTOUCHED
```

Final runner должен сравнивать literal phrase целиком. Authority single-use и
не переносится на повторный run, persistent API, production DB token,
deployment или другой overlay.

## 11. Запрещено

- public API/OpenAPI/docs exposure;
- persistent API systemd service;
- production DB token issue/use/revoke/audit writes;
- `install:write` route smoke или любой POST;
- config read/delivery, QR, `vpn://`, key/PSK access;
- peer create/revoke/sync или remote operation;
- bot/Telegram API message, update consumption или profile mutation;
- web restart/reconfigure;
- schema migration или blind DB restore;
- provider action;
- любое AWG stop/restart/reconfigure/test;
- Phase 10/11 rollout, `/start`, cleanup, stage, accept или restore repeat;
- диагностика VIDDA/standalone AmneziaWG в этом project slice.

## 12. Acceptance и evidence

Local acceptance:

```text
design_spec=written_and_separately_approved
tdd=red_then_green
focused_tests=pass
full_tests=pass
diff_check=pass
security_diff_coverage=complete
security_reportable_findings=0
amn2_origin_sync=true
amn3_origin_sync=true
live_authority=not_embedded
```

Будущий live success receipt:

```text
source_overlay=0b858c5|exact_source_hashes_match
preflight=pass
clone_db=private_consistent_integrity_ok_fk_0
api=transient_loopback_127.0.0.1_3040|six_routes_pass
auth=401_401_403_403|scopes_match
token=clone_only|ttl_bounded|used|revoked|raw_not_persisted
audit=clone_only|six_safe_reads|api_write_0
cleanup=listener_0|process_0|clone_0|state_0
production_bot=unchanged
production_web=unchanged
production_database=integrity_ok|fk_0|api_fingerprint_unchanged
production_awg=unchanged|never_mutated
public_write_config_peer_self_service=closed
```

## 13. Последовательность

```text
WRITTEN_SPEC_REVIEW
-> TDD_IMPLEMENTATION_PLAN
-> RED_TESTS
-> MINIMAL_EXECUTOR_AND_RUNNER
-> GREEN_SCOPED_AND_FULL_TESTS
-> DIFF_AND_SECURITY_REVIEW
-> STATUS_EVIDENCE_SYNC
-> COMMIT_PUSH_EXACT_ORIGIN_READBACK
-> ISSUE_SEPARATE_EXACT_LIVE_APPROVAL
-> ONLY_AFTER_APPROVAL_PREFLIGHT_AND_RUN
```

Ни один шаг не наследует live authority предыдущего шага.
