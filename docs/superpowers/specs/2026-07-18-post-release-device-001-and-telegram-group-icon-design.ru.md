# Post-release DEVICE-001 и TELEGRAM-GROUP-ICON-001 design

Дата: 2026-07-18.

Статус: `written-spec-approved-for-local-implementation`.

Утверждение:

```text
APPROVE_POST_RELEASE_DEVICE_001_READ_ONLY_OPERATOR_UX_AND_TELEGRAM_GROUP_ICON_GATE_DESIGN
```

Письменная спецификация отдельно утверждена:

```text
APPROVE_WRITTEN_DEVICE_001_AND_TELEGRAM_GROUP_ICON_001_SPEC_57EFE86
```

Это утверждение разрешает планирование, локальную реализацию и проверки, но
не разрешает `setChatPhoto` или иной live Telegram mutation.

Базовая ветка и commit:

```text
branch=codex-vps-test-prep
base=0b858c5cdbc5b565cc265966a2edfe2d339d65e0
production_overlay=0b858c5
phase11_release=completed-controlled-private-release
```

## 1. Декомпозиция

Утверждение охватывает два независимых трека, которые нельзя смешивать в
одну реализацию или один live authority:

1. `DEVICE-001` — локальная authenticated read-only operator UX поверх уже
   существующих `device_passports` и `device_lifecycle_events`.
2. `TELEGRAM-GROUP-ICON-001` — отдельный operational gate для изменения фото
   конкретной Telegram-группы canonical square logo.

`DEVICE-001` реализуется и тестируется без Telegram/VPS/network действий.
`TELEGRAM-GROUP-ICON-001` сначала получает собственный план, executor,
checksum/security review и exact approval; design approval не разрешает live
вызов Telegram API.

## 2. DEVICE-001: цель

Дать authenticated web-оператору понятный общий список Device Passport и
детальную карточку lifecycle/drift-состояния, не создавая новую write/API,
VPS или config-delivery поверхность.

Оператор должен отвечать на вопросы:

- кому принадлежит паспорт;
- с каким local device он связан;
- какая платформа и официальный клиент записаны;
- прошла ли acceptance-проверка;
- был ли паспорт отозван;
- какой desired/observed/drift state известен;
- насколько свежо наблюдение;
- какие безопасные lifecycle stages уже зафиксированы;
- какое следующее read-only действие рекомендуется.

## 3. DEVICE-001: не входит в scope

- создание, изменение, attach, revoke или удаление паспорта;
- issue/claim/revoke Enrollment Ticket;
- config/peer generation или delivery;
- показ raw config, private key, PSK, enrollment secret или token hash;
- live peer inventory collection, SSH, VPS или Telegram API;
- automatic drift remediation;
- public/self-service route;
- новый JSON API;
- hardware fingerprint, MDM, endpoint posture, attestation или собственный
  trusted AMN2 endpoint agent.

## 4. Рассмотренные подходы

### A. Отдельные list/detail страницы — выбран

```text
GET /device-passports
GET /device-passports/{device_id}
```

Плюсы: единая operator inventory, явная read-only граница, понятный detail,
не перегружает существующую карточку пользователя.

### B. Только список внутри `/users/{user_id}`

Меньше новых компонентов, но нет общей картины и поиск начинается с заранее
известного владельца. Оставлен только как дополнительная ссылка из карточки
пользователя, не как основной UX.

### C. API-first

Не выбран: расширяет private API до появления конкретного integration
consumer и не даёт требуемый operator UX быстрее web-first варианта.

## 5. DEVICE-001: архитектура

### Repository

В `app/db/repositories.py` добавляется read-only запрос:

```python
Repository.list_device_passports(*, limit: int = 100) -> list[sqlite3.Row]
```

Контракт:

- `1 <= limit <= 100`;
- сортировка `updated_at DESC, device_id ASC`;
- выбираются только safe passport columns;
- запрос не выбирает Enrollment Ticket token/idempotency hashes;
- транзакция и DB mutation отсутствуют.

Существующий `list_device_passports_for_owner(...)` не меняет semantics.

### Domain service

В `app/services/device_passports.py` добавляется:

```python
list_all_device_passports(
    repo: Repository,
    *,
    reconciliations: dict[str, ReconciliationSnapshot] | None = None,
    limit: int = 100,
) -> tuple[DevicePassport, ...]
```

Он повторно использует `_passport_from_row`, не выполняет remote observation
и возвращает `unknown` reconciliation, если snapshot не был передан.

### Web projector

Новый `app/web/device_passports.py` отвечает только за безопасную проекцию
domain objects в template context:

```python
build_device_passport_list_view(repo: Repository, *, limit: int = 100)
build_device_passport_detail_view(repo: Repository, device_id: str)
```

Projector:

- получает safe owner display через существующий user repository;
- добавляет lifecycle events через `list_device_lifecycle_events`;
- вычисляет только display labels и lifecycle completion summary;
- не принимает `Settings`, SSH client, Telegram client или network collector;
- не возвращает raw database rows в template.

### Web routes

В `app/web/app.py` добавляются два GET route:

```text
GET /device-passports
GET /device-passports/{device_id}
```

Оба требуют существующую authenticated web-admin session. Detail возвращает
fixed `404 Device passport not found` для отсутствующего ID. POST/PUT/DELETE
route в этом slice нет.

### Templates

Создаются:

```text
app/web/templates/device_passports.html
app/web/templates/device_passport_detail.html
```

`base.html` получает ссылку `Паспорта устройств` только в authenticated nav.
Карточка пользователя получает read-only ссылку на общий список; owner-filter
в этот MVP не входит.

## 6. DEVICE-001: отображаемые данные

### List

- stable `dev_<uuid>` ID;
- owner display и ссылка на `/users/{owner_user_id}`;
- local device ID или `не привязан`;
- platform, official client и client version;
- acceptance status;
- active/revoked state;
- drift state;
- last seen и last observed;
- updated at;
- ссылка на detail.

List ограничен последними 100 строками и явно показывает это ограничение.

### Detail

- все safe metadata из `DevicePassport.safe_metadata()`;
- полный SHA-256 config fingerprint как audit identifier, но не raw config;
- desired/observed/drift blocks;
- safe reconciliation evidence;
- recommended next action с пометкой `read-only recommendation`;
- acceptance evidence;
- ordered lifecycle events;
- capability boundary с явными `false` для hardware fingerprint, endpoint
  posture, impersonation protection, MDM и AMN2 agent.

## 7. DEVICE-001: security и privacy

Новые SurfacePolicy IDs:

```text
web.device_passports.index
web.device_passports.detail
```

Оба имеют:

```text
actor=web-admin
auth=session
risk_class=secret-adjacent-read
implementation_mode=implemented
enables_new_behavior=true
audit_required=false
live_retest_required=false
vps_write=false
```

Обязательные gates:

- session required;
- safe metadata only;
- no raw config/private key/PSK/ticket secret/token hash;
- no remote observation;
- no DB mutation;
- fixed 404;
- HTML escaping через Jinja autoescape.

## 8. DEVICE-001: ошибки

- unauthenticated request: существующий `303 /login`;
- unknown passport: fixed `404`;
- malformed device ID: тот же fixed `404`, без stack trace;
- missing owner row: fail closed как `404`, не частично отображённая карточка;
- malformed stored evidence: request возвращает controlled server error с
  redacted log; raw JSON не отражается в HTML;
- template не инициирует автоматический retry или mutation.

## 9. DEVICE-001: TDD acceptance

Минимальные тестовые группы:

1. Repository: global ordering, hard limit и invalid limit.
2. Service/projector: owner display, unknown reconciliation, lifecycle order,
   revoked и acceptance labels.
3. Web auth: оба route перенаправляют unauthenticated user.
4. List: показывает несколько owners и safe status fields.
5. Detail: показывает lifecycle/drift/capability boundary.
6. Not found: fixed `404` без отражения входного значения.
7. Secret-negative: HTML не содержит raw config/private key/PSK/ticket hash.
8. Read-only invariant: полный SQLite dump до и после list/detail совпадает.
9. SurfacePolicy inventory/binding: оба GET route покрыты и не входят в
   state-changing/VPS-write contour.
10. Full suite и package asset/template inclusion.

## 10. TELEGRAM-GROUP-ICON-001: цель

Применить canonical square logo к одной явно идентифицированной Telegram
group/supergroup, если пользователь подтвердит, что речь именно о group chat
photo, а не о profile photo самого бота.

Canonical asset:

```text
path=app/bot/assets/NEOBYATNAYA-AMNZ-BOT.png
sha256=40ACD9465DC9FDA06644D2D829DA996E1D9BF6C856E95298B624B31154FEC791
dimensions=1254x1254
```

## 11. TELEGRAM-GROUP-ICON-001: отдельная граница

Design approval не разрешает `setChatPhoto`. Перед live action обязательны:

1. отдельный bilingual implementation/runbook plan;
2. exact target chat ID/username, сохранённый только в private runtime input;
3. secret-safe fingerprint target chat ID в approval/evidence;
4. `getMe` identity match;
5. `getChat` exact title/type readback;
6. `getChatMember` для самого бота и право `can_change_info=true`;
7. exact asset SHA/PNG/dimensions check;
8. snapshot текущей chat photo в private `0600` temp или receipt
   `no_existing_photo`;
9. checksum-bound executor и отдельная literal approval;
10. один `setChatPhoto`, затем `getChat` postflight;
11. restore previous photo при failure; если фото не было —
    `deleteChatPhoto` rollback;
12. mandatory private snapshot/temp cleanup и secret re-audit.

## 12. TELEGRAM-GROUP-ICON-001: запрещено

- `setMyProfilePhoto` или изменение profile photo самого бота;
- отправка сообщения, `/start`, photo/message/document;
- webhook mutation или polling backlog consumption;
- restart/stop/disable regular bot;
- DB, web, config, peer, provider или VPS package mutation;
- любое AWG действие;
- логирование bot token, raw chat ID или token-bearing URL;
- применение, если пользователь имел в виду bot avatar, а не group photo.

## 13. TELEGRAM-GROUP-ICON-001: success receipt

```text
target_chat_fingerprint=match
bot_identity=match
bot_can_change_info=true
asset_sha256=40ACD9465DC9FDA06644D2D829DA996E1D9BF6C856E95298B624B31154FEC791
set_chat_photo_calls=1
postflight_photo_changed=true
messages_sent=0
bot_service=active_enabled_restart_unchanged
database=unchanged
web=unchanged
awg=untouched
private_temp_cleanup=pass
```

## 14. English normative summary

`DEVICE-001` adds authenticated, read-only Device Passport list/detail pages
over existing SQLite passport and lifecycle records. It performs no remote
collection, no database mutation, no config/peer operation, and exposes only
safe metadata. The implementation must add explicit read-only SurfacePolicy
bindings and prove database immutability plus secret-negative rendering.

`TELEGRAM-GROUP-ICON-001` is a separate live operational gate. It may change
one explicitly bound group chat photo to the canonical square logo only after
identity, permission, asset, rollback, checksum and exact-approval checks. It
must not change the bot profile, send messages, consume updates, restart the
bot, mutate the database/web/VPS package, or touch AWG.

## 15. Последовательность

```text
DEVICE_001_SPEC_REVIEW
-> DEVICE_001_TDD_IMPLEMENTATION_PLAN
-> DEVICE_001_RED_GREEN_REFACTOR
-> DEVICE_001_SCOPED_FULL_DIFF_SECURITY
-> DEVICE_001_STATUS_COMMIT_PUSH
-> TELEGRAM_GROUP_ICON_001_PLAN_AND_LOCAL_EXECUTOR
-> TELEGRAM_GROUP_ICON_001_TEST_DIFF_SECURITY_COMMIT_PUSH
-> SEPARATE_EXACT_LIVE_APPROVAL
-> PREFLIGHT_APPLY_POSTFLIGHT_OR_ROLLBACK
```

Ни один поздний шаг не наследует authority предыдущего шага.
