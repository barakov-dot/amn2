# AMN2 Fresh Install Wizard Boundary

Дата: 2026-06-14.

Статус: Phase 7 local-only RC readiness.

Этот wizard нужен, чтобы заранее собрать будущий чистый установщик через
вопросы и ответы. Он не устанавливает AMN2, не подключается к VPS, не чистит
сервер, не открывает публичный доступ и не выдает конфиги.

## Что Делает Wizard

Команды:

```text
.\scripts\test.ps1 tests\services\test_fresh_install_wizard.py -v
python -m app.cli install wizard --pretty
python -m app.cli install plan --answers fresh-install-answers.json --pretty
```

`install wizard` задает вопросы и печатает безопасный JSON plan.

`install plan` читает заранее подготовленный JSON с ответами и печатает такой
же безопасный JSON plan.

Для Codex Desktop/Windows checkout тесты запускать через `scripts/test.ps1`, а
не через системный `python`, потому что текущий рабочий runtime - CPython
3.12.x плюс `.codex_deps`.

## Schemas

Wizard output versioned:

- plan schema: `fresh-install-plan.v1`;
- question schema: `fresh-install-questions.v1`;
- answer schema: `fresh-install-answers.v1`;
- readiness schema: `fresh-install-readiness.v1`;
- evidence schema: `fresh-install-evidence.v1`;
- current-head package preflight schema: `fresh-install-package-preflight.v1`;
- clean installer RC acceptance schema: `clean-installer-rc-acceptance.v1`;
- public/config/write prerequisite split schema:
  `public-config-write-prerequisite-split.v1`;
- public exposure readiness design schema:
  `public-exposure-readiness-design.v1`;
- config delivery channel readiness schema:
  `config-delivery-channel-readiness.v1`;
- write API scope decision schema: `write-api-scope-decision.v1`;
- backup/restore/import readiness schema:
  `backup-restore-import-prerequisite-checklist.v1`;
- Telegram identity/profile/media readiness schema:
  `telegram-identity-profile-media-prerequisite-checklist.v1`;
- multi-instance/IPAM RC decision: `local-only/docs/tests`;
- package asset path preflight: `package/preflight only`, без live apply.

`build_fresh_install_manifest()` возвращает machine-readable manifest с
описанием questions, defaults, allowed values и gated fields. Manifest также
указывает secret handoff policy: `docs/AMN2_SECRET_HANDOFF_PROTOCOL.ru.md`.

Manifest также содержит `installer_readiness`: local-only матрицу будущего
preflight/runtime/package hygiene. Она не запускает диагностику на VPS и не
разрешает SSH.

## Вопросы

Wizard собирает только безопасные operational choices. Prompt copy теперь
Russian-first, но стабильные technical IDs остаются прежними:

- `project_name` - название проекта;
- `server_name` - имя сервера;
- `runtime` - режим запуска: `docker` or `host_systemd`;
- `vpn_protocol` - VPN-протокол: `amneziawg`, `wireguard` or `xray`;
- `public_exposure` - открывать публичный доступ сейчас;
- `config_delivery` - включать реальную выдачу конфигов сейчас;
- `write_api` - включать production write API сейчас;
- `destructive_cleanup` - запускать destructive cleanup/reinstall сейчас;
- `telegram_bot` - режим Telegram bot credential;
- `secret_handoff` - режим передачи секретов.

Значения по умолчанию безопасные:

- public exposure: `no`;
- config delivery: `no`;
- write API: `no`;
- destructive cleanup: `no`;
- secrets: `operator_local`;
- `VPS_APPLY_ENABLED=false`.

## Stop Lines

Если оператор отвечает `yes` на gated направление, wizard не выполняет действие.
Он переводит план в `blocked_named_gate_required` и показывает stop-line:

- `P7-C002 required before public exposure`;
- `P7-C003 required before config delivery`;
- `P7-C005 required before write API`;
- `P7-C004 required before destructive cleanup/reinstall`.

## Safety Boundary

Всегда выключено:

- live VPS commands;
- SSH commands;
- package apply/rebuild on VPS;
- service restart/deploy;
- public listener/domain/reverse proxy;
- real config delivery;
- write API;
- Local Agent mutation;
- backup/restore/import apply;
- production peer/user mutation;
- destructive cleanup/reinstall;
- Telegram identity mutation.

Wizard output must not contain raw Telegram credentials, `.conf`, QR,
`vpn://`, private key, preshared key, SSH secret, `Authorization` header or
token hash.

Wizard input also rejects secret-bearing strings before rendering a plan. If an
answer contains a marker such as `.env`, `.conf`, `servers.yml`, QR/config
payload wording, `vpn://`, private-key material, PSK wording, authorization
headers or token material, the error names only the field and does not echo the
provided value.

Secret handoff mode по умолчанию: `operator_local`. Это значит, что wizard
может создать только checklist для оператора, но не хранит и не печатает raw
secret values. Подробный протокол: `docs/AMN2_SECRET_HANDOFF_PROTOCOL.ru.md`.

## Rendered Plan

`build_fresh_install_plan()` возвращает не только raw operator inputs, но и
`rendered_plan`:

- `local-preflight` - только локальные проверки;
- `secret-handoff-checklist` - checklist без raw secrets;
- `target-preflight-matrix` - список read-only target checks без выполнения;
- `runtime-mode-decision` - выбранный runtime mode без restart;
- `package-hygiene-checklist` - обязательные проверки перед будущим package gate;
- `current-head-package-preflight` - local-only package preflight planning для
  текущего head;
- `package-asset-path-preflight` - local-only проверка referenced operator-kit
  assets, runbook paths, archive manifests and source zip paths before any
  future package apply;
- `clean-installer-rc-acceptance` - RC acceptance checklist для answers,
  preflight, package, smoke evidence, secret handoff, rollback и stop-lines;
- `multi-instance-ipam-rc-decision` - local-only review модели конфликтов
  runtime instance, listen port, VPN CIDR, interface, endpoint и DNS/IPv6;
- `public-config-write-prerequisite-split` - local-only разделение
  заблокированного combined gate `P7-C002 + P7-C003 + P7-C005` на readiness
  tracks: public exposure, config delivery channel и write API scope decision;
- `public-exposure-readiness-design` - local-only чеклист для будущего
  `P7-C002`: admin credential contract, domain/TLS/reverse proxy plan,
  firewall/listener plan, external probe matrix и rollback-to-loopback;
- `config-delivery-channel-readiness` - local-only чеклист для будущего
  `P7-C003`: SMTP/operator-local channel decision, secret-safe evidence
  protocol, client import matrix, one-time delivery policy and delivery
  revocation story;
- `write-api-scope-decision` - local-only decision для будущего `P7-C005`:
  public API остается read-only для RC, а implementation slice и
  operator-only write window остаются deferred options;
- `backup-restore-import-readiness` - local-only checklist для будущего
  `P7-C006`: backup scope, encryption/retention policy, restore preview
  safety, import source validation and disaster-recovery drill plan;
- `telegram-identity-readiness` - local-only checklist для будущего `P7-C007`:
  identity scope decision, credential handoff/storage policy, profile/media
  asset plan, operator preview/rollback and post-mutation relock audit;
- `secret-input-contract` - local-only security contract, запрещающий raw
  secret input and value echo;
- `smoke-evidence-template` - шаблон будущего smoke evidence без секретов;
- `existing-server-reconciliation-input` - report-only input для existing server;
- `installer-docs-index` - индекс операторских документов;
- `question-answer-render` - привязка к answer schema;
- `named-gate-stop` - финальная остановка перед любым gated action.

Если в ответах есть `yes` для public exposure, config delivery, write API или
destructive cleanup, `rendered_plan.requires_named_gates` перечисляет нужные
gate IDs и статус становится `blocked_named_gate_required`.

## Installer Readiness

`target_preflight` описывает проверки, которые должен будет пройти будущий
target до clean install:

- OS release;
- CPython 3.12.x runtime;
- Docker runtime availability when `runtime=docker`;
- selected listener/VPN ports;
- disk space;
- time sync;
- package/archive tools.

В текущем slice это только `local_plan_only`. Живое выполнение этих проверок
на VPS требует отдельного named diagnostic gate.

`runtime_decision` берется из ответа `runtime` и поддерживает только:

- `docker`;
- `host_systemd`.

Service restart/deploy по умолчанию запрещен.

`package_hygiene` фиксирует обязательные проверки перед будущим package gate:

- toolchain check;
- full pytest;
- git diff check;
- source zip checksum;
- forbidden source entries;
- shell LF/no-BOM;
- markdown hygiene;
- commit binding.

Уже VPS-smoked evidence packages нельзя перепаковывать или переписывать этим
slice. Новый package build/apply остается отдельным named gate.

## Current-Head Package Preflight

`current_head_package_preflight` фиксирует только local-only planning для
текущего AMN2 head:

```text
target_head=b121865
latest_vps_smoked_head=b121865
package_build_allowed_by_default=false
live_apply_allowed_by_default=false
live_smoke_allowed_by_default=false
```

Required checks before any future package/live gate:

- toolchain check;
- full pytest;
- git diff check;
- source zip checksum plan;
- forbidden source entries plan;
- shell LF/no-BOM plan;
- markdown hygiene;
- commit binding;
- named live gate checklist;
- asset path preflight.

Live apply/smoke для `b121865` требует отдельной `P7-C001` named gate phrase.
Этот preflight planning сам не строит пакет, не загружает пакет на VPS, не
перезапускает сервисы и не меняет known-good package evidence. `0de7a77`
остается предыдущим known-good baseline для history/rollback comparison.

Asset path preflight checks that required operator-kit files exist, generated
runbook paths resolve, package manifest paths match the archive, source zip
paths match the manifest and no secret material appears in the asset manifest.
It also verifies that package-local helper defaults match the package commit
and source checksum. It is `package/preflight only`; it does not build, upload
or apply a package.

## Clean Installer RC Acceptance

`clean_installer_rc_acceptance` is a local-only checklist for Phase 7 RC
readiness. It requires evidence for:

- rendered plan without secrets;
- package and source SHA256;
- operator runbook path verification;
- helper default bindings;
- known-good `0de7a77` baseline preservation;
- rollback and stop-line review.

It does not authorize live apply. The separate `P7-C001` named gate already
closed as live-smoke pass for `b121865`; future package/live changes still
require their own named gate.

## Public/Config/Write Prerequisite Split

`public_config_write_prerequisite_split` фиксирует результат Phase 7 preflight:
combined gate `P7-C002 + P7-C003 + P7-C005` нельзя повторять как один live
enablement step. Статус: `blocked_by_preconditions`.

Source evidence:

```text
research/amn2/phase-7-public-config-write-preflight-b121865-2026-06-14.md
```

Readiness tracks:

- `P7-C002` public exposure readiness: admin credential contract,
  domain/TLS/reverse proxy plan, firewall/listener plan, public probe matrix
  and rollback to loopback;
- `P7-C003` config delivery channel readiness: SMTP or operator-local channel,
  secret-safe evidence protocol, client import matrix, one-time delivery policy
  and delivery revocation story;
- `P7-C005` write API scope decision: keep public API read-only for RC, add a
  separate write API implementation slice, or use an operator-only web write
  window.

Blocked actions remain:

- public listener change;
- domain/TLS/reverse proxy apply;
- config artifact output;
- write API route enablement;
- `VPS_APPLY_ENABLED=true`;
- Local Agent mutation;
- live peer/user mutation.

## Config Delivery Channel Readiness

`config_delivery_channel_readiness` выделяет `P7-C003` из combined
public/config/write preflight в отдельный local-only checklist. Статус:
`readiness_design_ready`. Он не создает конфиги, не отправляет email, не
публикует ссылки и не генерирует QR для delivery.

Required checklists:

- `delivery-channel-decision`: выбрать только один разрешенный канал -
  `smtp_email` или `operator_local`;
- `secret-safe-evidence-protocol`: evidence может фиксировать только safe
  status/count/audit summary. Wizard manifest хранит forbidden evidence names,
  а rendered plan и `/api/integration/status` показывают только count/policy,
  чтобы не повторять secret-bearing marker vocabulary в публичном статусе;
- `client-import-matrix`: до apply должны быть описаны `conf_file`,
  `vpn_import_link` и `qr_vpn_import_link` как совместимые артефакты;
- `one-time-delivery-policy`: delivery должен быть single-use, short-TTL,
  purpose-bound и audit-redacted;
- `delivery-revocation-story`: нужен rollback path для отключения delivery
  channel, expire/revoke delivery token и safe revocation summary.

Blocked actions:

- config artifact output;
- SMTP send;
- Telegram config send;
- public config link issue/redeem;
- QR generation for delivery.

## Write API Scope Decision

`write_api_scope_decision` выделяет `P7-C005` из combined public/config/write
preflight в отдельный local-only decision. Статус: `decision_ready`.

Selected RC policy:

```text
keep_public_api_read_only_for_rc
```

Это значит:

- write API remains disabled;
- public write routes are not allowed;
- Local Agent mutation remains disabled;
- production peer/user mutation remains disabled;
- any future apply requires `P7-C005 write API / install mutation gate`.

Decision options:

- `keep-public-api-read-only-for-rc`: selected for RC;
- `separate-write-api-implementation-slice`: deferred, requires `P7-C005`;
- `operator-only-web-write-window`: deferred, requires `P7-C005`.

Before any future write path, the operator must have:

- route inventory still zero or explicitly scoped;
- auth scope model for write;
- idempotency and audit contract;
- rollback or compensating action story;
- operator confirmation boundary;
- safe evidence without secret or peer material.

Blocked actions remain:

- write API route enablement;
- `/api/clients` CRUD;
- install mutation route;
- Local Agent mutation;
- `VPS_APPLY_ENABLED=true`;
- production peer/user mutation;
- server config rewrite.

## Backup/Restore/Import Readiness

`backup_restore_import_readiness` выделяет `P7-C006` в отдельный local-only
checklist. Статус: `readiness_checklist_ready`. Он не создает backup archive,
не применяет restore, не импортирует archive и не выполняет reboot.

Required checklists:

- `backup-scope-decision`: source state scope, artifact inventory и operator
  retention choice должны быть объявлены до любого backup gate;
- `encryption-and-retention-policy`: backup artifacts должны быть encrypted at
  rest, secret handoff остается operator-local, retention window объявлен,
  evidence остается safe-only;
- `restore-preview-safety`: допускается только restore preview; target
  isolation и no-overwrite stop-line обязательны;
- `import-source-validation`: source integrity, schema version, operator
  ownership and safe manifest checks required before any import;
- `disaster-recovery-drill-plan`: drill scope, rollback stop-line и post-drill
  relock check должны быть заранее описаны.

Blocked actions remain:

- backup archive create;
- restore apply;
- archive import apply;
- reboot;
- destructive migration;
- remote backup download.

## Telegram Identity/Profile/Media Readiness

`telegram_identity_readiness` выделяет `P7-C007` в отдельный local-only
checklist. Статус: `readiness_checklist_ready`. Он не использует Telegram
token, не отправляет live bot messages, не меняет profile name/description,
не загружает profile photo и не делает media upload.

Required checklists:

- `telegram-identity-scope-decision`: bot identity target, allowed profile
  fields and operator approval window должны быть объявлены до apply;
- `credential-handoff-and-storage-policy`: credential handoff остается
  operator-local, evidence/rendered plan не содержат token value, rotation
  story должен быть готов заранее;
- `profile-media-asset-plan`: display name, description и media asset
  reference должны быть описаны без live upload;
- `operator-preview-and-rollback`: preview-only before/after summary и rollback
  story обязательны;
- `post-mutation-relock-audit`: после будущего gate нужен relock, safe audit
  summary и подтверждение, что live send не требуется.

Blocked actions remain:

- Telegram token use;
- live bot send;
- profile name mutation;
- profile description mutation;
- profile photo mutation;
- media upload.

## Public Exposure Readiness Design

`public_exposure_readiness_design` выделяет `P7-C002` из combined
public/config/write preflight в отдельный local-only checklist. Статус:
`readiness_design_ready`. Он не открывает портов и не применяет reverse proxy.

Required checklists:

- `admin-credential-contract`: `WEB_ADMIN_USERNAME`, `WEB_ADMIN_PASSWORD_HASH`
  и `APP_SECRET_KEY` должны быть present; evidence может содержать только
  presence/boolean flags, без raw values или hash values;
- `domain-tls-reverse-proxy-plan`: до apply нужны `domain_name`, `tls_mode` и
  `reverse_proxy_kind`; allowed backend target только `127.0.0.1:3030`;
- `firewall-listener-plan`: backend остается `127.0.0.1:3030`, direct
  `0.0.0.0:3030` и `0.0.0.0:3040` запрещены;
- `external-probe-matrix`: до apply внешние `3030` и `3040` должны быть closed;
  после apply `3030`/`3040` тоже остаются closed, а `80`/`443` проверяются как
  proxy/redirect/auth challenge;
- `rollback-to-loopback`: rollback goal всегда `web_loopback_only`.

Blocked actions:

- public listener change;
- firewall apply;
- reverse proxy apply;
- TLS certificate issue;
- public OpenAPI publication;
- direct public API `3040`.

## Multi-Instance/IPAM RC Decision

`multi_instance_ipam_rc_decision` встраивает Phase 6 model
`docs/MULTI_INSTANCE_IPAM_CONFLICT_MODEL.ru.md` в clean installer RC decisions.
Это только local planning: live multi-instance apply, runtime config write,
firewall change, peer migration, config delivery and service restart остаются
запрещены.

Required checks:

- unique runtime instance id;
- unique listen port per instance;
- non-overlapping VPN CIDR;
- unique interface name;
- endpoint pair review;
- DNS/IPv6 policy review.

Allowed outputs:

- conflict report;
- operator notes;
- blocked gate summary.

Blocked outputs:

- runtime config write;
- firewall change;
- peer migration;
- config delivery;
- service restart.

## Installer Evidence

`installer_evidence` описывает только шаблоны будущих доказательств. Он не
запускает smoke на VPS и не собирает secret-bearing payloads.

Smoke evidence template содержит только safe summary sections:

- selected commit;
- loopback HTTP codes;
- auth/scope status;
- listener summary;
- audit summary;
- external closed probe status;
- forbidden marker result;
- final verdict.

Existing-server reconciliation input остается `report_only`. Разрешенные input:

- server inventory summary;
- read-only peer counts;
- runtime mode observation;
- operator notes.

Запрещенные outputs:

- auto-fix;
- peer import;
- config overwrite;
- peer creation;
- peer removal.

Операторский индекс: `docs/FRESH_INSTALLER_OPERATOR_INDEX.ru.md`.

## Разрешенные Локальные Шаги

Wizard may recommend only local/dry-run steps such as:

```text
python -m app.toolchain check
python -m app.cli install plan --answers fresh-install-answers.json --pretty
python -m app.cli server retest-plan --config servers.yml --server local --db data/amneziya.sqlite3
```

These commands are planning/preflight helpers. They do not open the destructive
cleanup gate and do not turn on live deployment.

## Следующий Gate

After current Phase 7 RC readiness work, the safe default next planning item is:

```text
exact named gate only, or a new local-only RC gate matrix consolidation proposal
```

Destructive cleanup/reinstall remains `P7-C004` and requires a separate named
destructive gate.
