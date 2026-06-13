# AMN2 Fresh Install Wizard Boundary

Дата: 2026-06-13.

Статус: Phase 6 local-only `P6-I007`.

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
- answer schema: `fresh-install-answers.v1`.

`build_fresh_install_manifest()` возвращает machine-readable manifest с
описанием questions, defaults, allowed values и gated fields. Manifest также
указывает secret handoff policy: `docs/AMN2_SECRET_HANDOFF_PROTOCOL.ru.md`.

## Вопросы

Wizard собирает только безопасные operational choices:

- project name;
- server name;
- runtime: `docker` or `host_systemd`;
- VPN protocol: `amneziawg`, `wireguard` or `xray`;
- whether public exposure is wanted;
- whether real config delivery is wanted;
- whether production write API is wanted;
- whether destructive cleanup/reinstall is wanted;
- Telegram bot credential mode;
- secret handoff mode.

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

- `P6-C001 required before public exposure`;
- `P6-C002 required before config delivery`;
- `P6-C003 required before write API`;
- `P6-C007 required before destructive cleanup/reinstall`.

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

Secret handoff mode по умолчанию: `operator_local`. Это значит, что wizard
может создать только checklist для оператора, но не хранит и не печатает raw
secret values. Подробный протокол: `docs/AMN2_SECRET_HANDOFF_PROTOCOL.ru.md`.

## Rendered Plan

`build_fresh_install_plan()` возвращает не только raw operator inputs, но и
`rendered_plan`:

- `local-preflight` - только локальные проверки;
- `secret-handoff-checklist` - checklist без raw secrets;
- `question-answer-render` - привязка к answer schema;
- `named-gate-stop` - финальная остановка перед любым gated action.

Если в ответах есть `yes` для public exposure, config delivery, write API или
destructive cleanup, `rendered_plan.requires_named_gates` перечисляет нужные
gate IDs и статус становится `blocked_named_gate_required`.

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

After `P6-I007`, the safe default next planning item is:

```text
P6-N001 Public docs/API taxonomy if public docs are approved
```

Destructive cleanup/reinstall remains `P6-C007` and requires a separate named
destructive gate.
