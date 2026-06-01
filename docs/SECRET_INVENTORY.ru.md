# Secret inventory registry

Дата: 2026-06-01.

Статус: local-only no-route contract.

Этот slice добавляет только машинно-проверяемый registry secret-bearing surfaces. Он не читает `.env`, не подключается к БД, не добавляет `/api/*`, web-route, Local Agent route, backup export, restore apply, import apply или live VPS calls.

## Что фиксирует registry

`app.security.secret_inventory` описывает для каждого источника:

- `inventory_id`;
- `source_ref`;
- secret class;
- storage surface;
- default backup policy;
- default restore policy;
- route exposure boundary;
- redaction requirement;
- запрет raw value в safe metadata.

Registry покрывает:

- environment/config secrets: `APP_SECRET_KEY`, `TELEGRAM_BOT_TOKEN`, `VPS_SSH_PASSWORD`, SMTP credentials, web session secret;
- credential hashes: web admin password hash;
- token hashes: Local Agent, API tokens, config share tokens, email recovery tokens;
- client config secrets: encrypted peer private key, encrypted PSK, `.conf`, QR payload/PNG, `vpn://`;
- remote operation output and audit metadata;
- topology-sensitive runtime metadata.

## Правила

- Safe manifest содержит только policy metadata, не значения секретов.
- Token hashes не становятся active после redacted restore.
- Generated config artifacts исключаются из backup metadata and regenerate on restore.
- Client config secrets remain blocked from route exposure.
- Remote operation output and audit metadata are internal-only and must be redacted before display/export.

## Связь с backup/import

`tests/security/test_secret_inventory.py` проверяет, что `app.backup.policy.secret_field_sources()` покрыты registry. Это удерживает backup/import policy и общий secret inventory в одной модели перед будущими route/API decisions.

## VPS gate

VPS gate для этого slice не нужен: он не меняет peer apply/revoke/config delivery/sync/runtime behavior и не работает с live state.
