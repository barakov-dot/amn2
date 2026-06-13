# Scoped API Token Policy

Дата: 2026-06-01.

Этот документ фиксирует scoped API token contract и первый подключенный read-only route shell. Slice добавляет только aggregate `/api/*` endpoints, не меняет web/bot/agent runtime behavior и не трогает live VPS.

## First-slice contract

Разрешенные scopes первого slice:

- `server:read`;
- `metrics:read`.

Запрещено в первом slice:

- `config:read` - это future `secret-read` surface для `.conf`, QR и `vpn://`;
- любые `*:write`;
- destructive/remote-exec scopes;
- shared broad API key без scopes;
- хранение raw token в базе, audit metadata или logs.

## Storage

Таблица `api_tokens` хранит:

- `id` - стабильный token id для audit/revoke;
- `name` - operator label;
- `owner_user_id` и `owner_label`;
- `token_hash` - только `sha256:<digest>`, без raw token;
- `scopes_json` - отсортированный список scopes;
- `expires_at`;
- `revoked_at`;
- `last_used_at`;
- `created_at`.

Raw token возвращается только в момент выдачи через `ApiTokenIssue.raw_token`. Safe metadata содержит `raw_token_display=one-time` и не содержит raw token или token hash.

## Auth

`app.services.api_tokens.authenticate_api_token()` принимает raw bearer token, считает hash, проверяет:

- token exists;
- token not revoked;
- token not expired;
- required scope is present.
- если token привязан к `owner_user_id`, текущий owner status должен оставаться `active`.

Safe audit metadata содержит только `token_id`, `name`, `owner_label` и scopes.

## Lifecycle gate

Второй local-only slice добавляет lifecycle boundary до подключения токенов к маршрутам:

- `create_route_api_token()` требует явный `expires_at` для route-connected токенов;
- production policy задается машинно-проверяемым manifest `build_api_token_production_policy()`;
- route-connected token TTL ограничен `API_TOKEN_PRODUCTION_MAX_TTL_DAYS=30`;
- рекомендуемый rotation notice для операторских процедур: `API_TOKEN_PRODUCTION_ROTATION_NOTICE_DAYS=7`;
- `revoke_api_token()` возвращает idempotent safe event: повторный revoke не раскрывает, существовал ли usable token;
- `rotate_api_token()` использует create-new-then-revoke-old: новый token получает отдельный id и raw token показывается только один раз;
- `rotated_from_token_id` хранит lineage без raw token и без token hash в safe metadata;
- `revoke_reason` хранит причину отзыва без удаления audit history;
- user-owned token наследует статус владельца: `blocked`/`deleted` owner не проходит auth.

Safe lifecycle metadata не содержит raw token, Authorization header, token hash, `.conf`, QR payload, `vpn://`, private key, PSK или remote command output.

Production policy manifest фиксирует:

- allowed scopes: `server:read`, `metrics:read`;
- blocked production scopes: `config:read`, `server:write`, `clients:write`, `local-agent:write`, `backup:read`, `backup:restore`;
- raw token display: one-time;
- stored secret material: только `sha256` digest;
- safe backup/export behavior: credential digest исключается из safe exports;
- audit metadata: только safe metadata.

Route-connected токены для VPS smoke предпочтительно проверяются через safe CLI cycle:

```bash
python -m app.cli api smoke-cycle --db data/amneziya.sqlite3 --base-url http://127.0.0.1:3040 --server-name debian-vps-1 --name vps-smoke --owner-label ops --expires-at "$(date -u -d '+7 days' '+%Y-%m-%dT%H:%M:%S+00:00')" --pretty
```

`smoke-cycle` внутри выпускает token со scopes `server:read` и `metrics:read`, использует его только для loopback smoke-check и отзывает token после проверки. Raw token не печатается. Если оператор использует ручные `api token issue` / `api smoke-check`, raw token показывается только в выводе `issue`, в базе хранится только `sha256:<digest>`, а revoke обязателен после проверки.

## Connected read-only route shell

Первый route-connected slice разрешает только aggregate read-only endpoints:

- `GET /api/servers` - требует `server:read`;
- `GET /api/servers/{server_name}/summary` - требует `server:read`;
- `GET /api/integration/status` - требует `server:read`;
- `GET /api/local-agent/runtime/summary` - требует `server:read`;
- `GET /api/metrics/summary` - требует `metrics:read`;
- `GET /api/users/summary` - требует `metrics:read`.

Маршруты возвращают только безопасные summary/count fields: server name/status/runtime, device counters, latest health readiness, user/order aggregates, integration gate state, Local Agent controller-safe runtime readiness и aggregate metrics. Ответы не содержат Telegram ID, username, email, SSH host/port, endpoint host, Local Agent host/port/token id/token hash, container name, interface, public/private keys, PSK, token hash, `.conf`, QR или `vpn://`.

`server:read` не дает доступ к metrics/users endpoints, а `metrics:read` не дает доступ к server endpoints. Любой bearer token без нужного scope получает отказ без раскрытия raw token или token hash.

Каждый successful read пишет `api_read` audit event с safe metadata: method, route template, scope, token id/name и owner label. Audit metadata не содержит raw token, Authorization header, token hash или response body.

Этот shell не выполняет remote operations: нет peer apply/revoke/sync, backup/import/reboot, Docker restart, SSH command execution или выдачи secret-bearing config artifacts.

## VPS Gate

VPS gate не нужен для этого route shell: нет live write flow, нет peer apply/revoke/config/sync/runtime changes и нет secret-bearing config reads.

VPS gate понадобится только когда API начнет вызывать real remote operations или читать/выдавать live secret-bearing config artifacts.
