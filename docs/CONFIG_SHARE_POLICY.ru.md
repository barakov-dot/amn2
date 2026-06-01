# Политика public/self-service выдачи конфигов

Дата: 2026-06-01.

Статус: local-only no-route contract.

Этот slice добавляет только policy/storage/service boundary для будущей public/self-service выдачи клиентских VPN-конфигов. Он не добавляет public download route, self-service download route, `/api/*`, API `config:read`, Local Agent `/configs`, новый QR/import behavior, live VPS calls или хранение raw config в базе.

## Что добавлено

- `app.services.config_share_tokens` - hash-only share-token lifecycle and policy decision helpers.
- `config_share_tokens` table - storage contract для future bounded public shares.
- `self.device.config_download.blocked` и `public_token.config_share_download.blocked` в `SurfacePolicy`.
- Tests for hash-only raw token handling, expiry, revoke, one-time/max-download use, resource binding, safe audit metadata and redacted backup metadata.

## Token contract

Raw share token показывается только один раз через `ConfigShareTokenIssue.raw_token`. В БД хранятся только:

- `token_hash`;
- short `token_prefix`;
- `purpose=config_share`;
- creator/owner metadata;
- bound user/device/server ids;
- allowed artifact kinds;
- target client;
- expiry/revoke/use counters.

Safe metadata не содержит raw token, token hash, `.conf`, QR payload, QR PNG/base64, `vpn://`, private key или PSK.

## Download decision

`evaluate_config_share_download()` возвращает только allow/deny decision and safe audit metadata. Она не возвращает config payload.

Allow возможен только если:

- purpose is `config_share`;
- token не expired, не revoked, не exhausted by `max_downloads`;
- owner user active;
- device active;
- server active;
- requested device bound to token;
- requested artifacts are explicitly allowed;
- target client is supported and matches token policy.

Denied public response остается generic: `Config link is invalid or expired.`

## Backup policy

Redacted backup metadata intentionally excludes token hash and marks restored share as `restore-disabled`. Redacted restore must not recreate usable public shares.

## Blocked future routes

До отдельного route gate остаются заблокированы:

- public config download;
- self-service config download;
- API `config:read`;
- Local Agent `/configs`;
- full backup/restore of active share hashes;
- route examples containing real config payloads.

VPS gate не нужен для этого slice: он не меняет peer apply/revoke/config/sync/runtime behavior.
