# Route/Auth/Operation Policy

Дата: 2026-05-31.

Этот документ фиксирует первый безопасный API-readiness slice после verified live VPS baseline.

## Статус

`app/security/surface_policy.py` является inventory-only policy registry. Он не включает новые endpoints и не меняет runtime behavior.

## Правило для следующих изменений

Новый route, bot action, CLI command или remote operation не добавляется в production без policy entry, где указаны:

- actor;
- auth method;
- risk class;
- secret class;
- side effects;
- gates;
- audit decision;
- operation contract;
- live retest trigger;
- test references.

## Запреты первого slice

- Не включать `GET /agent/clients`.
- Не добавлять runtime config/self-service API.
- Не добавлять `/api/*` routes поверх scoped tokens до storage/auth/local tests.
- Не выдавать `config:read` или write scopes в первом API-token slice.
- Не добавлять backup, restore, reboot или generic write API.
- Не трогать live VPS.
- Не копировать upstream code.

## Self-service separation boundary

`P6-I002` добавляет только policy inventory для будущего user self-service surface.
Runtime routes не смонтированы, public exposure не открыт, config delivery не открыт и write/live gates не открыты.

Future self-service routes зарезервированы только как `blocked-future` entries:

- `GET /self-service` - будущий own-account dashboard, отдельный auth от web-admin;
- `POST /self-service/devices/{device_id}/config` - future secret-bearing config delivery, требует `P6-C001` и `P6-C002`;
- `POST /self-service/devices/{device_id}/revoke` - future production mutation, требует `P6-C001` и `P6-C003`.

Self-service surface не использует `web-admin` actor/auth и не переиспользует текущие admin session routes. До отдельного named gate `/self-service*` должен оставаться только policy inventory, без FastAPI route binding.

## Live Retest Rule

Новый live retest нужен, если меняется хотя бы одна из областей:

- peer apply/revoke;
- config template/defaults;
- IP allocation;
- peer sync classification;
- disable/enable/delete device flows;
- Docker runtime write/restart behavior.

Policy-only changes and tests do not require live VPS retest.

## Implemented read-only API routes

- `GET /api/servers` - `server:read`;
- `GET /api/servers/{server_name}/summary` - `server:read`;
- `GET /api/integration/status` - `server:read`;
- `GET /api/local-agent/runtime/summary` - `server:read`, controller-safe Local Agent runtime readiness, no Local Agent network call;
- `GET /api/metrics/summary` - `metrics:read`;
- `GET /api/users/summary` - `metrics:read`.

The next read-only API smoke for a head that includes this section should use `python -m app.cli api smoke-cycle` and report `checked_routes: 6`. This still does not enable `config:read`, write scopes, Local Agent mutations or public exposure.
