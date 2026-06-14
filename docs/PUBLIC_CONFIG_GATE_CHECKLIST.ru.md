# AMN2 Public Exposure And Config Delivery Gate Checklist

Дата: 2026-06-13.

Статус: Phase 6 docs-only checklist refresh for `P6-C001 + P6-C002`.

Этот документ готовит будущие решения по public exposure и config delivery,
но не открывает ни один gate.

```text
public_exposure_enabled=false
config_delivery_enabled=false
public_openapi_enabled=false
short_config_link_runtime_enabled=false
public_config_redeem_enabled=false
VPS_APPLY_ENABLED=false
```

## Scope

`P6-C001 Public exposure gate` отвечает за публикацию наружу: listener,
domain/reverse proxy, TLS, firewall, public docs/API visibility, probes,
rollback and incident handling.

`P6-C002 Config delivery gate` отвечает за выдачу secret-bearing config
artifacts: short tokenized link, redeem flow, QR, import link, `.conf`,
client config body and any bot/API surface that can deliver those artifacts.

До отдельной named gate phrase оба направления остаются closed/deferred.

## Allowed Default Work

Без открытия gates разрешены только:

- checklist drafting;
- threat model review;
- client compatibility notes;
- docs/API taxonomy review;
- local tests;
- safe evidence summary without secrets.

## P6-C001 Preconditions

Перед public exposure нужно отдельно зафиксировать:

- operator opens `P6-C001` by name;
- target environment and disposable/non-disposable status;
- domain/reverse proxy/listener plan;
- TLS certificate and renewal plan;
- firewall and allow/deny policy;
- admin authentication/session/rate-limit policy;
- public docs/OpenAPI scope;
- external probe scope;
- rollback and incident plan;
- log retention/redaction expectations.

Stop line: public exposure must not happen just because docs, taxonomy or
local tests exist.

## P6-C002 Preconditions

Перед config delivery нужно отдельно зафиксировать:

- operator opens `P6-C002` by name;
- token material is opaque random only;
- token storage is hash-at-rest only;
- raw token is returned once only at issue time;
- default TTL and one-time-use policy;
- order/user/device audience binding;
- audit fields and redaction policy;
- client import matrix for DefaultVPN, AmneziaWG iOS and AmneziaWG Android;
- revoke/expire behavior;
- support copy for failed import/handshake cases.

Stop line: config delivery must not happen just because the bot can display
copyable text or a future short-link design exists.

## Joint Negative Controls

Blocked without the correct named gate:

- public listener exposure;
- public OpenAPI publication;
- public config-link redeem endpoint;
- short config-link issue;
- QR code output;
- VPN import link output;
- client `.conf` output;
- private key or preshared key output;
- Telegram live config send;
- Local Agent config mutation;
- production peer/user mutation.

## Safe Evidence Fields

Evidence may include only:

- gate id;
- decision;
- operator;
- timestamp;
- approved scope;
- stop conditions;
- redacted test result summary.

Evidence must not include raw token, import link, QR, config body, private key,
preshared key, server secret, Telegram token, Telegram ID or username.

## Phase 6 Result

This checklist refresh closes the local-only planning item. It does not update
VPS, rebuild packages, restart services, publish public docs/API or deliver
configs.
