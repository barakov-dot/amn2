# AMN2 Commercial And Bot Productization Boundary

Дата: 2026-06-13.

Статус: Phase 6 local-only policy boundary for `P6-I003 + P6-I004 +
P6-C002-design + P6-I006`.

Этот документ фиксирует productization boundary для коммерческого доступа,
tokenized config link, entitlement audit и будущего разделения
access/support/news bot. Он не включает payment processor, public launch,
real config delivery, write API, live VPS work or Telegram identity mutation.

## Safety Boundary

По умолчанию остается закрыто:

- payment processor integration: no;
- payment webhook/callback route: no;
- automatic entitlement after payment: no;
- config delivery after payment: no;
- short config-link runtime: no;
- public config-link redeem route: no;
- public exposure: no;
- write API: no;
- Local Agent mutation: no;
- live VPS command, SSH command, package apply/rebuild, restart/deploy: no;
- production peer/user mutation: no;
- Telegram token use, live bot send or profile icon apply: no;
- upstream/GPL code copy: no.

`VPS_APPLY_ENABLED=false` remains the default.

## Commercial Access Boundary

Current AMN2 order flow remains manual:

- accepted current payment modes are `free_test` and `manual`;
- order status stays explicit: `manual_review`, `approved`, `fulfilled`,
  `rejected`;
- payment provider secrets are not stored by this slice;
- a successful payment must not automatically create VPN entitlement;
- a successful payment must not automatically deliver `.conf`, QR or `vpn://`;
- operator manual approval remains required before access changes.

Future payment processor work requires a separate named payment processor gate
with:

- provider choice and contract;
- webhook signature validation;
- idempotency and replay protection;
- fraud/manual review policy;
- refund/dispute handling;
- safe audit fields only;
- no raw provider secrets in logs or evidence;
- explicit separation from config delivery and peer mutation gates.

## Tokenized Config Link Boundary

`P6-C002` закрыт только как local-only design boundary. Реальная выдача
конфига, короткая ссылка, публичный redeem endpoint или отправка secret-bearing
артефакта все еще требуют отдельного named config delivery gate.

Будущая короткая ссылка должна быть именно tokenized config link:

- token material: opaque random token;
- storage: hash-at-rest only;
- raw token may be returned once only at issue time;
- purpose binding: config delivery only;
- audience binding: order + user + device;
- default TTL: 15 minutes;
- one-time use: yes;
- Telegram copy text target: short link under the one-tap copy limit, not a
  long full import link;
- no raw token, config body, QR or import link in audit logs/evidence.

Until the named gate is opened, the following stay blocked:

- issuing `/api/config-links`;
- redeeming `/c/{token}`;
- emitting config bodies, QR, `.conf`, `vpn://`, private key or preshared key
  through the new tokenized path.

## Commercial Entitlement Audit Boundary

`P6-I006` is closed as a local-only entitlement/audit model. It does not enable
a payment provider, write API or automatic access.

The future entitlement model must keep these defaults:

- payment provider enabled: no;
- entitlement write API enabled: no;
- automatic activation after payment: no;
- config delivery decoupled from payment: yes;
- manual operator review required: yes.

Allowed decision records are limited to:

- `manual_approved`;
- `manual_rejected`;
- `payment_seen_no_auto_access`;
- `operator_support_override`.

Safe audit fields:

- `entitlement_id`;
- `order_id`;
- `operator_id`;
- `decision`;
- `reason_code`;
- `created_at`.

Forbidden audit/evidence fields:

- raw payment payload;
- provider secret or payment token;
- client config body;
- VPN import link;
- QR code;
- private key or preshared key;
- Telegram ID or username.

## Support/News Bot Split

The current access bot remains the only runtime that owns access request,
approval and config delivery behavior.

Future support bot:

- requires a separate Telegram token and runtime;
- may collect support intake only after a support data-retention gate;
- must not issue configs, QR, `.conf` or `vpn://`;
- must not mutate orders, devices, peers or production users;
- must not reuse access-bot admin callbacks.

Future news bot:

- requires a separate Telegram token and runtime;
- may publish operator-written announcements only after a broadcast gate;
- must not request private VPN diagnostics;
- must not mutate user/device/account state;
- must not issue configs, QR, `.conf` or `vpn://`.

Shared negative controls:

- no access bot token reuse;
- no live Telegram send by Codex;
- no profile icon apply without `P6-I005`;
- no config artifact output;
- no production peer or user mutation.

## Telegram Profile Icon Apply Gate

`P6-I005` is closed as a local-only gate definition only.

Default allowed work:

- local image validation;
- local registry metadata;
- operator checklist drafting;
- safe evidence summary.

Blocked without a separate named Telegram identity mutation gate:

- Telegram Bot API `setMyProfilePhoto`;
- Telegram Bot API `deleteMyProfilePhoto`;
- BotFather/manual profile mutation by Codex;
- live bot send;
- Telegram token use.

Safe evidence fields are limited to:

- `bot_kind`;
- `asset_id`;
- `content_sha256`;
- `mime_type`;
- `width_px`;
- `height_px`;
- `byte_size`;
- `operator_decision`.

## Follow-up Candidates

Next practical local-only candidate:

- `P6-I007` Interactive fresh-install wizard/bootstrap automation.

Gated/deferred candidates:

- live config-link issue/redeem under `P6-C002`;
- payment provider integration under a separate named payment processor gate;
- write API and production peer/user mutation under `P6-C003`.
