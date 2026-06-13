# AMN2 Commercial And Bot Productization Boundary

Дата: 2026-06-13.

Статус: Phase 6 local-only policy boundary for `P6-I003 + P6-I004`.

Этот документ фиксирует productization boundary для коммерческого доступа и
будущего разделения access/support/news bot. Он не включает payment processor,
public launch, config delivery, write API, live VPS work or Telegram identity
mutation.

## Safety Boundary

По умолчанию остается закрыто:

- payment processor integration: no;
- payment webhook/callback route: no;
- automatic entitlement after payment: no;
- config delivery after payment: no;
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

## Follow-up Candidates

Candidate for the Phase 6 plan if commercial access proceeds:

- `P6-I006` Commercial entitlement/audit boundary: define entitlement records,
  safe audit fields and manual review reason codes before any payment provider
  integration.

This candidate is not active until explicitly accepted.
