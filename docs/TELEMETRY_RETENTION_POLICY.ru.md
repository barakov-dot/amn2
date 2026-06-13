# Telemetry retention and upstream refresh policy

Документ фиксирует Phase 6 границу для `P6-N004` и `P6-S002`.
Это local-only planning/security/productization slice: агрегаты можно хранить и
обсуждать, raw telemetry и upstream refresh actions остаются ограничены.

## Retention

- Raw stored snapshots are short lived: default retention is 7 days.
- Aggregate summaries may be retained for 180 days.
- Raw export is disabled by default.
- Allowed aggregate keys: status counts, daily traffic totals and health age
  buckets.

## Redaction

Before telemetry leaves local/admin context, redaction must remove identity
fields, peer key material, endpoint values, client config artifacts, command
output and raw tokens.

The default policy is aggregate-only. Identity fields and secret material are not
allowed in retained aggregate reports.

## Upstream refresh

Weekly upstream refresh jobs may create candidate rows and evidence notes only.
Default action is `candidate rows`.

Every upstream refresh incorporation must pass:

- license boundary review;
- security delta review;
- local tests;
- evidence update.

No upstream refresh may trigger live actions, public exposure, config delivery,
write API enablement, Local Agent mutation, production peer/user mutation or code
copy from incompatible upstream licenses.
