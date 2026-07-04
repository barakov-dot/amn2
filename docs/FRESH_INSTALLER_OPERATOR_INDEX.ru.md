# AMN2 Fresh Installer Operator Index

Дата: 2026-06-14.

Статус: Phase 7 local-only RC docs index.

Этот индекс собирает документы, которые нужны оператору перед будущим clean
install path. Он не разрешает live VPS commands, SSH, package apply, service
restart/deploy, public exposure, config delivery, write API, Local Agent
mutation, backup/import/reboot, production peer/user mutation, destructive
cleanup or Telegram identity mutation.

## Core Docs

- `docs/FRESH_INSTALL_WIZARD.ru.md` - question/answer wizard, rendered plan,
  readiness, RC acceptance, public/config/write prerequisite split, public
  exposure readiness design, config delivery channel readiness, write API scope
  decision, backup/restore/import readiness, Telegram identity/profile/media
  readiness and evidence template boundary.
- `docs/AMN2_SECRET_HANDOFF_PROTOCOL.ru.md` - operator-local secret handoff
  rules without raw secret output.
- `docs/MULTI_INSTANCE_IPAM_CONFLICT_MODEL.ru.md` - local-only модель
  конфликтов runtime instance, listen port, VPN CIDR, interface, endpoint и
  DNS/IPv6 для clean installer RC decisions.
- `docs/RELEASE_NOTES_RC_SKELETON.ru.md` - черновик release notes для будущего
  RC; не объявляет public release.
- `docs/DESTRUCTIVE_CLEANUP_GATE_CHECKLIST.ru.md` - destructive cleanup gate
  checklist; execution remains blocked without named gate.
- `docs/RECONCILIATION_RELEASE_CHECKLIST.ru.md` - report-only
  attach-existing-server and release checklist boundary.
- `docs/RUNTIME_TOOLCHAIN.ru.md` - supported CPython 3.12 runtime and local
  test wrapper.

## Local-Only Flow

1. Collect fresh install answers.
2. Render the local dry-run plan.
3. Review target preflight matrix without executing live diagnostics.
4. Review runtime mode decision without service restart.
5. Review package hygiene checklist without rebuilding an already-smoked
   package.
6. Review current-head package preflight for `b121865`; `b121865` is the
   current known-good VPS-smoked baseline and `0de7a77` remains previous
   history/rollback evidence.
7. Verify operator-kit paths, source/package SHA files and package-local helper
   defaults before any future live gate.
8. Review clean installer RC acceptance checklist: answers, target preflight,
   package preflight, smoke evidence, secret handoff, rollback and stop-lines.
9. Review multi-instance/IPAM RC decisions without runtime config write,
   firewall change, peer migration, config delivery or service restart.
10. Review public/config/write prerequisite split before retrying any combined
    `P7-C002 + P7-C003 + P7-C005` gate.
11. Review public exposure readiness design before any `P7-C002` named gate:
    admin credential contract, domain/TLS/reverse proxy plan, firewall/listener
    plan, external probe matrix and rollback-to-loopback.
12. Review config delivery channel readiness before any `P7-C003` named gate:
    SMTP/operator-local channel decision, secret-safe evidence protocol,
    client import matrix, one-time delivery policy and delivery revocation
    story.
13. Review write API scope decision before any `P7-C005` named gate: public API
    remains read-only for RC; implementation slice and operator-only write
    window remain deferred options.
14. Review backup/restore/import readiness before any `P7-C006` named gate:
    backup scope, encryption/retention policy, restore preview safety, import
    source validation and disaster-recovery drill plan.
15. Review Telegram identity/profile/media readiness before any `P7-C007`
    named gate: identity scope, operator-local credential handoff, profile/media
    asset plan, preview/rollback and post-mutation relock audit.
16. Review API/docs taxonomy RC drift check without OpenAPI publication or new
    route exposure.
17. Prepare smoke evidence template without secret-bearing payloads.
18. Prepare existing-server reconciliation input as report-only data.

## Hard Stops

Stop and require a separate named gate before:

- SSH or live VPS diagnostics;
- package upload/apply/rebuild on VPS;
- current-head live apply/smoke without named `P7-C001`;
- service restart/deploy;
- public listener, domain, HTTPS or reverse proxy changes;
- config delivery, QR, import links or client config payloads;
- write API, Local Agent mutation or production peer/user mutation;
- backup/import/reboot;
- destructive cleanup/reinstall;
- Telegram token use, live bot send or identity/profile mutation.
