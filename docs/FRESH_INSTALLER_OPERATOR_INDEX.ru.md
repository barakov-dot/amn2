# AMN2 Fresh Installer Operator Index

Дата: 2026-06-13.

Статус: local-only docs index.

Этот индекс собирает документы, которые нужны оператору перед будущим clean
install path. Он не разрешает live VPS commands, SSH, package apply, service
restart/deploy, public exposure, config delivery, write API, Local Agent
mutation, backup/import/reboot, production peer/user mutation, destructive
cleanup or Telegram identity mutation.

## Core Docs

- `docs/FRESH_INSTALL_WIZARD.ru.md` - question/answer wizard, rendered plan,
  readiness and evidence template boundary.
- `docs/AMN2_SECRET_HANDOFF_PROTOCOL.ru.md` - operator-local secret handoff
  rules without raw secret output.
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
6. Prepare smoke evidence template without secret-bearing payloads.
7. Prepare existing-server reconciliation input as report-only data.

## Hard Stops

Stop and require a separate named gate before:

- SSH or live VPS diagnostics;
- package upload/apply/rebuild on VPS;
- service restart/deploy;
- public listener, domain, HTTPS or reverse proxy changes;
- config delivery, QR, import links or client config payloads;
- write API, Local Agent mutation or production peer/user mutation;
- backup/import/reboot;
- destructive cleanup/reinstall;
- Telegram token use, live bot send or identity/profile mutation.
