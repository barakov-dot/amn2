# Runtime Registry

This document records the runtime dependencies for Amneziya, where they live in the repository, and how to verify a VPS before another production test.

## Stored In Git

The repository stores lightweight, auditable artifacts only:

- `deploy/runtime/manifest.yml` - runtime requirement manifest;
- `deploy/runtime/check_vps.sh` - read-only VPS checker;
- `deploy/runtime/collect_debug_snapshot.sh` - read-only debug snapshot collector;
- `deploy/examples/servers.host_systemd.example.yml` - host/systemd server config example;
- `deploy/examples/servers.docker.example.yml` - Docker server config example;
- `deploy/examples/.env.production.example` - production `.env` template without real secrets;
- `deploy/examples/nginx-proxy-manager-notes.ru.md` - reverse proxy notes for the web panel.

## SSH Auth

Recommended mode for live health checks and future apply/revoke operations is SSH key auth:

```yaml
ssh:
  auth:
    type: key
    private_key_path: /root/.ssh/id_ed25519
```

Password auth is also supported, but it requires `sshpass` on the server running the bot/web panel:

```bash
sudo apt-get update
sudo apt-get install -y sshpass
```

In `servers.yml`:

```yaml
ssh:
  auth:
    type: password
```

In `.env`:

```env
VPS_SSH_PASSWORD=CHANGE_ME_REAL_SSH_PASSWORD
```

The password is passed to `sshpass` through `SSHPASS`, not through command-line arguments. If `VPS_SSH_PASSWORD` is not set or `sshpass` is missing, live health checks fail with an explicit local error before remote commands run.

## Not Stored In Git

Do not store real `.env`, `servers.yml`, SSH private keys, bot tokens, `APP_SECRET_KEY`, SQLite databases, backup archives, generated client configs, QR images, Docker images, virtual environments, `node_modules`, or logs with private data.

### Secret-bearing delivery artifacts

`.conf`, QR payload/PNG, and `vpn://` import links are `client-config-secret` artifacts.
They must not be included in runtime diagnostics, plain backups, audit metadata, logs, or error output.
If such an artifact reaches text diagnostic output, it must pass through `app.security.redaction.redact()`.

If heavy artifacts are needed later, put them in GitHub Releases or separate storage. Keep only URL, version, and checksum in the repository.

## Quick VPS Check

Docker peer apply/revoke requires `runtime.config_path` in `servers.yml`. The app rewrites that persistent config inside the container and then runs `docker restart <container_name>`. Traffic collection and `sync-peers` are read-only and use `awg show <interface> dump`.

Host/systemd runtime:

```bash
cd /opt/amn2
bash deploy/runtime/check_vps.sh
```

Docker runtime:

```bash
cd /opt/amn2
AMN_RUNTIME=docker AMN_CONTAINER_NAME=amnezia-awg AMN_INTERFACE=awg0 bash deploy/runtime/check_vps.sh
```

## First `RemoteOperationRunner` Slice

Server health checks use the first `RemoteOperationRunner` slice:

- risk class: `read-only-remote`;
- command policy: existing read-only allowlist;
- remote side effects: none;
- local side effects: health snapshot and admin audit event when launched from web;
- consistency status: `read-only`.

This slice does not enable peer apply/revoke, Docker config writes, firewall changes, or destructive operations.

## Local Gate For State-Changing Remote Operations

Before any live VPS apply/revoke, state-changing operations must pass a local gate:

- `remote-state-write` and `destructive-remote` operations describe `operation_id`, `risk_class`, `consistency_status`, `local_side_effects`, `remote_side_effects`, `rollback_note`, and `idempotency_key`;
- `RemoteOperationRunner.plan()` returns a `consistency_status=dry-run` preview for state-changing operations without executing SSH;
- `OperationPlan.to_safe_metadata()` does not publish command strings, and redacts `audit_summary`, `rollback_note`, and idempotency metadata;
- `apply-peer` and `revoke-peer` dry-run previews show operation ID, risk class, side effects, and rollback note without exposing PSK, private keys, `.conf`, or `vpn://`;
- the real VPS gate starts only after focused tests and the full local `pytest tests -v` suite pass.

This gate does not replace live verification. It makes live verification narrow, repeatable, and backed by rollback/recovery context before a real server is touched.

The script does not install packages, change firewall rules, restart services, or write files. It only reads VPS state and exits with code `1` when critical errors are found.

## Debug Snapshot

When a full VPS report is needed:

```bash
cd /opt/amn2
bash deploy/runtime/collect_debug_snapshot.sh
```

For Docker runtime:

```bash
cd /opt/amn2
AMN_RUNTIME=docker AMN_CONTAINER_NAME=amnezia-awg AMN_INTERFACE=awg0 bash deploy/runtime/collect_debug_snapshot.sh
```

The detailed command list and redaction rules are documented in `docs/VPS_LOG_COLLECTION.ru.md`.
