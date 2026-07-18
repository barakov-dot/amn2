# POST-RELEASE-API-001: current-overlay transient loopback acceptance design

Date: 2026-07-18.

Status: `design-approved|written-spec-pending-review`.

Design approval:

```text
APPROVE_API_001_DESIGN
```

The approval permits writing and committing this bilingual design. It does
not authorize SSH, live preflight, a VPS API listener, or any production
action. The written specification requires a separate review before TDD
planning and implementation begin.

## 1. Baseline and purpose

```text
amn2_branch=codex-vps-test-prep
production_overlay=0b858c5cdbc5b565cc265966a2edfe2d339d65e0
phase11_release=completed-controlled-private-release
api_code_delta_0b858c5_to_current=none
production_api_3040_listener=absent_by_default
public_write_config_peer_self_service=closed
```

Overlay `0b858c5` already contains scoped bearer-token storage and auth,
TTL/revoke/rotate lifecycle, safe audit metadata, six aggregate read-only API
routes, the CLI smoke cycle, and a loopback-only bind contract. The Phase 11
combined rollout intentionally excluded API smoke. This slice therefore adds
no routes or scopes. It creates a reproducible acceptance gate for the
existing private API lane on the current production source overlay.

## 2. Selected approach

The executor creates a private, consistent SQLite clone from a read-only
production source connection, starts the existing API temporarily on
`127.0.0.1:3040` against the clone, runs the existing scoped-token smoke cycle,
stops the process, removes all private state, and re-audits production
invariants.

This is preferred over running against the production database because issue,
use, revoke, and audit changes remain clone-only. A documentation-only closeout
was rejected because older smoke receipts do not prove `0b858c5` acceptance.

The result accepts the private API lane. It does not create a persistent API
service, public listener, or new integration consumer.

## 3. Components and modes

A checksum-bound Bash executor is streamed as exact bytes through `bash -s`
and supports:

```text
preflight
run
```

`preflight` is read-only and creates no clone, token, listener, or receipt.
`run` requires a separate literal approval validated by a PowerShell runner
before SSH.

The runner must use the absolute trusted Windows OpenSSH path, a dedicated
AMN2 key, and a one-target known-host binding. It hashes the same remote bytes
that it sends, accepts no shell fragment or arbitrary command, redacts the
target, and creates a single-use local approval receipt only for `run`.

## 4. Fail-closed preflight

Both modes require:

1. Exact `0b858c5` overlay marker and exact SHA-256 values for the CLI, API
   app, settings, schema, repositories, token service, and smoke validator.
2. Regular non-symlink `.env` and production database files.
3. `VPS_APPLY_ENABLED=false` and
   `OPERATOR_DEVICE_CREATE_ENABLED=false`.
4. Production SQLite integrity `ok` and zero foreign-key violations.
5. Active/enabled healthy single-instance bot with a valid restart snapshot.
6. Active/enabled web, successful loopback HTTP checks, and loopback-only
   port `3030`.
7. No listener on port `3040` before the run.
8. A running AWG container/interface and readable container ID, restart,
   peer-set, and configuration-hash snapshots.
9. Required fixed tools and enough private disk space.

Any mismatch rejects the gate without remediation.

## 5. Clone and transient runtime contract

`run` creates a root-owned `0700` state directory and a root-owned `0600`
clone below a fixed base path. Names derive only from a bounded run ID.

The clone is built with the Python SQLite backup API from a `mode=ro` source.
The executor must not call `initialize_schema`, migrate production, or pass the
production database path to token lifecycle or API-server commands. Clone
integrity and foreign keys are checked after backup. Production `api_tokens`
and API-related `admin_actions` fingerprints must be identical before and
after the run.

The API runs in its own process group with the clone database, both write
gates false, and the exact IPv4 loopback bind `127.0.0.1:3040`. The cleanup
trap is armed before process start. An independent watchdog bounds the entire
run to 180 seconds. Wildcard, public-interface, persistent systemd, firewall,
and reverse-proxy changes are prohibited.

Success and failure both stop the process group, prove that port `3040` and
the process are absent, destroy token-bearing transient state, remove the
clone, and remove the state directory. Cleanup failure returns one redacted
`gate_rejected`; it never triggers a blind database restore.

## 6. Auth and smoke acceptance

The existing `python -m app.cli api smoke-cycle` runs against the clone and
`http://127.0.0.1:3040` with a TTL of at most seven days.

Acceptance proves:

- missing and invalid bearer credentials return `401` without echo;
- `server:read` cannot access metrics routes and `metrics:read` cannot access
  server routes (`403`);
- the combined scoped token passes exactly six expected GET routes;
- response validation finds no forbidden secret or personal markers;
- one clone-only token lifecycle is issued, used, and revoked;
- six expected safe `api_read` rows exist in the clone;
- no new clone `api_write` row exists;
- raw token, Authorization header, and token hash never enter stdout, stderr,
  evidence, or a persistent file.

No POST route is exercised.

## 7. Independent postflight

After mandatory cleanup, the executor rechecks:

- no port `3040` listener or API process;
- unchanged active/enabled web and bot health/restart invariants;
- production database integrity, foreign keys, and API-related fingerprints;
- unchanged AWG container ID, restart count, peer set, and configuration
  hashes;
- absence of clone, PID, output, and state paths;
- closed public/write/config/peer/self-service gates.

An invariant mismatch is reported immediately without blind remediation. AWG
must never be stopped, restarted, reconfigured, or used for a test operation.

## 8. Separate live authority

Design, written-spec, plan, and implementation approvals do not authorize a
live preflight or run. After local tests, complete diff/security review,
commits, pushes, and exact origin readback, the final runner emits this
checksum-bound form:

```text
APPROVE POST_RELEASE_API_001_REMOTE_SHA_<SHA256>_SOURCE_0B858C5_TRANSIENT_LOOPBACK_3040_CLONE_DB_SCOPED_TOKEN_TTL_REVOKE_AUDIT_SIX_ROUTE_SMOKE_MANDATORY_CLEANUP_PRODUCTION_BOT_WEB_DB_AND_AWG_UNTOUCHED
```

The runner compares the entire literal phrase ordinally. Authority is
single-use and does not extend to a repeat run, persistent service,
production-database token, deployment, or another overlay.

## 9. Explicit exclusions

- public API/OpenAPI exposure or persistent API service;
- production token/audit writes or schema migration;
- `install:write`, POST, config delivery, QR, `vpn://`, keys, or PSKs;
- peer operations, remote operations, bot/Telegram actions, or web restart;
- provider action, blind database restore, or any AWG mutation;
- any Phase 10/11 rollout, `/start`, cleanup, stage, accept, or restore repeat;
- VIDDA or standalone AmneziaWG client diagnostics.

## 10. Acceptance sequence

```text
WRITTEN_SPEC_REVIEW
-> TDD_IMPLEMENTATION_PLAN
-> RED_TESTS
-> MINIMAL_EXECUTOR_AND_RUNNER
-> GREEN_SCOPED_AND_FULL_TESTS
-> DIFF_AND_SECURITY_REVIEW
-> STATUS_EVIDENCE_SYNC
-> COMMIT_PUSH_EXACT_ORIGIN_READBACK
-> ISSUE_SEPARATE_EXACT_LIVE_APPROVAL
-> ONLY_AFTER_APPROVAL_PREFLIGHT_AND_RUN
```

No step inherits live authority from an earlier step.
