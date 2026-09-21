# Changelog

## 2026-09-21

- Added a scoped stop controller and SIGTERM/SIGINT registration boundary.
  Signals before loop attachment are retained; admission closes once, repeated
  stop leaves cleanup alive, and external cancellation is not classified as an
  owned stop. Previous signal handlers are restored even after partial install
  or restore failure. Tests use a fake registry, without host OS signals.
  RED: missing controller and signal-scope API; GREEN: 10 passed in 2.48s on
  Python 3.12.14 / pinned aiogram 3.30.0. Runtime wiring follows separately.
  No dependency/unit/schema changes, live access or deployment; no hard stop SLA.

## 2026-09-20

- Independent review found two pre-dispatch lifecycle races. A cancelled queued
  waiter could reach the executor before its caller handled cancellation; the
  pump now drops it before submit. A factory could start after close had already
  ended admission; factory submit now checks state. Both reproduced with failing
  deterministic tests before the fix. Final relevant suite: 312 passed in 47.46s,
  without warnings. Review of 2069e41..8bc8496 found no Critical issues; both
  findings were addressed in this fix pass. No merge or deployment was performed.

- Wired persistent bot startup and all 41 handler workflow calls through the
  worker/facade. Accepted handlers drain through remote/local completion and
  Telegram delivery recording before SQLite, session and instance lock close.
  Startup timeouts drain started factories; repeated cancellation retains ownership;
  simultaneous runtime/cleanup failures are preserved. Raw phase15 components are
  no longer exported in dispatcher context. Added safe ru/en partial-operation and
  busy/closed replies. Failed delivery records never report success or resend.
- Verification: handler/partial RED 5 failures; runtime RED 6 failures; a failed
  partial-error reply additionally reproduced unsafe exception propagation and
  now emits a fixed diagnostic marker. Final bot/device-revoke/bootstrap suite:
  310 passed (baseline 278). Real temporary SQLite, controlled peer stubs and fake
  Telegram only. Includes fresh authorization after queuing and remote success
  with local rollback failure. No live access, dependency/schema changes, package
  builds or deployment. One worker serializes this bot only; drain has no hard
  deadline, and forced process termination/exactly-once recovery remain unsolved.

- Added bounded ownership of accepted handlers and cancellation-resistant cleanup.
  Parent cancellation leaves delivery/record work alive; shutdown rejects new
  handlers and drains accepted ones. Tickets cannot be reused by child tasks.
  RED: absent lifetime module; GREEN: 11 worker/lifetime tests passed. Runtime
  integration follows separately; no Telegram or server operations were performed.

- Added an explicit async facade for the 30 bot workflow methods and detached
  result snapshots. Managed factory failures close SQLite; successful workflows
  expose idempotent close without taking ownership of externally supplied repos.
  RED confirmed three leaked connections and absent close/facade APIs; targeted
  worker/facade/bootstrap/workflow suite: 75 passed. Runtime wiring remains pending.

- Added a sequential bot workflow worker with eight outstanding slots, its own
  FIFO, per-call context and one resource-owning thread. Queued cancellation
  removes work; dispatched work finishes. Shutdown drains and joins off-loop.
  Runtime wiring is pending. Baseline: 278 passed. Worker RED: missing module;
  GREEN: 6 tests passed, including real SQLite ownership, cancellation churn,
  capacity, context isolation, factory/close failures and startup cancellation.
  No live access, dependency changes or deployment.

- Web server health checks now run outside the application event loop. A slow
  SSH check no longer blocks other requests on that loop. Authentication, CSRF,
  SQLite access, stored health summaries, audit records and redirects retain
  their existing behavior; only the synchronous health function is offloaded.
- Verification: existing web server/health tests 28 passed; the new responsiveness
  cases reproduced two failures before the fix (three rejection cases passed).
  Final targeted run: 33 passed using Python 3.12.14. The existing Starlette
  deprecation warning about httpx remains; dependencies were not changed.
- Independent read-only review found no Critical, Important or Minor issues.
- All test data and health responses were synthetic. No live SSH, Telegram,
  production database, config issuance, package rebuild or deployment occurred.
  This does not add retries, a circuit breaker or an operation deadline, and
  cancellation of the awaiting request does not stop a running worker thread.
