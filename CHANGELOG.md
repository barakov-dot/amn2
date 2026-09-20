# Changelog

## 2026-09-20

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
