# Changelog

## 2026-09-20

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
