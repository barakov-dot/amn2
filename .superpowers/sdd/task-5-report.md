# Task 5 report: admin-only config handoff

## Status

Implemented an admin-only `/admin_issue_config recipient | device | platform`
handoff plus `/admin_resend_issued_config <device_id>` for delivery recovery.
The handoff result is distinct from ordinary user delivery and contains no user
Telegram target. Telegram sends exactly one captionless `.conf` document to the
invoking authorized admin. No recipient send, QR send, `vpn://` message, or
secret-bearing caption/log/audit was added.

Delivery lifecycle evidence is recorded only after `send_document` returns.
Telegram failure records a failed `delivered` stage and offers resend of the
existing device. The integration test proves resend does not apply a second
peer and transitions lifecycle evidence from failed to completed.

## RED evidence

Initial exact tests:

```text
python -m pytest tests/bot/test_bot_workflows.py::test_issue_admin_config_rejects_non_admin_before_issuance tests/bot/test_bot_workflows.py::test_issue_admin_config_returns_distinct_secret_handoff_to_admin tests/bot/test_bot_handlers.py::test_handle_admin_issue_config_rejects_non_admin_before_parsing_or_mutation tests/bot/test_bot_handlers.py::test_handle_admin_issue_config_sends_one_secretless_conf_to_invoking_admin -q

FAILED test_issue_admin_config_returns_distinct_secret_handoff_to_admin
assert None == AdminConfigHandoff(...)
```

Handler behavior RED:

```text
python -m pytest tests/bot/test_bot_handlers.py::test_handle_admin_issue_config_rejects_non_admin_before_parsing_or_mutation tests/bot/test_bot_handlers.py::test_handle_admin_issue_config_sends_one_secretless_conf_to_invoking_admin -q

2 failed
- expected "Admin access required.", got usage text
- expected one issuance call, got none
```

Real resend integration RED:

```text
python -m pytest tests/bot/test_bot_workflows.py::test_failed_admin_handoff_can_resend_existing_device_without_second_peer -q

FAILED: TypeError in build_device_config_delivery
int(user["telegram_id"]) received None for an operator-created recipient
```

That RED led to the shared delivery result correctly allowing an absent
recipient Telegram ID while preserving ordinary-user behavior.

## GREEN evidence

Exact authorization and handoff tests after minimal implementation:

```text
4 passed in 2.40s
```

Exact validation, failure lifecycle, safe resend, and registration tests:

```text
4 passed in 1.84s
```

Real operator-recipient lifecycle/resend integration after shared-service fix:

```text
1 passed in 2.27s
```

Post-review exact delivery/audit tests:

```text
4 passed in 2.39s
```

Fresh required focused suite after all changes:

```text
python -m pytest tests/bot/test_bot_workflows.py tests/bot/test_bot_handlers.py tests/bot/test_app_bootstrap.py -q
95 passed in 18.73s
```

Adjacent shared config-delivery coverage:

```text
python -m pytest tests/services/test_config_delivery.py -q
4 passed in 3.24s
```

## Full-suite evidence

Fresh full repository suite after final self-review changes:

```text
python -m pytest -q
992 passed, 1 skipped, 1 warning in 161.09s (0:02:41)
```

The warning is the pre-existing Starlette `httpx` deprecation warning from
`fastapi.testclient`; there were no test failures.

## Self-review

- Authorization occurs before command parsing and before issuance/device reads.
- Length and supported-platform validation occur before service mutation.
- `AdminConfigIssuanceService` performs the single issuance call and the
  handoff uses `OperatorDeviceCreateResult.config_filename` via its receipt.
- Telegram destination is always the invoking admin ID; recipient Telegram ID
  is absent from the handoff DTO.
- Document caption is `None`; the admin path sends no message/photo/QR/import link.
- Exception details and config bytes are absent from user-visible failure text,
  lifecycle evidence, and audit assertions.
- Completed delivery lifecycle is recorded only after Telegram returns; failed
  send records `delivered/failed`.
- Safe resend rebuilds stored device material and does not create/apply a peer.
- Ordinary user delivery functions and handlers were not changed.
- `git diff --check` passed before report creation.

## Concerns

No blocking concerns. The full suite retains one unrelated, pre-existing
Starlette deprecation warning.

## Controller security fix wave

### Fix RED evidence

Exact authorization, provenance, safe-unavailable, and repository lookup tests:

```text
python -m pytest tests/bot/test_bot_workflows.py::test_database_admin_cannot_issue_config_without_configured_membership tests/bot/test_bot_workflows.py::test_admin_resend_rejects_ordinary_device_without_issuance_provenance tests/bot/test_bot_handlers.py::test_secret_command_rejects_database_admin_outside_configured_set tests/bot/test_bot_handlers.py::test_handle_admin_resend_issued_config_returns_safe_unavailable_response tests/db/test_repositories.py::test_completed_admin_issuance_provenance_lookup_rejects_ambiguity -q

5 failed in 3.69s
```

The failures demonstrated the required gaps:

- a database `is_admin=1` row outside the configured set reached issuance and
  performed an authorization repository read;
- an ordinary passport-bearing device was exportable without issuance provenance;
- unavailable resend propagated secret-bearing internal exception detail;
- no completed, request-bound, unambiguous receipt lookup existed.

### Fix GREEN evidence

The same exact five nodes after the minimal fix:

```text
5 passed in 3.30s
```

Focused bot, shared config-delivery, and repository coverage:

```text
python -m pytest tests/bot/test_bot_workflows.py tests/bot/test_bot_handlers.py tests/bot/test_app_bootstrap.py tests/services/test_config_delivery.py tests/db/test_repositories.py -q
140 passed in 34.03s
```

Fresh full suite after final provenance cleanup:

```text
python -m pytest -q
998 passed, 1 skipped, 1 warning in 138.70s (0:02:18)
```

The warning remains the unrelated pre-existing Starlette `httpx` deprecation.

### Fix-wave self-review

- `is_configured_admin()` is a set-only predicate and does not consult storage.
- Both secret-bearing handlers and all corresponding workflow methods use that
  predicate; unrelated generic admin handlers retain their existing `is_admin()` behavior.
- A persisted database admin outside `_admin_telegram_ids` is denied for issue
  and resend before parsing, issuance, receipt lookup, device lookup, or rendering.
- Resend requires exactly one completed issuance receipt joined to its persisted
  request; missing, partial, or ambiguous provenance returns ineligible.
- The receipt passport must match the current device passport before rendering.
- Ordinary and nonexistent devices cannot be exported and produce one generic,
  secretless unavailable response through the handler.
- Successful resend still sends one captionless document to the configured admin,
  uses the persisted issuance filename, and creates no second peer.
- Ordinary user config delivery coverage remains green.
