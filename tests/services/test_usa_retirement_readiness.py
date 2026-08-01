from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from app.services.usa_retirement_readiness import (
    UsaRetirementEvidence,
    evaluate_usa_retirement_readiness,
)


NOT_READY = (
    "USA ПОКА НЕЛЬЗЯ ОТКЛЮЧАТЬ: ROLLBACK CONTOUR ЕЩЁ НЕ ЗАМЕНЁН ИЛИ НЕ ПРИНЯТ"
)
READY = (
    "USA МОЖНО БЕЗОПАСНО ОТКЛЮЧАТЬ И ПЕРЕПРОФИЛИРОВАТЬ ПОСЛЕ ОТДЕЛЬНОГО "
    "EXACT APPROVAL"
)
NOW = datetime(2026, 8, 15, 12, 0, tzinfo=timezone.utc)


def all_ready_evidence(**overrides) -> UsaRetirementEvidence:
    values = {
        "spain_baseline_equal": True,
        "required_devices_accepted": True,
        "unknown_client_facts_listed": True,
        "last_dataplane_mutation": NOW - timedelta(days=14),
        "critical_incident_since_mutation": False,
        "unexplained_drift_since_mutation": False,
        "encrypted_backup_verified": True,
        "backup_checksum_verified": True,
        "backup_secret_inventory_verified": True,
        "backup_retention_defined": True,
        "restore_inputs_documented": True,
        "independent_restore_rehearsed": True,
        "replacement_rollback_accepted": True,
        "no_failover_risk_acceptance_receipt": None,
        "usa_dependency_audit_clear": True,
        "retirement_plan_ready": True,
        "final_readonly_audit_completed": True,
    }
    values.update(overrides)
    return UsaRetirementEvidence(**values)


@pytest.mark.parametrize(
    "missing_field",
    [
        "spain_baseline_equal",
        "required_devices_accepted",
        "unknown_client_facts_listed",
        "encrypted_backup_verified",
        "backup_checksum_verified",
        "backup_secret_inventory_verified",
        "backup_retention_defined",
        "restore_inputs_documented",
        "independent_restore_rehearsed",
        "usa_dependency_audit_clear",
        "retirement_plan_ready",
        "final_readonly_audit_completed",
    ],
)
def test_each_stored_missing_prerequisite_keeps_usa_not_ready(missing_field):
    evidence = replace(all_ready_evidence(), **{missing_field: False})

    result = evaluate_usa_retirement_readiness(evidence, now=NOW)

    assert result.ready is False
    assert result.notification == NOT_READY
    assert missing_field in result.missing
    assert result.live_action_authorized is False


@pytest.mark.parametrize(
    "override",
    [
        {"critical_incident_since_mutation": True},
        {"unexplained_drift_since_mutation": True},
    ],
)
def test_incident_or_unexplained_drift_resets_observation_window(override):
    result = evaluate_usa_retirement_readiness(
        all_ready_evidence(**override),
        now=NOW,
    )

    assert result.ready is False
    assert "observation_window_complete" in result.missing


def test_dataplane_mutation_resets_fourteen_day_window():
    evidence = replace(
        all_ready_evidence(),
        last_dataplane_mutation=NOW - timedelta(days=13, hours=23),
    )

    result = evaluate_usa_retirement_readiness(evidence, now=NOW)

    assert result.ready is False
    assert "observation_window_complete" in result.missing


def test_missing_rollback_and_missing_risk_acceptance_keeps_usa_not_ready():
    result = evaluate_usa_retirement_readiness(
        all_ready_evidence(
            replacement_rollback_accepted=False,
            no_failover_risk_acceptance_receipt=None,
        ),
        now=NOW,
    )

    assert "rollback_contour_decision" in result.missing


def test_explicit_no_failover_risk_acceptance_can_replace_rollback_evidence():
    result = evaluate_usa_retirement_readiness(
        all_ready_evidence(
            replacement_rollback_accepted=False,
            no_failover_risk_acceptance_receipt="sha256:" + "d" * 64,
        ),
        now=NOW,
    )

    assert result.ready is True
    assert result.live_action_authorized is False


@pytest.mark.parametrize(
    "receipt",
    ["", "sha256:abc", "sha256:" + "D" * 64, "not-a-receipt"],
)
def test_invalid_no_failover_risk_acceptance_receipt_fails_closed(receipt):
    with pytest.raises(ValueError, match="risk acceptance receipt"):
        all_ready_evidence(no_failover_risk_acceptance_receipt=receipt)


def test_naive_timestamps_fail_closed():
    with pytest.raises(ValueError, match="timezone-aware"):
        all_ready_evidence(last_dataplane_mutation=NOW.replace(tzinfo=None))

    with pytest.raises(ValueError, match="timezone-aware"):
        evaluate_usa_retirement_readiness(
            all_ready_evidence(),
            now=NOW.replace(tzinfo=None),
        )


def test_ready_message_still_requires_separate_exact_approval():
    result = evaluate_usa_retirement_readiness(all_ready_evidence(), now=NOW)

    assert result.ready is True
    assert result.notification == READY
    assert result.live_action_authorized is False
