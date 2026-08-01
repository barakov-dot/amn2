import re
from dataclasses import dataclass
from datetime import datetime, timedelta


USA_RETIREMENT_NOT_READY = (
    "USA ПОКА НЕЛЬЗЯ ОТКЛЮЧАТЬ: ROLLBACK CONTOUR ЕЩЁ НЕ ЗАМЕНЁН ИЛИ НЕ ПРИНЯТ"
)
USA_RETIREMENT_READY = (
    "USA МОЖНО БЕЗОПАСНО ОТКЛЮЧАТЬ И ПЕРЕПРОФИЛИРОВАТЬ ПОСЛЕ ОТДЕЛЬНОГО "
    "EXACT APPROVAL"
)


def _require_timezone_aware(field_name: str, value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")


@dataclass(frozen=True)
class UsaRetirementEvidence:
    spain_baseline_equal: bool
    required_devices_accepted: bool
    unknown_client_facts_listed: bool
    last_dataplane_mutation: datetime
    critical_incident_since_mutation: bool
    unexplained_drift_since_mutation: bool
    encrypted_backup_verified: bool
    backup_checksum_verified: bool
    backup_secret_inventory_verified: bool
    backup_retention_defined: bool
    restore_inputs_documented: bool
    independent_restore_rehearsed: bool
    replacement_rollback_accepted: bool
    no_failover_risk_acceptance_receipt: str | None
    usa_dependency_audit_clear: bool
    retirement_plan_ready: bool
    final_readonly_audit_completed: bool

    def __post_init__(self) -> None:
        _require_timezone_aware(
            "last_dataplane_mutation",
            self.last_dataplane_mutation,
        )
        receipt = self.no_failover_risk_acceptance_receipt
        if receipt is not None and not re.fullmatch(r"sha256:[0-9a-f]{64}", receipt):
            raise ValueError("invalid no-failover risk acceptance receipt")


@dataclass(frozen=True)
class UsaRetirementReadiness:
    ready: bool
    missing: tuple[str, ...]
    notification: str
    live_action_authorized: bool = False


def evaluate_usa_retirement_readiness(
    evidence: UsaRetirementEvidence,
    *,
    now: datetime,
) -> UsaRetirementReadiness:
    _require_timezone_aware("now", now)
    window_complete = (
        now - evidence.last_dataplane_mutation >= timedelta(days=14)
        and not evidence.critical_incident_since_mutation
        and not evidence.unexplained_drift_since_mutation
    )
    rollback_contour_decision = (
        evidence.replacement_rollback_accepted
        or bool(evidence.no_failover_risk_acceptance_receipt)
    )
    checks = {
        "spain_baseline_equal": evidence.spain_baseline_equal,
        "required_devices_accepted": evidence.required_devices_accepted,
        "unknown_client_facts_listed": evidence.unknown_client_facts_listed,
        "observation_window_complete": window_complete,
        "encrypted_backup_verified": evidence.encrypted_backup_verified,
        "backup_checksum_verified": evidence.backup_checksum_verified,
        "backup_secret_inventory_verified": evidence.backup_secret_inventory_verified,
        "backup_retention_defined": evidence.backup_retention_defined,
        "restore_inputs_documented": evidence.restore_inputs_documented,
        "independent_restore_rehearsed": evidence.independent_restore_rehearsed,
        "rollback_contour_decision": rollback_contour_decision,
        "usa_dependency_audit_clear": evidence.usa_dependency_audit_clear,
        "retirement_plan_ready": evidence.retirement_plan_ready,
        "final_readonly_audit_completed": evidence.final_readonly_audit_completed,
    }
    missing = tuple(name for name, passed in checks.items() if not passed)
    return UsaRetirementReadiness(
        ready=not missing,
        missing=missing,
        notification=(USA_RETIREMENT_READY if not missing else USA_RETIREMENT_NOT_READY),
    )
