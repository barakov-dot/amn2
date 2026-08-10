from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal

from app.db.repositories import Repository
from app.services.dual_protocol_profiles import (
    DualProtocolProfileService,
    ProtocolProfile,
)
from app.services.drift_diagnostics import (
    DesiredPeerState,
    ObservedPeerState,
    ReconciliationEvidence,
    ReconciliationSnapshot,
)
from app.vpn.config_versions import SUPPORTED_CONFIG_VERSIONS
from app.vpn.protocol_versions import (
    config_version_for_protocol,
    normalize_protocol_version,
)


DEVICE_PLATFORMS = frozenset(
    {"android", "android_tv", "ios", "linux", "macos", "windows", "unknown"}
)
OFFICIAL_CLIENT_TYPES = frozenset(
    {
        "amnezia_vpn",
        "amneziawg",
        "default_vpn",
        "defaultvpn",
        "unknown_official",
    }
)
DEVICE_IMPORT_METHODS = frozenset(
    {
        "standard_conf",
        "conf_file",
        "native_vpn_json",
        "qr",
        "managed_ticket",
        "unknown",
    }
)
CONFIG_FINGERPRINT_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")

AcceptanceStatus = Literal["passed", "failed", "pending"]
AcceptanceSource = Literal[
    "manual_client_test",
    "ticket_claim",
    "traffic_observation",
    "unknown",
]
ClientIdentityEvidenceStatus = Literal[
    "unknown", "claimed", "verified", "failed", "stale"
]


@dataclass(frozen=True)
class DeviceAcceptanceEvidence:
    status: AcceptanceStatus
    source: AcceptanceSource
    observed_at: datetime
    reference: str

    def safe_metadata(self) -> dict[str, str]:
        return {
            "status": self.status,
            "source": self.source,
            "observed_at": _format_datetime(self.observed_at),
            "reference": self.reference,
        }


@dataclass(frozen=True)
class DevicePassport:
    device_id: str
    local_device_id: int | None
    owner_user_id: int
    server_id: int | None
    platform: str
    official_client_type: str
    client_version: str | None
    import_method: str
    config_schema_version: str
    config_fingerprint: str
    protocol_version: str | None
    runtime_instance_id: str | None
    client_identity_evidence_status: ClientIdentityEvidenceStatus
    compatibility_evidence_id: str | None
    last_seen_at: datetime | None
    acceptance_evidence: DeviceAcceptanceEvidence | None
    revoked_at: datetime | None
    revoke_reason: str | None
    reconciliation: ReconciliationSnapshot
    created_at: datetime
    updated_at: datetime
    protocol_profiles: tuple[ProtocolProfile, ...] = ()

    def safe_metadata(self) -> dict[str, object]:
        snapshot = self.reconciliation
        return {
            "device_id": self.device_id,
            "local_device_id": self.local_device_id,
            "owner_user_id": self.owner_user_id,
            "server_id": self.server_id,
            "platform": self.platform,
            "official_client_type": self.official_client_type,
            "client_version": self.client_version,
            "import_method": self.import_method,
            "config_schema_version": self.config_schema_version,
            "config_fingerprint": self.config_fingerprint,
            "protocol_version": self.protocol_version,
            "runtime_instance_id": self.runtime_instance_id,
            "client_identity_evidence_status": self.client_identity_evidence_status,
            "compatibility_evidence_id": self.compatibility_evidence_id,
            "last_seen_at": _format_optional_datetime(self.last_seen_at),
            "acceptance_evidence": (
                self.acceptance_evidence.safe_metadata()
                if self.acceptance_evidence is not None
                else None
            ),
            "revoked_at": _format_optional_datetime(self.revoked_at),
            "revoke_reason": self.revoke_reason,
            "desired_state": snapshot.desired_state.safe_metadata(),
            "observed_state": snapshot.observed_state.safe_metadata(),
            "drift_state": snapshot.drift_state,
            "drift_reason": snapshot.drift_reason,
            "last_observed_at": _format_optional_datetime(
                snapshot.last_observed_at
            ),
            "reconciliation_evidence": [
                item.safe_metadata() for item in snapshot.evidence
            ],
            "recommended_next_action": snapshot.recommended_next_action,
            "created_at": _format_datetime(self.created_at),
            "updated_at": _format_datetime(self.updated_at),
            "protocol_profiles": [
                profile.safe_metadata()
                for profile in sorted(
                    self.protocol_profiles,
                    key=lambda item: item.protocol_version.value,
                )
            ],
            "capability_boundary": {
                "hardware_fingerprint": False,
                "endpoint_posture": False,
                "device_impersonation_protection": False,
                "mdm": False,
                "amnezia_agent_present": False,
            },
        }


def fingerprint_config(config_text: str) -> str:
    if not config_text:
        raise ValueError("config_text is required")
    digest = hashlib.sha256(config_text.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def generate_device_passport_id() -> str:
    return f"dev_{uuid.uuid4().hex}"


def validate_device_passport_context(
    *,
    platform: str,
    official_client_type: str,
    import_method: str,
    config_schema_version: str,
    client_version: str | None = None,
) -> None:
    _validate_passport_fields(
        platform=platform,
        official_client_type=official_client_type,
        import_method=import_method,
        config_schema_version=config_schema_version,
        client_version=client_version,
    )


def create_device_passport(
    repo: Repository,
    *,
    owner_user_id: int,
    platform: str,
    official_client_type: str,
    import_method: str,
    config_schema_version: str,
    config_text: str | None = None,
    config_fingerprint: str | None = None,
    local_device_id: int | None = None,
    client_version: str | None = None,
    last_seen_at: datetime | None = None,
    acceptance_evidence: DeviceAcceptanceEvidence | None = None,
    device_id: str | None = None,
    reconciliation: ReconciliationSnapshot | None = None,
    protocol_version: str | None = None,
    runtime_instance_id: str | None = None,
    client_identity_evidence_status: ClientIdentityEvidenceStatus | None = None,
    compatibility_evidence_id: str | None = None,
) -> DevicePassport:
    normalized = _validate_passport_fields(
        platform=platform,
        official_client_type=official_client_type,
        import_method=import_method,
        config_schema_version=config_schema_version,
        client_version=client_version,
    )
    actual_fingerprint = _resolve_config_fingerprint(
        config_text=config_text,
        config_fingerprint=config_fingerprint,
    )
    actual_device_id = device_id or generate_device_passport_id()
    if not re.fullmatch(r"dev_[0-9a-f]{32}", actual_device_id):
        raise ValueError("device_id must use the generated dev_<uuid> format")
    _validate_acceptance_evidence(acceptance_evidence)
    (
        normalized_protocol,
        normalized_runtime,
        normalized_identity_status,
        normalized_compatibility_evidence,
    ) = _validate_phase13_passport_fields(
        protocol_version=protocol_version,
        runtime_instance_id=runtime_instance_id,
        client_identity_evidence_status=client_identity_evidence_status,
        compatibility_evidence_id=compatibility_evidence_id,
        client_version=normalized[4],
        config_schema_version=normalized[3],
    )

    repo.create_device_passport(
        device_id=actual_device_id,
        owner_user_id=owner_user_id,
        local_device_id=local_device_id,
        platform=normalized[0],
        official_client_type=normalized[1],
        client_version=normalized[4],
        import_method=normalized[2],
        config_schema_version=normalized[3],
        config_fingerprint=actual_fingerprint,
        last_seen_at=_format_optional_datetime(last_seen_at),
        acceptance_evidence=(
            acceptance_evidence.safe_metadata()
            if acceptance_evidence is not None
            else None
        ),
        protocol_version=normalized_protocol,
        runtime_instance_id=normalized_runtime,
        client_identity_evidence_status=normalized_identity_status,
        compatibility_evidence_id=normalized_compatibility_evidence,
    )
    return get_device_passport(
        repo,
        actual_device_id,
        reconciliation=reconciliation,
    )


def get_device_passport(
    repo: Repository,
    device_id: str,
    *,
    reconciliation: ReconciliationSnapshot | None = None,
) -> DevicePassport:
    row = repo.get_device_passport(device_id)
    if row is None:
        raise LookupError("device passport not found")
    return _passport_from_row(
        repo,
        row,
        reconciliation=reconciliation,
    )


def list_device_passports(
    repo: Repository,
    owner_user_id: int,
    *,
    reconciliations: dict[str, ReconciliationSnapshot] | None = None,
    limit: int = 100,
) -> tuple[DevicePassport, ...]:
    snapshots = reconciliations or {}
    return tuple(
        _passport_from_row(
            repo,
            row,
            reconciliation=snapshots.get(str(row["device_id"])),
        )
        for row in repo.list_device_passports_for_owner(owner_user_id, limit=limit)
    )


def list_all_device_passports(
    repo: Repository,
    *,
    reconciliations: dict[str, ReconciliationSnapshot] | None = None,
    limit: int = 100,
) -> tuple[DevicePassport, ...]:
    snapshots = reconciliations or {}
    return tuple(
        _passport_from_row(
            repo,
            row,
            reconciliation=snapshots.get(str(row["device_id"])),
        )
        for row in repo.list_device_passports(limit=limit)
    )


def attach_passport_to_local_device(
    repo: Repository,
    *,
    passport_device_id: str,
    local_device_id: int,
) -> DevicePassport:
    attached = repo.attach_device_passport_to_local_device(
        passport_device_id=passport_device_id,
        local_device_id=local_device_id,
    )
    if not attached:
        raise ValueError("revoked device passport cannot be attached")
    return get_device_passport(repo, passport_device_id)


def record_device_acceptance(
    repo: Repository,
    *,
    device_id: str,
    last_seen_at: datetime,
    evidence: DeviceAcceptanceEvidence,
) -> DevicePassport:
    _validate_acceptance_evidence(evidence)
    with repo.transaction():
        updated = repo.update_device_passport_observation(
            device_id=device_id,
            last_seen_at=_format_datetime(last_seen_at),
            acceptance_evidence=evidence.safe_metadata(),
        )
        if not updated:
            raise LookupError("device passport not found")
        ticket = repo.get_enrollment_ticket_by_claimed_device_id(device_id)
        if ticket is not None and evidence.status != "pending":
            from app.services.device_lifecycle import (
                LifecycleEvidence,
                list_device_lifecycle_events,
                record_device_lifecycle_stage,
            )

            ticket_id = str(ticket["id"])
            lifecycle = list_device_lifecycle_events(repo, ticket_id=ticket_id)
            delivered = next(
                (
                    event
                    for event in reversed(lifecycle)
                    if event.stage == "delivered" and event.status == "completed"
                ),
                None,
            )
            if delivered is None:
                raise ValueError(
                    "acceptance_verified requires completed delivered lifecycle stage"
                )
            record_device_lifecycle_stage(
                repo,
                ticket_id=ticket_id,
                passport_device_id=device_id,
                stage="acceptance_verified",
                status="completed" if evidence.status == "passed" else "failed",
                started_at=delivered.occurred_at,
                occurred_at=evidence.observed_at,
                evidence=LifecycleEvidence(
                    source=evidence.source,
                    reference=evidence.reference,
                ),
            )
    return get_device_passport(repo, device_id)


def _passport_from_row(
    repo: Repository,
    row,
    *,
    reconciliation: ReconciliationSnapshot | None,
) -> DevicePassport:
    evidence = _parse_acceptance_evidence(row["acceptance_evidence_json"])
    snapshot = reconciliation or _unknown_snapshot(repo, row)
    local_device = (
        repo.get_device(int(row["local_device_id"]))
        if row["local_device_id"] is not None
        else None
    )
    return DevicePassport(
        device_id=str(row["device_id"]),
        local_device_id=(
            int(row["local_device_id"])
            if row["local_device_id"] is not None
            else None
        ),
        owner_user_id=int(row["owner_user_id"]),
        server_id=(
            int(local_device["server_id"])
            if local_device is not None
            else None
        ),
        platform=str(row["platform"]),
        official_client_type=str(row["official_client_type"]),
        client_version=(
            str(row["client_version"]) if row["client_version"] is not None else None
        ),
        import_method=str(row["import_method"]),
        config_schema_version=str(row["config_schema_version"]),
        config_fingerprint=str(row["config_fingerprint"]),
        protocol_version=_optional_row_text(row, "protocol_version"),
        runtime_instance_id=_optional_row_text(row, "runtime_instance_id"),
        client_identity_evidence_status=(
            _optional_row_text(row, "client_identity_evidence_status") or "unknown"
        ),
        compatibility_evidence_id=_optional_row_text(
            row, "compatibility_evidence_id"
        ),
        last_seen_at=_parse_optional_datetime(row["last_seen_at"]),
        acceptance_evidence=evidence,
        revoked_at=_parse_optional_datetime(row["revoked_at"]),
        revoke_reason=(
            str(row["revoke_reason"]) if row["revoke_reason"] is not None else None
        ),
        reconciliation=snapshot,
        created_at=_parse_datetime(str(row["created_at"])),
        updated_at=_parse_datetime(str(row["updated_at"])),
        protocol_profiles=DualProtocolProfileService(repo).for_passport(
            str(row["device_id"])
        ),
    )


def _unknown_snapshot(repo: Repository, row) -> ReconciliationSnapshot:
    local_device_id = row["local_device_id"]
    if local_device_id is None:
        desired = DesiredPeerState(
            peer_expected=None,
            peer_public_key=None,
            allowed_ips=(),
            device_status=None,
        )
    else:
        device = repo.get_device(int(local_device_id))
        desired = DesiredPeerState(
            peer_expected=str(device["status"]) == "active",
            peer_public_key=str(device["peer_public_key"]),
            allowed_ips=(f"{device['vpn_ip']}/32",),
            device_status=str(device["status"]),
            protocol_version=(
                _optional_row_text(row, "protocol_version")
                or _optional_row_text(device, "protocol_version")
            ),
            runtime_instance_id=(
                _optional_row_text(row, "runtime_instance_id")
                or _optional_row_text(device, "runtime_instance_id")
            ),
            compatibility_evidence_id=(
                _optional_row_text(row, "compatibility_evidence_id")
                or _optional_row_text(device, "compatibility_evidence_id")
            ),
            compatibility_status=(
                _optional_row_text(row, "client_identity_evidence_status")
                or _optional_row_text(device, "client_identity_evidence_status")
            ),
        )
    created_at = _parse_datetime(str(row["created_at"]))
    return ReconciliationSnapshot(
        subject_id=f"passport:{row['device_id']}",
        desired_state=desired,
        observed_state=ObservedPeerState(
            peer_present=None,
            peer_public_key=None,
            allowed_ips=(),
            observation_succeeded=True,
        ),
        drift_state="unknown",
        drift_reason="no_remote_observation_has_been_supplied",
        last_observed_at=None,
        evidence=(
            ReconciliationEvidence(
                source="device_passport",
                reference=f"passport:{row['device_id']}",
                collected_at=created_at,
            ),
        ),
        recommended_next_action="collect_fresh_observation",
    )


def _validate_passport_fields(
    *,
    platform: str,
    official_client_type: str,
    import_method: str,
    config_schema_version: str,
    client_version: str | None,
) -> tuple[str, str, str, str, str | None]:
    normalized_platform = platform.strip().lower()
    normalized_client_type = official_client_type.strip().lower()
    normalized_import_method = import_method.strip().lower()
    normalized_schema_version = config_schema_version.strip()
    normalized_client_version = (
        client_version.strip() if client_version and client_version.strip() else None
    )

    if normalized_platform not in DEVICE_PLATFORMS:
        raise ValueError("unsupported device platform")
    if normalized_client_type not in OFFICIAL_CLIENT_TYPES:
        raise ValueError("unsupported official client type")
    if normalized_import_method not in DEVICE_IMPORT_METHODS:
        raise ValueError("unsupported import method")
    if normalized_schema_version not in SUPPORTED_CONFIG_VERSIONS:
        raise ValueError("unsupported config schema version")
    if normalized_client_version is not None and len(normalized_client_version) > 64:
        raise ValueError("client_version is too long")
    return (
        normalized_platform,
        normalized_client_type,
        normalized_import_method,
        normalized_schema_version,
        normalized_client_version,
    )


def _resolve_config_fingerprint(
    *,
    config_text: str | None,
    config_fingerprint: str | None,
) -> str:
    if (config_text is None) == (config_fingerprint is None):
        raise ValueError("provide exactly one config_text or config_fingerprint")
    if config_text is not None:
        return fingerprint_config(config_text)
    actual_fingerprint = str(config_fingerprint)
    if CONFIG_FINGERPRINT_PATTERN.fullmatch(actual_fingerprint) is None:
        raise ValueError("invalid config fingerprint")
    return actual_fingerprint


def _validate_phase13_passport_fields(
    *,
    protocol_version: str | None,
    runtime_instance_id: str | None,
    client_identity_evidence_status: str | None,
    compatibility_evidence_id: str | None,
    client_version: str | None,
    config_schema_version: str,
) -> tuple[str | None, str | None, ClientIdentityEvidenceStatus, str | None]:
    normalized_protocol = None
    if protocol_version is not None:
        protocol = normalize_protocol_version(protocol_version)
        normalized_protocol = protocol.value
        if config_version_for_protocol(protocol) != config_schema_version:
            raise ValueError("protocol_version does not match config_schema_version")
    normalized_runtime = _optional_safe_identifier(
        runtime_instance_id, "runtime_instance_id"
    )
    normalized_compatibility = _optional_safe_identifier(
        compatibility_evidence_id, "compatibility_evidence_id"
    )
    status = client_identity_evidence_status or "unknown"
    if status not in {"unknown", "claimed", "verified", "failed", "stale"}:
        raise ValueError("unsupported client_identity_evidence_status")
    if status == "verified" and (client_version is None or normalized_compatibility is None):
        raise ValueError("verified client identity requires exact version and evidence")
    return normalized_protocol, normalized_runtime, status, normalized_compatibility


def _optional_safe_identifier(value: str | None, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(field)
    if len(value) > 255 or any(ord(char) < 32 for char in value):
        raise ValueError(field)
    return value


def _optional_row_text(row, key: str) -> str | None:
    value = row[key] if key in row.keys() else None
    return str(value) if value is not None else None


def _validate_acceptance_evidence(
    evidence: DeviceAcceptanceEvidence | None,
) -> None:
    if evidence is None:
        return
    if evidence.status not in {"passed", "failed", "pending"}:
        raise ValueError("unsupported acceptance status")
    if evidence.source not in {
        "manual_client_test",
        "ticket_claim",
        "traffic_observation",
        "unknown",
    }:
        raise ValueError("unsupported acceptance source")
    if not evidence.reference.strip() or len(evidence.reference) > 200:
        raise ValueError("acceptance evidence reference is invalid")
    if any(char in evidence.reference for char in ("\r", "\n", "\t")):
        raise ValueError("acceptance evidence reference must be one line")


def _parse_acceptance_evidence(value: str | None) -> DeviceAcceptanceEvidence | None:
    if value is None:
        return None
    payload = json.loads(value)
    return DeviceAcceptanceEvidence(
        status=payload["status"],
        source=payload["source"],
        observed_at=_parse_datetime(payload["observed_at"]),
        reference=payload["reference"],
    )


def _parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return _as_utc(parsed)


def _parse_optional_datetime(value: str | None) -> datetime | None:
    return _parse_datetime(value) if value is not None else None


def _format_datetime(value: datetime) -> str:
    return _as_utc(value).isoformat().replace("+00:00", "Z")


def _format_optional_datetime(value: datetime | None) -> str | None:
    return _format_datetime(value) if value is not None else None


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
