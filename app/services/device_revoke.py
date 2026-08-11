from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from collections.abc import Callable
from typing import Protocol

from app.db.repositories import Repository
from app.server.operations import OperationPlan, remote_changed_local_failed_result
from app.services.access import RemoteOperationPartialFailure
from app.vpn.protocol_versions import ProtocolVersion


class DevicePeerRemover(Protocol):
    def remove_peer(self, *, server, peer_public_key: str) -> None: ...


class CascadeRevokeApplyRequired(ValueError):
    def __init__(self, plan: OperationPlan) -> None:
        super().__init__(
            "Cascade revoke requires the remote peer removal apply gate; "
            "local-only revoke is refused"
        )
        self.plan = plan


@dataclass(frozen=True)
class CascadeRevokeResult:
    plan: OperationPlan
    local_device_id: int
    passport_device_id: str | None
    remote_peer_removed: bool
    device_rows_revoked: int
    enrollment_tickets_revoked: int
    delivery_links_closed: int
    assignments_closed: int
    revoked_at: datetime

    def safe_metadata(self) -> dict[str, object]:
        return {
            "operation_plan": self.plan.to_safe_metadata(),
            "local_device_id": self.local_device_id,
            "passport_device_id": self.passport_device_id,
            "remote_peer_removed": self.remote_peer_removed,
            "device_rows_revoked": self.device_rows_revoked,
            "enrollment_tickets_revoked": self.enrollment_tickets_revoked,
            "delivery_links_closed": self.delivery_links_closed,
            "assignments_closed": self.assignments_closed,
            "revoked_at": _format_datetime(self.revoked_at),
        }


@dataclass(frozen=True)
class ProtocolConfigRevokeResult:
    plan: OperationPlan
    local_device_id: int
    passport_device_id: str
    protocol_version: ProtocolVersion
    remote_peer_removed: bool
    device_rows_revoked: int
    profile_state: str
    revoked_at: datetime

    def safe_metadata(self) -> dict[str, object]:
        return {
            "operation_plan": self.plan.to_safe_metadata(),
            "local_device_id": self.local_device_id,
            "passport_device_id": self.passport_device_id,
            "protocol_version": self.protocol_version.value,
            "remote_peer_removed": self.remote_peer_removed,
            "device_rows_revoked": self.device_rows_revoked,
            "profile_state": self.profile_state,
            "revoked_at": _format_datetime(self.revoked_at),
        }


def build_physical_device_revoke_plan(
    repo: Repository,
    *,
    local_device_id: int,
) -> OperationPlan:
    device = repo.get_device(local_device_id)
    passport = repo.get_device_passport_by_local_device_id(local_device_id)
    subject_id = (
        str(passport["device_id"])
        if passport is not None
        else f"local-device-{local_device_id}"
    )
    remote_required = str(device["status"]) in {"pending", "active"}
    return OperationPlan(
        operation_id="device.physical_access.revoke",
        risk_class="remote-state-write" if remote_required else "state-write",
        consistency_status="dry-run",
        commands=("remove configured remote peer",) if remote_required else (),
        audit_summary=(
            "Cascade physical-device access revoke with remote-first ordering"
        ),
        rollback_note=(
            "Do not reactivate from observation. Re-enrollment requires a new "
            "ticket, config and explicit remote peer apply."
        ),
        local_side_effects=(
            "revoke-device",
            "revoke-passport",
            "revoke-enrollment-tickets",
            "close-config-delivery-links",
            "close-device-assignments",
        ),
        remote_side_effects=("awg-peer-remove",) if remote_required else (),
        idempotency_key=f"physical-device-revoke:{subject_id}",
    )


def build_protocol_config_revoke_plan(
    repo: Repository,
    *,
    local_device_id: int,
) -> OperationPlan:
    device = repo.get_device(local_device_id)
    profile = repo.get_device_protocol_profile_by_local_device_id(local_device_id)
    if profile is None:
        raise LookupError("protocol profile not found")
    remote_required = str(device["status"]) in {"pending", "active"}
    return OperationPlan(
        operation_id="protocol-config.revoke",
        risk_class="remote-state-write" if remote_required else "state-write",
        consistency_status="dry-run",
        commands=("remove configured remote peer",) if remote_required else (),
        audit_summary="Revoke one protocol config with remote-first ordering",
        rollback_note=(
            "Do not restore the selected config from observation. A replacement "
            "requires explicit issuance and peer apply."
        ),
        local_side_effects=(
            "revoke-selected-local-device",
            "mark-selected-protocol-profile-revoked",
        ),
        remote_side_effects=("awg-peer-remove",) if remote_required else (),
        idempotency_key=f"protocol-config-revoke:{local_device_id}",
    )


def cascade_revoke_physical_device(
    repo: Repository,
    *,
    local_device_id: int,
    reason: str,
    revoked_at: datetime,
    peer_remover: DevicePeerRemover | None,
    apply_remote: bool,
    remote_already_removed: bool = False,
    audit_recorder: Callable[[dict[str, object]], None] | None = None,
) -> CascadeRevokeResult:
    normalized_reason = " ".join(reason.split())
    if not normalized_reason or len(normalized_reason) > 200:
        raise ValueError("revoke reason is invalid")
    actual_revoked_at = _as_utc(revoked_at)
    device = repo.get_device(local_device_id)
    plan = build_physical_device_revoke_plan(repo, local_device_id=local_device_id)
    remote_required = str(device["status"]) in {"pending", "active"}

    if remote_required and not remote_already_removed and (
        not apply_remote or peer_remover is None
    ):
        raise CascadeRevokeApplyRequired(plan)

    remote_removed = remote_required and remote_already_removed
    if remote_required and not remote_already_removed:
        peer_remover.remove_peer(
            server=repo.get_server(int(device["server_id"])),
            peer_public_key=str(device["peer_public_key"]),
        )
        remote_removed = True

    try:
        with repo.transaction():
            counts = repo.cascade_revoke_device_access(
                local_device_id=local_device_id,
                revoked_at=_format_datetime(actual_revoked_at),
                reason=normalized_reason,
            )
            if audit_recorder is not None:
                audit_recorder(
                    {
                        "operation_plan": plan.to_safe_metadata(),
                        "passport_device_id": counts["passport_device_id"],
                        "remote_peer_removed": remote_removed,
                        "device_rows_revoked": counts["device_rows_revoked"],
                        "enrollment_tickets_revoked": counts[
                            "enrollment_tickets_revoked"
                        ],
                        "delivery_links_closed": counts["delivery_links_closed"],
                        "assignments_closed": counts["assignments_closed"],
                    }
                )
    except Exception as exc:
        if remote_removed:
            raise RemoteOperationPartialFailure(
                remote_changed_local_failed_result(
                    operation_id=plan.operation_id,
                    recovery_note=(
                        "Remote peer was removed but local cascade failed. Keep "
                        "the device blocked, inspect local ticket/delivery/assignment "
                        "state and reconcile before any re-enrollment."
                    ),
                ),
                exc,
            ) from exc
        raise

    return CascadeRevokeResult(
        plan=plan,
        local_device_id=local_device_id,
        passport_device_id=(
            str(counts["passport_device_id"])
            if counts["passport_device_id"] is not None
            else None
        ),
        remote_peer_removed=remote_removed,
        device_rows_revoked=int(counts["device_rows_revoked"]),
        enrollment_tickets_revoked=int(counts["enrollment_tickets_revoked"]),
        delivery_links_closed=int(counts["delivery_links_closed"]),
        assignments_closed=int(counts["assignments_closed"]),
        revoked_at=actual_revoked_at,
    )


def cascade_revoke_protocol_config(
    repo: Repository,
    *,
    local_device_id: int,
    reason: str,
    revoked_at: datetime,
    peer_remover: DevicePeerRemover | None,
    apply_remote: bool,
    remote_already_removed: bool = False,
    actor_kind: str = "system",
    actor_id: int = 0,
    audit_recorder: Callable[[dict[str, object]], None] | None = None,
) -> ProtocolConfigRevokeResult:
    normalized_reason = " ".join(reason.split())
    if not normalized_reason or len(normalized_reason) > 200:
        raise ValueError("revoke reason is invalid")
    actual_revoked_at = _as_utc(revoked_at)
    device = repo.get_device(local_device_id)
    profile = repo.get_device_protocol_profile_by_local_device_id(local_device_id)
    if profile is None:
        raise LookupError("protocol profile not found")
    plan = build_protocol_config_revoke_plan(
        repo, local_device_id=local_device_id
    )
    status = str(device["status"])
    remote_required = status in {"pending", "active"}
    if remote_required and not remote_already_removed and (
        not apply_remote or peer_remover is None
    ):
        raise CascadeRevokeApplyRequired(plan)

    remote_removed = remote_required and remote_already_removed
    if remote_required and not remote_already_removed:
        peer_remover.remove_peer(
            server=repo.get_server(int(device["server_id"])),
            peer_public_key=str(device["peer_public_key"]),
        )
        remote_removed = True

    protocol = ProtocolVersion(str(profile["protocol_version"]))
    passport_device_id = str(profile["passport_device_id"])
    device_rows_revoked = 0
    try:
        with repo.transaction():
            if status in {"pending", "active"}:
                if not repo.revoke_device(
                    local_device_id,
                    reason=normalized_reason,
                    revoked_at=_format_datetime(actual_revoked_at),
                ):
                    raise ValueError("protocol config changed concurrently")
                device_rows_revoked = 1
            if str(profile["lifecycle_state"]) != "revoked":
                changed = repo.transition_device_protocol_profile(
                    profile_id=int(profile["id"]),
                    expected_lifecycle_state=str(profile["lifecycle_state"]),
                    expected_local_device_id=local_device_id,
                    expected_replacement_device_id=(
                        int(profile["replacement_device_id"])
                        if profile["replacement_device_id"] is not None
                        else None
                    ),
                    lifecycle_state="revoked",
                    local_device_id=local_device_id,
                    replacement_device_id=None,
                )
                if not changed:
                    raise ValueError("protocol config changed concurrently")
                repo.append_protocol_config_event(
                    event_type="protocol_config_revoked",
                    actor_kind=actor_kind,
                    actor_id=actor_id,
                    reason=normalized_reason,
                    passport_device_id=passport_device_id,
                    protocol_version=protocol.value,
                    local_device_id=local_device_id,
                    metadata={
                        "profile_id": int(profile["id"]),
                        "lifecycle_state": "revoked",
                    },
                )
            result = ProtocolConfigRevokeResult(
                plan=plan,
                local_device_id=local_device_id,
                passport_device_id=passport_device_id,
                protocol_version=protocol,
                remote_peer_removed=remote_removed,
                device_rows_revoked=device_rows_revoked,
                profile_state="revoked",
                revoked_at=actual_revoked_at,
            )
            if audit_recorder is not None:
                audit_recorder(result.safe_metadata())
    except Exception as exc:
        if remote_removed:
            raise RemoteOperationPartialFailure(
                remote_changed_local_failed_result(
                    operation_id=plan.operation_id,
                    recovery_note=(
                        "Remote peer was removed but the selected config projection "
                        "failed. Keep it blocked and reconcile the local device and "
                        "protocol profile before replacement."
                    ),
                ),
                exc,
            ) from exc
        raise
    return result


def _format_datetime(value: datetime) -> str:
    return _as_utc(value).isoformat().replace("+00:00", "Z")


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
