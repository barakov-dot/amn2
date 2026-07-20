from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol

from app.db.repositories import Repository
from app.server.operations import OperationPlan, remote_changed_local_failed_result
from app.services.access import RemoteOperationPartialFailure
from app.services.device_revoke import cascade_revoke_physical_device


class PeerRemover(Protocol):
    def remove_peer(self, *, server, peer_public_key: str) -> None: ...


class AccessSlotApplyRequired(ValueError):
    def __init__(self, plan: OperationPlan) -> None:
        super().__init__("access slot mutation requires remote-first apply")
        self.plan = plan


@dataclass(frozen=True)
class AccessSlotLifecycleResult:
    plan: OperationPlan
    local_device_id: int
    status: str
    remote_peer_removed: bool
    changed_at: datetime

    def safe_metadata(self) -> dict[str, object]:
        return {
            "operation_plan": self.plan.to_safe_metadata(),
            "local_device_id": self.local_device_id,
            "status": self.status,
            "remote_peer_removed": self.remote_peer_removed,
            "changed_at": _format_datetime(self.changed_at),
        }


def build_access_slot_disable_plan(
    repo: Repository, *, local_device_id: int
) -> OperationPlan:
    device = repo.get_device(local_device_id)
    remote_required = str(device["status"]) in {"pending", "active"}
    return OperationPlan(
        operation_id="access_slot.disable",
        risk_class="remote-state-write" if remote_required else "state-write",
        consistency_status="dry-run",
        commands=("remove configured remote peer",) if remote_required else (),
        audit_summary="Disable one access slot with remote-first ordering",
        rollback_note="Re-enable requires an explicit peer apply and local status update.",
        local_side_effects=("disable-single-access-slot",),
        remote_side_effects=("awg-peer-remove",) if remote_required else (),
        idempotency_key=f"access-slot-disable:{local_device_id}",
    )


def disable_access_slot(
    repo: Repository,
    *,
    local_device_id: int,
    reason: str,
    changed_at: datetime,
    peer_remover: PeerRemover | None,
    apply_remote: bool,
    admin_telegram_id: int,
) -> AccessSlotLifecycleResult:
    normalized_reason = _validate_reason(reason)
    actual_changed_at = _as_utc(changed_at)
    device = repo.get_device(local_device_id)
    plan = build_access_slot_disable_plan(repo, local_device_id=local_device_id)
    status = str(device["status"])
    remote_required = status in {"pending", "active"}
    if remote_required and (not apply_remote or peer_remover is None):
        raise AccessSlotApplyRequired(plan)
    remote_removed = False
    if remote_required:
        peer_remover.remove_peer(
            server=repo.get_server(int(device["server_id"])),
            peer_public_key=str(device["peer_public_key"]),
        )
        remote_removed = True
    try:
        with repo.transaction():
            if status != "disabled":
                if not repo.disable_device(
                    local_device_id,
                    reason=normalized_reason,
                    disabled_at=_format_datetime(actual_changed_at),
                ):
                    raise ValueError("access slot cannot be disabled from current status")
            repo.record_admin_action(
                admin_telegram_id=admin_telegram_id,
                action="access_slot.disable",
                target_user_id=int(device["user_id"]),
                target_device_id=local_device_id,
                metadata={
                    "remote_peer_removed": remote_removed,
                    "status": "disabled",
                },
            )
    except Exception as exc:
        if remote_removed:
            raise RemoteOperationPartialFailure(
                remote_changed_local_failed_result(
                    operation_id=plan.operation_id,
                    recovery_note=(
                        "Remote peer was removed but local disable failed; keep the "
                        "slot blocked and reconcile before any re-enable."
                    ),
                ),
                exc,
            ) from exc
        raise
    return AccessSlotLifecycleResult(
        plan=plan,
        local_device_id=local_device_id,
        status="disabled",
        remote_peer_removed=remote_removed,
        changed_at=actual_changed_at,
    )


def revoke_access_slot(
    repo: Repository,
    *,
    local_device_id: int,
    reason: str,
    changed_at: datetime,
    peer_remover: PeerRemover | None,
    apply_remote: bool,
    admin_telegram_id: int,
) -> AccessSlotLifecycleResult:
    device = repo.get_device(local_device_id)
    cascade = cascade_revoke_physical_device(
        repo,
        local_device_id=local_device_id,
        reason=_validate_reason(reason),
        revoked_at=_as_utc(changed_at),
        peer_remover=peer_remover,
        apply_remote=apply_remote,
        audit_recorder=lambda metadata: repo.record_admin_action(
            admin_telegram_id=admin_telegram_id,
            action="access_slot.revoke",
            target_user_id=int(device["user_id"]),
            target_device_id=local_device_id,
            metadata=metadata,
        ),
    )
    return AccessSlotLifecycleResult(
        plan=cascade.plan,
        local_device_id=local_device_id,
        status="revoked",
        remote_peer_removed=cascade.remote_peer_removed,
        changed_at=_as_utc(changed_at),
    )


def _validate_reason(value: str) -> str:
    normalized = " ".join(value.split())
    if not normalized or len(normalized) > 200:
        raise ValueError("reason is invalid")
    return normalized


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("changed_at must include timezone")
    return value.astimezone(timezone.utc)


def _format_datetime(value: datetime) -> str:
    return _as_utc(value).isoformat().replace("+00:00", "Z")
