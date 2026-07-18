from __future__ import annotations

from typing import Any

from app.db.repositories import Repository
from app.services.device_lifecycle import list_device_lifecycle_events
from app.services.device_passports import (
    DevicePassport,
    get_device_passport,
    list_all_device_passports,
)


def build_device_passport_list_view(
    repo: Repository,
    *,
    limit: int = 100,
) -> dict[str, object]:
    items = [
        _list_item(repo, passport)
        for passport in list_all_device_passports(repo, limit=limit)
    ]
    return {"items": items, "count": len(items), "limit": limit}


def build_device_passport_detail_view(
    repo: Repository,
    device_id: str,
) -> dict[str, object]:
    passport = get_device_passport(repo, device_id)
    owner = _owner_view(repo, passport.owner_user_id)
    lifecycle = [
        event.safe_metadata()
        for event in list_device_lifecycle_events(
            repo,
            passport_device_id=passport.device_id,
        )
    ]
    return {
        "owner": owner,
        "passport": passport.safe_metadata(),
        "state": "revoked" if passport.revoked_at is not None else "active",
        "acceptance_status": (
            passport.acceptance_evidence.status
            if passport.acceptance_evidence is not None
            else "pending"
        ),
        "lifecycle": lifecycle,
    }


def _list_item(repo: Repository, passport: DevicePassport) -> dict[str, Any]:
    lifecycle = list_device_lifecycle_events(
        repo,
        passport_device_id=passport.device_id,
    )
    metadata = passport.safe_metadata()
    return {
        "device_id": passport.device_id,
        "owner": _owner_view(repo, passport.owner_user_id),
        "local_device_id": passport.local_device_id,
        "platform": passport.platform,
        "official_client_type": passport.official_client_type,
        "client_version": passport.client_version,
        "state": "revoked" if passport.revoked_at is not None else "active",
        "acceptance_status": (
            passport.acceptance_evidence.status
            if passport.acceptance_evidence is not None
            else "pending"
        ),
        "drift_state": passport.reconciliation.drift_state,
        "last_seen_at": metadata["last_seen_at"],
        "last_observed_at": metadata["last_observed_at"],
        "updated_at": metadata["updated_at"],
        "lifecycle_completed": [
            event.stage
            for event in lifecycle
            if event.status == "completed"
        ],
    }


def _owner_view(repo: Repository, owner_user_id: int) -> dict[str, object]:
    row = repo.get_user(owner_user_id)
    if row is None:
        raise LookupError("device passport owner not found")
    display = str(row["username"] or "").strip()
    if not display:
        display = " ".join(
            part
            for part in (
                str(row["first_name"] or "").strip(),
                str(row["last_name"] or "").strip(),
            )
            if part
        )
    if not display:
        display = str(row["telegram_id"])
    return {"id": owner_user_id, "display": display}
