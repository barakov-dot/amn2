from __future__ import annotations

from typing import Any

from app.db.repositories import Repository, user_display_label
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
        "protocol_cards": _protocol_cards(repo, passport),
    }


def _protocol_cards(
    repo: Repository,
    passport: DevicePassport,
) -> list[dict[str, object]]:
    cards: list[dict[str, object]] = []
    for profile in passport.protocol_profiles:
        device = repo.get_device(profile.local_device_id)
        attempts = repo.list_protocol_issuance_attempts(
            passport_device_id=passport.device_id,
            protocol_version=profile.protocol_version.value,
        )
        issuance = next(
            (
                row
                for row in reversed(attempts)
                if str(row["state"]) == "completed"
                and row["local_device_id"] is not None
                and int(row["local_device_id"]) == profile.local_device_id
            ),
            None,
        )
        cards.append(
            {
                "profile_id": profile.profile_id,
                "protocol_version": profile.protocol_version.value,
                "local_device_id": profile.local_device_id,
                "runtime_instance_id": (
                    str(device["runtime_instance_id"])
                    if device["runtime_instance_id"] is not None
                    else None
                ),
                "client_application": (
                    str(issuance["client_application"])
                    if issuance is not None
                    else passport.official_client_type
                ),
                "client_platform": (
                    str(issuance["client_platform"])
                    if issuance is not None
                    else passport.platform
                ),
                "client_version": (
                    str(issuance["client_version"])
                    if issuance is not None
                    else passport.client_version
                ),
                "client_build": (
                    str(issuance["client_build"])
                    if issuance is not None and issuance["client_build"] is not None
                    else None
                ),
                "lifecycle_state": profile.lifecycle_state,
                "compatibility_evidence_id": (
                    str(device["compatibility_evidence_id"])
                    if device["compatibility_evidence_id"] is not None
                    else None
                ),
                "client_identity_evidence_status": (
                    str(device["client_identity_evidence_status"])
                    if device["client_identity_evidence_status"] is not None
                    else "unknown"
                ),
            }
        )
    return cards


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
    return {"id": owner_user_id, "display": user_display_label(row)}
