from __future__ import annotations

import hashlib
import json

from app.db.repositories import Repository
from app.services.access import OperatorDeviceContext
from app.services.config_identity import build_config_identity
from app.services.device_passports import (
    DevicePassport,
    create_device_passport,
    get_device_passport,
)


def assign_access_slot(
    repo: Repository,
    *,
    request_id: str,
    local_device_id: int,
    device_label: str,
    context: OperatorDeviceContext,
    admin_telegram_id: int,
) -> DevicePassport:
    normalized_request_id = request_id.strip()
    normalized_label = device_label.strip()
    if not normalized_request_id or len(normalized_request_id) > 120:
        raise ValueError("request_id is invalid")
    if not normalized_label or len(normalized_label) > 120:
        raise ValueError("device_label is invalid")
    if admin_telegram_id <= 0:
        raise ValueError("admin_telegram_id must be positive")
    fingerprint = _request_fingerprint(
        local_device_id=local_device_id,
        device_label=normalized_label,
        context=context,
    )
    existing_request = repo.get_access_slot_assignment_request(normalized_request_id)
    if existing_request is not None:
        if str(existing_request["request_fingerprint"]) != fingerprint:
            raise ValueError("assignment request does not match existing request")
        return get_device_passport(repo, str(existing_request["passport_device_id"]))
    if repo.get_access_slot_assignment_by_device(local_device_id) is not None:
        raise ValueError("access slot is already assigned")

    device = repo.get_device(local_device_id)
    if str(device["assignment_mode"]) != "recipient_unassigned":
        raise ValueError("access slot is already assigned")
    if str(device["status"]) == "revoked":
        raise ValueError("revoked access slot cannot be assigned")
    config_fingerprint = device["config_fingerprint"]
    if config_fingerprint is None:
        raise ValueError("access slot has no stored config fingerprint")
    owner = repo.get_user(int(device["user_id"]))
    owner_label = str(
        owner["operator_label"]
        or owner["username"]
        or owner["first_name"]
        or f"user-{int(owner['id'])}"
    )
    identity = build_config_identity(owner_label, normalized_label)

    with repo.transaction():
        passport = create_device_passport(
            repo,
            owner_user_id=int(device["user_id"]),
            local_device_id=local_device_id,
            platform=context.platform,
            official_client_type=context.official_client_type,
            client_version=context.client_version,
            import_method=context.import_method,
            config_schema_version=str(device["config_version"]),
            config_fingerprint=str(config_fingerprint),
        )
        repo.complete_access_slot_assignment(
            request_id=normalized_request_id,
            request_fingerprint=fingerprint,
            local_device_id=local_device_id,
            passport_device_id=passport.device_id,
            display_name=identity.display_name,
        )
        repo.record_admin_action(
            admin_telegram_id=admin_telegram_id,
            action="access_slot.assign",
            target_user_id=int(device["user_id"]),
            target_device_id=local_device_id,
            metadata={
                "request_id": normalized_request_id,
                "passport_device_id": passport.device_id,
                "assignment_mode": "dedicated_device",
            },
        )
    return passport


def _request_fingerprint(
    *,
    local_device_id: int,
    device_label: str,
    context: OperatorDeviceContext,
) -> str:
    canonical = json.dumps(
        {
            "local_device_id": local_device_id,
            "device_label": device_label,
            "platform": context.platform,
            "official_client_type": context.official_client_type,
            "client_version": context.client_version,
            "import_method": context.import_method,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return f"sha256:{hashlib.sha256(canonical.encode()).hexdigest()}"
