from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from app.db.repositories import Repository
from app.services.access import OperatorDeviceContext
from app.services.device_passports import validate_device_passport_context


MAX_MANIFEST_ITEMS = 100
MAX_LABEL_LENGTH = 120
_ROOT_FIELDS = frozenset({"request_id", "server", "items"})
_ITEM_FIELDS = frozenset({"recipient_label", "device_label", "platform"})


class OperatorAccessService(Protocol):
    def create_operator_device(self, **kwargs): ...


@dataclass(frozen=True)
class IssuanceManifestItem:
    recipient_label: str
    device_label: str
    platform: str


@dataclass(frozen=True)
class ValidatedIssuanceManifest:
    request_id: str
    server: str
    items: tuple[IssuanceManifestItem, ...]


@dataclass(frozen=True)
class AdminConfigIssuanceReceipt:
    receipt_id: int
    request_id: str
    item_index: int
    recipient_user_id: int | None
    device_id: int | None
    passport_device_id: str | None
    status: str
    config_filename: str | None
    error_code: str | None
    created_at: str
    updated_at: str

    def to_safe_dict(self) -> dict[str, object]:
        return {
            "receipt_id": self.receipt_id,
            "request_id": self.request_id,
            "item_index": self.item_index,
            "recipient_user_id": self.recipient_user_id,
            "device_id": self.device_id,
            "passport_device_id": self.passport_device_id,
            "status": self.status,
            "config_filename": self.config_filename,
            "error_code": self.error_code,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass(frozen=True)
class AdminConfigIssuanceResult:
    request_id: str
    server: str
    status: str
    receipts: tuple[AdminConfigIssuanceReceipt, ...]

    def to_safe_dict(self) -> dict[str, object]:
        return {
            "request_id": self.request_id,
            "server": self.server,
            "status": self.status,
            "receipts": [receipt.to_safe_dict() for receipt in self.receipts],
        }


class AdminConfigIssuanceService:
    def __init__(
        self,
        *,
        repo: Repository,
        access_service: OperatorAccessService,
        admin_telegram_id: int,
        attachment_builder: Callable[[str, str], object],
        duration_days: int = 30,
        config_version: str = "amneziawg_v2",
    ) -> None:
        if admin_telegram_id <= 0:
            raise ValueError("admin_telegram_id must be positive")
        if duration_days <= 0:
            raise ValueError("duration_days must be positive")
        self._repo = repo
        self._access_service = access_service
        self._admin_telegram_id = admin_telegram_id
        self._attachment_builder = attachment_builder
        self._duration_days = duration_days
        self._config_version = config_version

    def issue_manifest(
        self,
        manifest: Mapping[str, object],
    ) -> AdminConfigIssuanceResult:
        validated = validate_admin_config_issuance_manifest(manifest)
        server = self._repo.get_server_by_name(validated.server)
        request_fingerprint = _request_fingerprint(validated)
        existing_request = self._repo.get_admin_config_issuance_request(
            request_id=validated.request_id
        )
        if existing_request is None:
            self._repo.create_admin_config_issuance_request(
                request_id=validated.request_id,
                request_fingerprint=request_fingerprint,
                item_count=len(validated.items),
            )
        elif (
            str(existing_request["request_fingerprint"]) != request_fingerprint
            or int(existing_request["item_count"]) != len(validated.items)
        ):
            raise ValueError("manifest does not match existing request")
        receipts: list[AdminConfigIssuanceReceipt] = []

        for item_index, item in enumerate(validated.items):
            item_fingerprint = _item_fingerprint(validated.server, item)
            existing = self._repo.get_admin_config_issuance_receipt(
                request_id=validated.request_id,
                item_index=item_index,
            )
            if existing is not None:
                if str(existing["item_fingerprint"]) != item_fingerprint:
                    raise ValueError(
                        "manifest item does not match existing receipt"
                    )
                receipt = _receipt_from_row(existing)
                receipts.append(receipt)
                if receipt.status != "completed":
                    break
                continue

            recipient = self._repo.get_user_by_operator_label(item.recipient_label)
            if recipient is None:
                recipient_user_id = self._repo.create_operator_recipient(
                    operator_label=item.recipient_label
                )
            else:
                recipient_user_id = int(recipient["id"])

            started_row = self._repo.create_admin_config_issuance_receipt(
                request_id=validated.request_id,
                item_index=item_index,
                item_fingerprint=item_fingerprint,
                recipient_user_id=recipient_user_id,
            )
            device_id = None
            passport_device_id = None
            config_filename = None
            try:
                created = self._access_service.create_operator_device(
                    owner_user_id=recipient_user_id,
                    server_id=int(server["id"]),
                    device_name=item.device_label,
                    duration_days=self._duration_days,
                    admin_telegram_id=self._admin_telegram_id,
                    config_version=self._config_version,
                    device_context=OperatorDeviceContext(platform=item.platform),
                )
                device_id = int(created.device_id)
                config_filename = str(created.config_filename)
                passport = self._repo.get_device_passport_by_local_device_id(device_id)
                if passport is None:
                    raise RuntimeError("device passport was not created")
                passport_device_id = str(passport["device_id"])
                self._attachment_builder(config_filename, str(created.config_text))
                with self._repo.transaction():
                    self._repo.record_admin_action(
                        admin_telegram_id=self._admin_telegram_id,
                        action="admin_config.issue_manifest",
                        target_user_id=recipient_user_id,
                        target_device_id=device_id,
                        metadata={
                            "request_id": validated.request_id,
                            "item_index": item_index,
                            "receipt_id": int(started_row["id"]),
                            "passport_device_id": passport_device_id,
                            "status": "completed",
                            "config_filename": config_filename,
                        },
                    )
                    row = self._repo.complete_admin_config_issuance_receipt(
                        request_id=validated.request_id,
                        item_index=item_index,
                        device_id=device_id,
                        passport_device_id=passport_device_id,
                        config_filename=config_filename,
                    )
            except Exception as exc:
                row = self._repo.fail_admin_config_issuance_receipt(
                    request_id=validated.request_id,
                    item_index=item_index,
                    error_code=_safe_error_code(exc),
                    device_id=device_id,
                    passport_device_id=passport_device_id,
                    config_filename=config_filename,
                )
                receipts.append(_receipt_from_row(row))
                break
            else:
                receipts.append(_receipt_from_row(row))

        status = "completed"
        if receipts and receipts[-1].status != "completed":
            status = "partial_failure"
        return AdminConfigIssuanceResult(
            request_id=validated.request_id,
            server=validated.server,
            status=status,
            receipts=tuple(receipts),
        )


def validate_admin_config_issuance_manifest(
    manifest: Mapping[str, object],
) -> ValidatedIssuanceManifest:
    if not isinstance(manifest, Mapping):
        raise ValueError("manifest must be a JSON object")
    unsupported = set(manifest) - _ROOT_FIELDS
    if unsupported:
        raise ValueError(f"manifest has unsupported fields: {sorted(unsupported)}")
    request_id = _required_bounded_text(manifest, "request_id")
    server = _required_bounded_text(manifest, "server")
    raw_items = manifest.get("items")
    if not isinstance(raw_items, Sequence) or isinstance(raw_items, (str, bytes)):
        raise ValueError("manifest items must be a JSON array")
    if not 1 <= len(raw_items) <= MAX_MANIFEST_ITEMS:
        raise ValueError(f"manifest must contain 1 to {MAX_MANIFEST_ITEMS} items")

    items = []
    for item_index, raw_item in enumerate(raw_items):
        if not isinstance(raw_item, Mapping):
            raise ValueError(f"manifest item {item_index} must be a JSON object")
        unsupported = set(raw_item) - _ITEM_FIELDS
        if unsupported:
            raise ValueError(
                f"manifest item {item_index} has unsupported fields: "
                f"{sorted(unsupported)}"
            )
        platform = _required_bounded_text(raw_item, "platform").lower()
        validate_device_passport_context(
            platform=platform,
            official_client_type="amnezia_vpn",
            import_method="conf_file",
            config_schema_version="amneziawg_v2",
        )
        items.append(
            IssuanceManifestItem(
                recipient_label=_required_bounded_text(raw_item, "recipient_label"),
                device_label=_required_bounded_text(raw_item, "device_label"),
                platform=platform,
            )
        )
    return ValidatedIssuanceManifest(
        request_id=request_id,
        server=server,
        items=tuple(items),
    )


def _required_bounded_text(values: Mapping[str, object], key: str) -> str:
    value = values.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{key} must be a non-blank string")
    normalized = value.strip()
    if len(normalized) > MAX_LABEL_LENGTH:
        raise ValueError(f"{key} must be at most {MAX_LABEL_LENGTH} characters")
    return normalized


def _safe_error_code(exc: Exception) -> str:
    name = type(exc).__name__
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()[:80]


def _item_fingerprint(server: str, item: IssuanceManifestItem) -> str:
    canonical = json.dumps(
        {
            "server": server,
            "recipient_label": item.recipient_label,
            "device_label": item.device_label,
            "platform": item.platform,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


def _request_fingerprint(manifest: ValidatedIssuanceManifest) -> str:
    canonical = json.dumps(
        {
            "server": manifest.server,
            "item_count": len(manifest.items),
            "items": [
                {
                    "recipient_label": item.recipient_label,
                    "device_label": item.device_label,
                    "platform": item.platform,
                }
                for item in manifest.items
            ],
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


def _receipt_from_row(row) -> AdminConfigIssuanceReceipt:
    return AdminConfigIssuanceReceipt(
        receipt_id=int(row["id"]),
        request_id=str(row["request_id"]),
        item_index=int(row["item_index"]),
        recipient_user_id=(
            int(row["recipient_user_id"])
            if row["recipient_user_id"] is not None
            else None
        ),
        device_id=int(row["device_id"]) if row["device_id"] is not None else None,
        passport_device_id=(
            str(row["passport_device_id"])
            if row["passport_device_id"] is not None
            else None
        ),
        status=str(row["status"]),
        config_filename=(
            str(row["config_filename"])
            if row["config_filename"] is not None
            else None
        ),
        error_code=str(row["error_code"]) if row["error_code"] is not None else None,
        created_at=str(row["created_at"]),
        updated_at=str(row["updated_at"]),
    )
