from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol

from app.access_expiry import AccessExpiry, parse_access_expiry
from app.config_assignment import DEDICATED_DEVICE, RECIPIENT_UNASSIGNED
from app.db.repositories import Repository
from app.services.access import OperatorDeviceContext
from app.services.device_passports import validate_device_passport_context


MAX_MANIFEST_ITEMS = 100
MAX_EXPANDED_SLOTS = 100
MAX_LABEL_LENGTH = 120
_ROOT_FIELDS = frozenset({"request_id", "server", "expiry", "items"})
_ITEM_FIELDS = frozenset(
    {"mode", "recipient_label", "quantity", "device_label", "platform", "expiry"}
)


class OperatorAccessService(Protocol):
    def create_operator_device(self, **kwargs): ...


@dataclass(frozen=True)
class IssuanceManifestItem:
    assignment_mode: str
    recipient_label: str
    quantity: int
    device_label: str | None
    platform: str | None
    expiry: AccessExpiry


@dataclass(frozen=True)
class ExpandedIssuanceSlot:
    item_index: int
    recipient_label: str
    assignment_mode: str
    slot_sequence: int
    device_label: str
    platform: str | None
    expiry: AccessExpiry


@dataclass(frozen=True)
class ValidatedIssuanceManifest:
    request_id: str
    server: str
    expiry: AccessExpiry
    items: tuple[IssuanceManifestItem, ...]
    expanded_slots: tuple[ExpandedIssuanceSlot, ...]


@dataclass(frozen=True)
class AdminConfigIssuanceReceipt:
    receipt_id: int
    request_id: str
    item_index: int
    recipient_user_id: int | None
    device_id: int | None
    passport_device_id: str | None
    assignment_mode: str
    slot_sequence: int
    expiry_policy: str
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
            "assignment_mode": self.assignment_mode,
            "slot_sequence": self.slot_sequence,
            "expiry_policy": self.expiry_policy,
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
        duration_days: int | None = None,
        config_version: str = "amneziawg_v2",
        max_devices_per_recipient: int = 5,
    ) -> None:
        if admin_telegram_id <= 0:
            raise ValueError("admin_telegram_id must be positive")
        if duration_days is not None and duration_days <= 0:
            raise ValueError("duration_days must be positive")
        if max_devices_per_recipient <= 0:
            raise ValueError("max_devices_per_recipient must be positive")
        self._repo = repo
        self._access_service = access_service
        self._admin_telegram_id = admin_telegram_id
        self._attachment_builder = attachment_builder
        self._config_version = config_version
        self._max_devices_per_recipient = max_devices_per_recipient

    def issue_manifest(self, manifest: Mapping[str, object]) -> AdminConfigIssuanceResult:
        validated = validate_admin_config_issuance_manifest(manifest)
        server = self._repo.get_server_by_name(validated.server)
        request_fingerprint = _request_fingerprint(validated)
        existing_request = self._repo.get_admin_config_issuance_request(
            request_id=validated.request_id
        )
        if existing_request is not None:
            if (
                str(existing_request["request_fingerprint"]) != request_fingerprint
                or int(existing_request["item_count"]) != len(validated.expanded_slots)
            ):
                raise ValueError("manifest does not match existing request")
        else:
            self._admit_full_batch(validated.expanded_slots)
            self._repo.create_admin_config_issuance_request(
                request_id=validated.request_id,
                request_fingerprint=request_fingerprint,
                item_count=len(validated.expanded_slots),
            )

        receipts: list[AdminConfigIssuanceReceipt] = []
        for receipt_index, slot in enumerate(validated.expanded_slots):
            item_fingerprint = _slot_fingerprint(validated.server, slot)
            existing = self._repo.get_admin_config_issuance_receipt(
                request_id=validated.request_id,
                item_index=receipt_index,
            )
            if existing is not None:
                if str(existing["item_fingerprint"]) != item_fingerprint:
                    raise ValueError("manifest item does not match existing receipt")
                receipt = _receipt_from_row(existing)
                receipts.append(receipt)
                if receipt.status != "completed":
                    break
                continue

            recipient = self._repo.get_user_by_operator_label(slot.recipient_label)
            recipient_user_id = (
                self._repo.create_operator_recipient(operator_label=slot.recipient_label)
                if recipient is None
                else int(recipient["id"])
            )
            started_row = self._repo.create_admin_config_issuance_receipt(
                request_id=validated.request_id,
                item_index=receipt_index,
                item_fingerprint=item_fingerprint,
                recipient_user_id=recipient_user_id,
                assignment_mode=slot.assignment_mode,
                slot_sequence=slot.slot_sequence,
                expiry_policy=slot.expiry.policy,
            )
            device_id = None
            passport_device_id = None
            config_filename = None
            try:
                kwargs = {
                    "owner_user_id": recipient_user_id,
                    "server_id": int(server["id"]),
                    "device_name": slot.device_label,
                    "duration_days": None,
                    "expiry": slot.expiry,
                    "admin_telegram_id": self._admin_telegram_id,
                    "config_version": self._config_version,
                    "assignment_mode": slot.assignment_mode,
                }
                if slot.assignment_mode == DEDICATED_DEVICE:
                    kwargs["device_context"] = OperatorDeviceContext(
                        platform=str(slot.platform)
                    )
                created = self._access_service.create_operator_device(**kwargs)
                device_id = int(created.device_id)
                passport_device_id = created.passport_device_id
                config_filename = str(created.config_filename)
                if slot.assignment_mode == DEDICATED_DEVICE and not passport_device_id:
                    raise RuntimeError("device passport was not created")
                if slot.assignment_mode == RECIPIENT_UNASSIGNED and passport_device_id:
                    raise RuntimeError("unassigned slot unexpectedly created a passport")
                self._attachment_builder(config_filename, str(created.config_text))
                with self._repo.transaction():
                    self._repo.record_admin_action(
                        admin_telegram_id=self._admin_telegram_id,
                        action="admin_config.issue_manifest",
                        target_user_id=recipient_user_id,
                        target_device_id=device_id,
                        metadata={
                            "request_id": validated.request_id,
                            "item_index": receipt_index,
                            "receipt_id": int(started_row["id"]),
                            "assignment_mode": slot.assignment_mode,
                            "slot_sequence": slot.slot_sequence,
                            "expiry_policy": slot.expiry.policy,
                            "passport_device_id": passport_device_id,
                            "status": "completed",
                            "config_filename": config_filename,
                        },
                    )
                    row = self._repo.complete_admin_config_issuance_receipt(
                        request_id=validated.request_id,
                        item_index=receipt_index,
                        device_id=device_id,
                        passport_device_id=passport_device_id,
                        config_filename=config_filename,
                    )
            except Exception as exc:
                row = self._repo.fail_admin_config_issuance_receipt(
                    request_id=validated.request_id,
                    item_index=receipt_index,
                    error_code=_safe_error_code(exc),
                    device_id=device_id,
                    passport_device_id=passport_device_id,
                    config_filename=config_filename,
                )
                receipts.append(_receipt_from_row(row))
                break
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

    def _admit_full_batch(self, slots: tuple[ExpandedIssuanceSlot, ...]) -> None:
        requested = Counter(_duplicate_label_key(slot.recipient_label) for slot in slots)
        labels = {
            _duplicate_label_key(slot.recipient_label): slot.recipient_label for slot in slots
        }
        for key, count in requested.items():
            recipient = self._repo.get_user_by_operator_label(labels[key])
            active = 0 if recipient is None else self._repo.count_active_devices(int(recipient["id"]))
            if active + count > self._max_devices_per_recipient:
                raise ValueError("full-batch quota exceeded for recipient")


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
    root_expiry = parse_access_expiry(manifest.get("expiry"))
    raw_items = manifest.get("items")
    if not isinstance(raw_items, Sequence) or isinstance(raw_items, (str, bytes)):
        raise ValueError("manifest items must be a JSON array")
    if not 1 <= len(raw_items) <= MAX_MANIFEST_ITEMS:
        raise ValueError(f"manifest must contain 1 to {MAX_MANIFEST_ITEMS} items")

    items: list[IssuanceManifestItem] = []
    expanded: list[ExpandedIssuanceSlot] = []
    seen: set[tuple[str, str]] = set()
    for source_index, raw_item in enumerate(raw_items):
        if not isinstance(raw_item, Mapping):
            raise ValueError(f"manifest item {source_index} must be a JSON object")
        unsupported = set(raw_item) - _ITEM_FIELDS
        if unsupported:
            raise ValueError(
                f"manifest item {source_index} has unsupported fields: {sorted(unsupported)}"
            )
        recipient_label = _required_bounded_text(raw_item, "recipient_label")
        mode_value = raw_item.get("mode", DEDICATED_DEVICE)
        if mode_value not in {DEDICATED_DEVICE, RECIPIENT_UNASSIGNED}:
            raise ValueError(f"manifest item {source_index} has unsupported mode")
        mode = str(mode_value)
        expiry = (
            parse_access_expiry(raw_item["expiry"])
            if "expiry" in raw_item
            else root_expiry
        )
        if mode == RECIPIENT_UNASSIGNED:
            forbidden = {"device_label", "platform"} & set(raw_item)
            if forbidden:
                raise ValueError("recipient_unassigned cannot include device fields")
            quantity = raw_item.get("quantity")
            if isinstance(quantity, bool) or not isinstance(quantity, int) or not 1 <= quantity <= 100:
                raise ValueError("quantity must be an integer between 1 and 100")
            device_label = None
            platform = None
            duplicate_key = (_duplicate_label_key(recipient_label), mode)
        else:
            if "quantity" in raw_item:
                raise ValueError("dedicated_device cannot include quantity")
            quantity = 1
            device_label = _required_bounded_text(raw_item, "device_label")
            platform = _required_bounded_text(raw_item, "platform").lower()
            validate_device_passport_context(
                platform=platform,
                official_client_type="amnezia_vpn",
                import_method="conf_file",
                config_schema_version="amneziawg_v2",
            )
            duplicate_key = (
                _duplicate_label_key(recipient_label),
                _duplicate_label_key(device_label),
            )
        if duplicate_key in seen:
            raise ValueError("manifest contains duplicate recipient/device labels")
        seen.add(duplicate_key)
        item = IssuanceManifestItem(
            assignment_mode=mode,
            recipient_label=recipient_label,
            quantity=quantity,
            device_label=device_label,
            platform=platform,
            expiry=expiry,
        )
        items.append(item)
        for ordinal in range(1, quantity + 1):
            expanded.append(
                ExpandedIssuanceSlot(
                    item_index=source_index,
                    recipient_label=recipient_label,
                    assignment_mode=mode,
                    slot_sequence=ordinal,
                    device_label=(f"{ordinal:02d}" if mode == RECIPIENT_UNASSIGNED else str(device_label)),
                    platform=platform,
                    expiry=expiry,
                )
            )
    if len(expanded) > MAX_EXPANDED_SLOTS:
        raise ValueError(f"expanded manifest cannot exceed {MAX_EXPANDED_SLOTS} slots")
    return ValidatedIssuanceManifest(
        request_id=request_id,
        server=server,
        expiry=root_expiry,
        items=tuple(items),
        expanded_slots=tuple(expanded),
    )


def _required_bounded_text(values: Mapping[str, object], key: str) -> str:
    value = values.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{key} must be a non-blank string")
    normalized = value.strip()
    if len(normalized) > MAX_LABEL_LENGTH:
        raise ValueError(f"{key} must be at most {MAX_LABEL_LENGTH} characters")
    return normalized


def _duplicate_label_key(value: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", value).split()).casefold()


def _safe_error_code(exc: Exception) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", type(exc).__name__).lower()[:80]


def _expiry_dict(expiry: AccessExpiry) -> dict[str, object]:
    return {
        "policy": expiry.policy,
        "duration_days": expiry.duration_days,
        "expires_at": expiry.expires_at,
    }


def _slot_dict(slot: ExpandedIssuanceSlot) -> dict[str, object]:
    return {
        "source_item_index": slot.item_index,
        "recipient_label": slot.recipient_label,
        "assignment_mode": slot.assignment_mode,
        "slot_sequence": slot.slot_sequence,
        "device_label": slot.device_label,
        "platform": slot.platform,
        "expiry": _expiry_dict(slot.expiry),
    }


def _slot_fingerprint(server: str, slot: ExpandedIssuanceSlot) -> str:
    canonical = json.dumps(
        {"server": server, **_slot_dict(slot)},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


def _request_fingerprint(manifest: ValidatedIssuanceManifest) -> str:
    canonical = json.dumps(
        {
            "server": manifest.server,
            "expanded_slot_count": len(manifest.expanded_slots),
            "slots": [_slot_dict(slot) for slot in manifest.expanded_slots],
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
        recipient_user_id=(int(row["recipient_user_id"]) if row["recipient_user_id"] is not None else None),
        device_id=int(row["device_id"]) if row["device_id"] is not None else None,
        passport_device_id=(str(row["passport_device_id"]) if row["passport_device_id"] is not None else None),
        assignment_mode=str(row["assignment_mode"]),
        slot_sequence=int(row["slot_sequence"]),
        expiry_policy=str(row["expiry_policy"]),
        status=str(row["status"]),
        config_filename=(str(row["config_filename"]) if row["config_filename"] is not None else None),
        error_code=str(row["error_code"]) if row["error_code"] is not None else None,
        created_at=str(row["created_at"]),
        updated_at=str(row["updated_at"]),
    )
