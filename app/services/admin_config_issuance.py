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
from app.db.repositories import ProtocolIssuanceExecutionBlocked, Repository
from app.services.access import OperatorDeviceContext
from app.services.device_passports import (
    generate_device_passport_id,
    validate_device_passport_context,
)
from app.services.dual_protocol_profiles import DualProtocolProfileService
from app.services.config_identity import (
    build_config_identity,
    build_unassigned_slot_identity,
)
from app.services.client_compatibility import ClientIdentity
from app.services.protocol_admission import (
    AdmissionRequest,
    AdmissionResult,
    ProtocolAdmissionService,
)
from app.vpn.protocol_versions import (
    ProtocolVersion,
    config_version_for_protocol,
    normalize_protocol_version,
)


MAX_MANIFEST_ITEMS = 100
MAX_EXPANDED_SLOTS = 100
MAX_LABEL_LENGTH = 120
_ROOT_FIELDS = frozenset({"request_id", "server", "expiry", "items"})
_ITEM_FIELDS = frozenset(
    {
        "mode",
        "quantity",
        "recipient_label",
        "device_label",
        "client_application",
        "client_platform",
        "client_version",
        "client_build",
        "protocol_version",
        "expiry",
    }
)


class OperatorAccessService(Protocol):
    def create_operator_device(self, **kwargs): ...


@dataclass(frozen=True)
class IssuanceManifestItem:
    assignment_mode: str
    recipient_label: str
    quantity: int
    device_label: str
    client_application: str
    client_platform: str
    client_version: str
    client_build: str | None
    protocol_version: ProtocolVersion
    expiry: AccessExpiry


@dataclass(frozen=True)
class ExpandedIssuanceSlot:
    item_index: int
    recipient_label: str
    assignment_mode: str
    slot_sequence: int
    device_label: str
    client_application: str
    client_platform: str
    client_version: str
    client_build: str | None
    protocol_version: ProtocolVersion
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
    config_version: str | None
    protocol_version: str | None
    runtime_instance_id: str | None
    compatibility_evidence_id: str | None
    client_application: str | None
    client_platform: str | None
    client_version: str | None
    client_build: str | None
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
            "config_version": self.config_version,
            "protocol_version": self.protocol_version,
            "runtime_instance_id": self.runtime_instance_id,
            "compatibility_evidence_id": self.compatibility_evidence_id,
            "client_application": self.client_application,
            "client_platform": self.client_platform,
            "client_version": self.client_version,
            "client_build": self.client_build,
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


@dataclass(frozen=True)
class _Awg3ExecutionPreparation:
    admission: AdmissionResult
    intended_passport_device_id: str
    attempt_id: int
    execution_lease: object
    started_row: object


class AdminConfigIssuanceService:
    def __init__(
        self,
        *,
        repo: Repository,
        access_service: OperatorAccessService,
        admission_service: ProtocolAdmissionService,
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
        self._admission = admission_service
        self._admin_telegram_id = admin_telegram_id
        self._attachment_builder = attachment_builder
        self._config_version = config_version
        self._max_devices_per_recipient = max_devices_per_recipient

    def issue_manifest(self, manifest: Mapping[str, object]) -> AdminConfigIssuanceResult:
        validated = validate_admin_config_issuance_manifest(manifest)
        server = self._repo.get_server_by_name(validated.server)
        admissions = self._admit_protocol_batch(validated.expanded_slots)
        request_fingerprint = _request_fingerprint(validated, admissions)
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
        for receipt_index, (slot, admission) in enumerate(
            zip(validated.expanded_slots, admissions, strict=True)
        ):
            recipient = self._repo.get_user_by_operator_label(slot.recipient_label)
            recipient_user_id = (
                self._repo.create_operator_recipient(operator_label=slot.recipient_label)
                if recipient is None
                else int(recipient["id"])
            )
            if slot.protocol_version is ProtocolVersion.AWG3:
                row = self._issue_awg3_slot(
                    validated=validated,
                    server=server,
                    slot=slot,
                    recipient_user_id=recipient_user_id,
                    receipt_index=receipt_index,
                )
                receipts.append(_receipt_from_row(row, client_build=slot.client_build))
                if str(row["status"]) != "completed":
                    break
                continue

            item_fingerprint = _slot_fingerprint(validated.server, slot, admission)
            existing = self._repo.get_admin_config_issuance_receipt(
                request_id=validated.request_id,
                item_index=receipt_index,
            )
            if existing is not None:
                if str(existing["item_fingerprint"]) != item_fingerprint:
                    raise ValueError("manifest item does not match existing receipt")
                receipt = _receipt_from_row(existing, client_build=slot.client_build)
                receipts.append(receipt)
                if receipt.status != "completed":
                    break
                continue
            started_row = self._repo.create_admin_config_issuance_receipt(
                request_id=validated.request_id,
                item_index=receipt_index,
                item_fingerprint=item_fingerprint,
                recipient_user_id=recipient_user_id,
                assignment_mode=slot.assignment_mode,
                slot_sequence=slot.slot_sequence,
                expiry_policy=slot.expiry.policy,
                config_version=config_version_for_protocol(slot.protocol_version),
                protocol_version=slot.protocol_version.value,
                runtime_instance_id=admission.runtime_instance_id,
                compatibility_evidence_id=admission.compatibility_evidence_id,
                client_application=slot.client_application,
                client_platform=slot.client_platform,
                client_version=slot.client_version,
                client_build=slot.client_build,
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
                    "config_version": config_version_for_protocol(slot.protocol_version),
                    "assignment_mode": slot.assignment_mode,
                }
                if slot.assignment_mode == DEDICATED_DEVICE:
                    kwargs["device_context"] = OperatorDeviceContext(
                        platform=slot.client_platform,
                        official_client_type=slot.client_application,
                        client_version=slot.client_version,
                        protocol_version=slot.protocol_version.value,
                        runtime_instance_id=admission.runtime_instance_id,
                        client_identity_evidence_status="verified",
                        compatibility_evidence_id=admission.compatibility_evidence_id,
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
                            "config_version": config_version_for_protocol(
                                slot.protocol_version
                            ),
                            "protocol_version": slot.protocol_version.value,
                            "runtime_instance_id": admission.runtime_instance_id,
                            "compatibility_evidence_id": admission.compatibility_evidence_id,
                            "client_application": slot.client_application,
                            "client_platform": slot.client_platform,
                            "client_version": slot.client_version,
                            "client_build": slot.client_build,
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
                receipts.append(_receipt_from_row(row, client_build=slot.client_build))
                break
            receipts.append(_receipt_from_row(row, client_build=slot.client_build))

        status = "completed"
        if receipts and receipts[-1].status != "completed":
            status = "partial_failure"
        return AdminConfigIssuanceResult(
            request_id=validated.request_id,
            server=validated.server,
            status=status,
            receipts=tuple(receipts),
        )

    def _issue_awg3_slot(
        self,
        *,
        validated: ValidatedIssuanceManifest,
        server,
        slot: ExpandedIssuanceSlot,
        recipient_user_id: int,
        receipt_index: int,
    ):
        row, prepared = self._prepare_awg3_execution_marker(
            validated=validated,
            slot=slot,
            recipient_user_id=recipient_user_id,
            receipt_index=receipt_index,
        )
        if row is not None:
            return row
        assert prepared is not None
        failure: Exception | None = None
        row = None
        try:
            with self._repo.transaction():
                self._repo.bind_protocol_issuance_execution_lease(
                    prepared.attempt_id,
                    prepared.execution_lease,
                )
                device_id = None
                passport_device_id = None
                config_filename = None
                try:
                    created = self._access_service.create_operator_device(
                        owner_user_id=recipient_user_id,
                        server_id=int(server["id"]),
                        device_name=slot.device_label,
                        duration_days=None,
                        expiry=slot.expiry,
                        admin_telegram_id=self._admin_telegram_id,
                        config_version=config_version_for_protocol(
                            slot.protocol_version
                        ),
                        assignment_mode=slot.assignment_mode,
                        passport_device_id=prepared.intended_passport_device_id,
                        device_context=OperatorDeviceContext(
                            platform=slot.client_platform,
                            official_client_type=slot.client_application,
                            client_version=slot.client_version,
                            protocol_version="awg3",
                            runtime_instance_id=prepared.admission.runtime_instance_id,
                            client_identity_evidence_status="verified",
                            compatibility_evidence_id=(
                                prepared.admission.compatibility_evidence_id
                            ),
                        ),
                    )
                    device_id = int(created.device_id)
                    passport_device_id = created.passport_device_id
                    config_filename = str(created.config_filename)
                    if passport_device_id != prepared.intended_passport_device_id:
                        raise RuntimeError("issuer did not bind the intended passport")
                    self._attachment_builder(
                        config_filename,
                        str(created.config_text),
                    )
                    row = self._finalize_awg3_issuance(
                        validated=validated,
                        slot=slot,
                        prepared=prepared,
                        recipient_user_id=recipient_user_id,
                        receipt_index=receipt_index,
                        device_id=device_id,
                        config_filename=config_filename,
                    )
                except Exception as exc:
                    try:
                        self._repo.mark_protocol_issuance_attempt_recovery_required(
                            prepared.attempt_id,
                            local_device_id=device_id,
                            reason_code="admin_issuer_or_finalization_failed",
                            passport_device_id=passport_device_id,
                        )
                    except Exception as recovery_exc:
                        failure = recovery_exc
                    else:
                        try:
                            row = self._repo.fail_admin_config_issuance_receipt(
                                request_id=validated.request_id,
                                item_index=receipt_index,
                                error_code=_safe_error_code(exc),
                                device_id=device_id,
                                passport_device_id=passport_device_id,
                                config_filename=config_filename,
                            )
                        except Exception as receipt_exc:
                            failure = receipt_exc
        except ProtocolIssuanceExecutionBlocked as exc:
            return self._repo.fail_admin_config_issuance_receipt(
                request_id=validated.request_id,
                item_index=receipt_index,
                error_code=exc.reason_code,
            )
        if failure is not None:
            raise failure
        assert row is not None
        return row

    def _finalize_awg3_issuance(
        self,
        *,
        validated: ValidatedIssuanceManifest,
        slot: ExpandedIssuanceSlot,
        prepared: _Awg3ExecutionPreparation,
        recipient_user_id: int,
        receipt_index: int,
        device_id: int,
        config_filename: str,
    ):
        with self._repo.transaction():
            profile = DualProtocolProfileService(self._repo).attach_active(
                prepared.intended_passport_device_id,
                ProtocolVersion.AWG3,
                device_id,
                actor_kind="admin",
                actor_id=self._admin_telegram_id,
                reason="admin_config_issued",
            )
            self._repo.append_protocol_config_event(
                event_type="admin_config_issued",
                actor_kind="admin",
                actor_id=self._admin_telegram_id,
                reason="issued",
                passport_device_id=prepared.intended_passport_device_id,
                protocol_version="awg3",
                local_device_id=device_id,
                metadata={
                    "attempt_id": prepared.attempt_id,
                    "receipt_id": int(prepared.started_row["id"]),
                    "profile_id": profile.profile_id,
                    "client_application": slot.client_application,
                    "client_platform": slot.client_platform,
                    "client_version": slot.client_version,
                    "client_build": slot.client_build,
                },
            )
            self._repo.record_admin_action(
                admin_telegram_id=self._admin_telegram_id,
                action="admin_config.issue_manifest",
                target_user_id=recipient_user_id,
                target_device_id=device_id,
                metadata={
                    "request_id": validated.request_id,
                    "item_index": receipt_index,
                    "receipt_id": int(prepared.started_row["id"]),
                    "assignment_mode": slot.assignment_mode,
                    "slot_sequence": slot.slot_sequence,
                    "expiry_policy": slot.expiry.policy,
                    "passport_device_id": prepared.intended_passport_device_id,
                    "status": "completed",
                    "config_filename": config_filename,
                    "config_version": config_version_for_protocol(
                        slot.protocol_version
                    ),
                    "protocol_version": "awg3",
                    "runtime_instance_id": prepared.admission.runtime_instance_id,
                    "compatibility_evidence_id": (
                        prepared.admission.compatibility_evidence_id
                    ),
                    "client_application": slot.client_application,
                    "client_platform": slot.client_platform,
                    "client_version": slot.client_version,
                    "client_build": slot.client_build,
                },
            )
            row = self._repo.complete_admin_config_issuance_receipt(
                request_id=validated.request_id,
                item_index=receipt_index,
                device_id=device_id,
                passport_device_id=prepared.intended_passport_device_id,
                config_filename=config_filename,
            )
            self._repo.complete_protocol_issuance_attempt(
                prepared.attempt_id,
                local_device_id=device_id,
                passport_device_id=prepared.intended_passport_device_id,
                execution_lease=prepared.execution_lease,
            )
            return row

    def _prepare_awg3_execution_marker(
        self,
        *,
        validated: ValidatedIssuanceManifest,
        slot: ExpandedIssuanceSlot,
        recipient_user_id: int,
        receipt_index: int,
    ):
        with self._repo.transaction():
            admission = self._admission.decide(
                AdmissionRequest(
                    client=ClientIdentity(
                        slot.client_application,
                        slot.client_platform,
                        slot.client_version,
                        build_id=slot.client_build,
                    ),
                    protocol_version=ProtocolVersion.AWG3,
                )
            )
            item_fingerprint = _slot_fingerprint(
                validated.server,
                slot,
                admission,
            )
            existing = self._repo.get_admin_config_issuance_receipt(
                request_id=validated.request_id,
                item_index=receipt_index,
            )
            if existing is not None:
                if str(existing["item_fingerprint"]) != item_fingerprint:
                    raise ValueError("manifest item does not match existing receipt")
                return existing, None
            if not admission.admitted:
                self._create_awg3_receipt(
                    validated=validated,
                    slot=slot,
                    admission=admission,
                    recipient_user_id=recipient_user_id,
                    receipt_index=receipt_index,
                    item_fingerprint=item_fingerprint,
                )
                return (
                    self._repo.fail_admin_config_issuance_receipt(
                        request_id=validated.request_id,
                        item_index=receipt_index,
                        error_code=admission.decision,
                    ),
                    None,
                )

            intended_passport_device_id = generate_device_passport_id()
            attempt = self._repo.reserve_protocol_issuance_attempt(
                owner_user_id=recipient_user_id,
                intended_passport_device_id=intended_passport_device_id,
                passport_device_id=None,
                protocol_version="awg3",
                request_fingerprint=item_fingerprint,
                actor_kind="admin",
                actor_id=self._admin_telegram_id,
                client_application=slot.client_application,
                client_platform=slot.client_platform,
                client_version=slot.client_version,
                client_build=slot.client_build,
                runtime_instance_id=admission.runtime_instance_id,
                compatibility_evidence_id=admission.compatibility_evidence_id,
            )
            if attempt is None:
                raise ValueError("protocol issuance reservation denied")
            self._repo.mark_protocol_issuance_attempt_recovery_required(
                int(attempt["id"]),
                local_device_id=None,
                reason_code="issuer_in_progress",
            )
            execution_lease = self._repo.create_protocol_issuance_execution_lease(
                int(attempt["id"])
            )
            started_row = self._create_awg3_receipt(
                validated=validated,
                slot=slot,
                admission=admission,
                recipient_user_id=recipient_user_id,
                receipt_index=receipt_index,
                item_fingerprint=item_fingerprint,
            )
            return None, _Awg3ExecutionPreparation(
                admission=admission,
                intended_passport_device_id=intended_passport_device_id,
                attempt_id=int(attempt["id"]),
                execution_lease=execution_lease,
                started_row=started_row,
            )

    def _create_awg3_receipt(
        self,
        *,
        validated: ValidatedIssuanceManifest,
        slot: ExpandedIssuanceSlot,
        admission: AdmissionResult,
        recipient_user_id: int,
        receipt_index: int,
        item_fingerprint: str,
    ):
        return self._repo.create_admin_config_issuance_receipt(
            request_id=validated.request_id,
            item_index=receipt_index,
            item_fingerprint=item_fingerprint,
            recipient_user_id=recipient_user_id,
            assignment_mode=slot.assignment_mode,
            slot_sequence=slot.slot_sequence,
            expiry_policy=slot.expiry.policy,
            config_version=config_version_for_protocol(slot.protocol_version),
            protocol_version=slot.protocol_version.value,
            runtime_instance_id=admission.runtime_instance_id,
            compatibility_evidence_id=admission.compatibility_evidence_id,
            client_application=slot.client_application,
            client_platform=slot.client_platform,
            client_version=slot.client_version,
            client_build=slot.client_build,
        )

    def replay_existing_request(self, request_id: str) -> AdminConfigIssuanceResult:
        request = self._repo.get_admin_config_issuance_request(request_id=request_id)
        if request is None:
            raise ValueError("issuance request was not found")
        rows = self._repo.list_admin_config_issuance_receipts(request_id)
        if len(rows) != int(request["item_count"]):
            raise ValueError("issuance request receipt set is incomplete")
        receipts = tuple(_receipt_from_row(row) for row in rows)
        status = "completed" if all(item.status == "completed" for item in receipts) else "partial_failure"
        return AdminConfigIssuanceResult(
            request_id=request_id,
            server="legacy_read_only",
            status=status,
            receipts=receipts,
        )

    def _admit_protocol_batch(
        self, slots: tuple[ExpandedIssuanceSlot, ...]
    ) -> tuple[AdmissionResult, ...]:
        admissions = tuple(
            self._admission.decide(
                AdmissionRequest(
                    client=ClientIdentity(
                        slot.client_application,
                        slot.client_platform,
                        slot.client_version,
                        build_id=slot.client_build,
                    ),
                    protocol_version=slot.protocol_version,
                )
            )
            for slot in slots
        )
        blocked = next((item for item in admissions if not item.admitted), None)
        if blocked is not None:
            raise ValueError(blocked.decision)
        return admissions

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
            if recipient is not None:
                existing_device_names = {
                    str(row["name"])
                    for row in self._repo.list_user_devices_for_admin(
                        int(recipient["id"]), limit=100
                    )
                }
                existing_names = set(
                    self._repo.list_completed_admin_config_filenames_for_recipient(
                        int(recipient["id"])
                    )
                )
                proposed_names = {
                    (
                        build_unassigned_slot_identity(
                            slot.recipient_label, slot.slot_sequence
                        ).filename
                        if slot.assignment_mode == RECIPIENT_UNASSIGNED
                        else build_config_identity(
                            slot.recipient_label, slot.device_label
                        ).filename
                    )
                    for slot in slots
                    if _duplicate_label_key(slot.recipient_label) == key
                }
                proposed_device_names = {
                    build_config_identity(
                        slot.recipient_label, slot.device_label
                    ).display_name
                    for slot in slots
                    if _duplicate_label_key(slot.recipient_label) == key
                }
                if existing_names & proposed_names or existing_device_names & proposed_device_names:
                    raise ValueError("full-batch filename collision for recipient")


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
            raise ValueError("recipient_unassigned requires a separate reservation workflow")
        quantity = 1
        device_label = _required_bounded_text(raw_item, "device_label")
        protocol_version = normalize_protocol_version(raw_item.get("protocol_version"))
        raw_client_build = raw_item.get("client_build")
        client_build = (
            _required_bounded_text(raw_item, "client_build")
            if protocol_version is ProtocolVersion.AWG3 or raw_client_build is not None
            else None
        )
        client = ClientIdentity(
            _required_bounded_text(raw_item, "client_application"),
            _required_bounded_text(raw_item, "client_platform"),
            _required_bounded_text(raw_item, "client_version"),
            build_id=client_build,
        )
        validate_device_passport_context(
            platform=client.platform,
            official_client_type=client.application,
            import_method="conf_file",
            config_schema_version=config_version_for_protocol(protocol_version),
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
            client_application=client.application,
            client_platform=client.platform,
            client_version=client.version,
            client_build=client.build_id,
            protocol_version=protocol_version,
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
                    device_label=str(device_label),
                    client_application=client.application,
                    client_platform=client.platform,
                    client_version=client.version,
                    client_build=client.build_id,
                    protocol_version=protocol_version,
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


def _slot_dict(
    slot: ExpandedIssuanceSlot, admission: AdmissionResult | None = None
) -> dict[str, object]:
    return {
        "source_item_index": slot.item_index,
        "recipient_label": slot.recipient_label,
        "assignment_mode": slot.assignment_mode,
        "slot_sequence": slot.slot_sequence,
        "device_label": slot.device_label,
        "client_application": slot.client_application,
        "client_platform": slot.client_platform,
        "client_version": slot.client_version,
        "client_build": slot.client_build,
        "protocol_version": slot.protocol_version.value,
        "runtime_instance_id": admission.runtime_instance_id if admission else None,
        "compatibility_evidence_id": (
            admission.compatibility_evidence_id if admission else None
        ),
        "expiry": _expiry_dict(slot.expiry),
    }


def _slot_fingerprint(
    server: str, slot: ExpandedIssuanceSlot, admission: AdmissionResult
) -> str:
    canonical = json.dumps(
        {"server": server, **_slot_dict(slot, admission)},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


def _request_fingerprint(
    manifest: ValidatedIssuanceManifest,
    admissions: tuple[AdmissionResult, ...] | None = None,
) -> str:
    if admissions is not None and len(admissions) != len(manifest.expanded_slots):
        raise ValueError("admission count does not match expanded slots")
    canonical = json.dumps(
        {
            "server": manifest.server,
            "expanded_slot_count": len(manifest.expanded_slots),
            "slots": [
                _slot_dict(slot, admissions[index] if admissions else None)
                for index, slot in enumerate(manifest.expanded_slots)
            ],
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


def _receipt_from_row(
    row, *, client_build: str | None = None
) -> AdminConfigIssuanceReceipt:
    persisted_client_build = _optional_row_text(row, "client_build")
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
        config_version=_optional_row_text(row, "config_version"),
        protocol_version=_optional_row_text(row, "protocol_version"),
        runtime_instance_id=_optional_row_text(row, "runtime_instance_id"),
        compatibility_evidence_id=_optional_row_text(
            row, "compatibility_evidence_id"
        ),
        client_application=_optional_row_text(row, "client_application"),
        client_platform=_optional_row_text(row, "client_platform"),
        client_version=_optional_row_text(row, "client_version"),
        client_build=(
            client_build if client_build is not None else persisted_client_build
        ),
        created_at=str(row["created_at"]),
        updated_at=str(row["updated_at"]),
    )


def _optional_row_text(row, key: str) -> str | None:
    value = row[key] if key in row.keys() else None
    return str(value) if value is not None else None
