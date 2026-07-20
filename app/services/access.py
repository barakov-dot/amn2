from __future__ import annotations

import ipaddress
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Protocol

from app.access_expiry import AccessExpiry, DURATION, INDEFINITE
from app.db.repositories import Repository
from app.server.operations import (
    RemoteMutationResult,
    remote_changed_local_failed_result,
)
from app.security.crypto import SecretBox
from app.services.config_identity import build_config_identity
from app.services.device_lifecycle import LifecycleEvidence, record_device_lifecycle_stage
from app.services.device_passports import (
    create_device_passport,
    fingerprint_config,
    generate_device_passport_id,
    validate_device_passport_context,
)
from app.config_assignment import (
    DEDICATED_DEVICE,
    OWNER_SHARED,
    RECIPIENT_UNASSIGNED,
    config_assignment_policy,
    validate_config_assignment_mode,
)
from app.vpn.amneziawg_v2.config import ClientConfigDefaults, ClientConfigInput
from app.vpn.amneziawg_v2.keys import generate_key, generate_keypair
from app.vpn.config_versions import render_client_config_for_version, validate_config_version


IP_ALLOCATION_ATTEMPTS = 3


class MaxDevicesReached(ValueError):
    pass


class OrderAlreadyFulfilled(ValueError):
    pass


class OrderNotApprovable(ValueError):
    pass


class IpAllocationConflict(RuntimeError):
    pass


class OperatorOwnerNotFound(LookupError):
    pass


class OperatorOwnerNotActive(ValueError):
    pass


class OperatorOwnerSharedRequiresAdmin(ValueError):
    pass


class OperatorPeerApplierRequired(RuntimeError):
    pass


class RemoteOperationPartialFailure(RuntimeError):
    def __init__(self, result: RemoteMutationResult, cause: Exception) -> None:
        super().__init__(f"{result.operation_id} partial failure: {result.recovery_note}")
        self.result = result
        self.cause = cause


@dataclass(frozen=True)
class AccessApprovalResult:
    device_id: int
    config_text: str
    assignment_mode: str = DEDICATED_DEVICE


@dataclass(frozen=True)
class OperatorDeviceCreateResult:
    device_id: int
    config_text: str
    config_artifact_path: str | None
    config_filename: str
    config_fingerprint: str
    passport_device_id: str | None
    assignment_mode: str = DEDICATED_DEVICE


@dataclass(frozen=True)
class OperatorDeviceContext:
    platform: str
    official_client_type: str = "amnezia_vpn"
    client_version: str | None = None
    import_method: str = "conf_file"


class PeerApplier(Protocol):
    def apply_peer(
        self,
        *,
        server,
        peer_public_key: str,
        preshared_key: str,
        vpn_ip: str,
    ) -> None:
        pass

    def list_allocated_ips(self, *, server) -> list[str]:
        pass


class AccessService:
    def __init__(
        self,
        *,
        repo: Repository,
        secret_box: SecretBox,
        max_devices_per_user: int = 5,
        duration_days: int = 30,
        peer_applier: PeerApplier | None = None,
        client_config_template_dir: str | Path | None = None,
        client_config_defaults: ClientConfigDefaults | None = None,
    ) -> None:
        self._repo = repo
        self._secret_box = secret_box
        self._max_devices_per_user = max_devices_per_user
        self._duration_days = duration_days
        self._peer_applier = peer_applier
        self._client_config_template_dir = client_config_template_dir
        self._client_config_defaults = client_config_defaults or ClientConfigDefaults()

    def approve_order(
        self,
        order_id: int,
        server_id: int,
        device_name: str,
        *,
        admin_telegram_id: int,
        config_version: str | None = None,
    ) -> AccessApprovalResult:
        remote_mutation: RemoteMutationResult | None = None

        def record_remote_mutation(result: RemoteMutationResult) -> None:
            nonlocal remote_mutation
            remote_mutation = result

        try:
            with self._repo.transaction():
                return self._approve_order(
                    order_id=order_id,
                    server_id=server_id,
                    device_name=device_name,
                    admin_telegram_id=admin_telegram_id,
                    config_version=config_version,
                    remote_mutation_observer=record_remote_mutation,
                )
        except Exception as exc:
            if remote_mutation is not None and not remote_mutation.local_applied:
                raise RemoteOperationPartialFailure(remote_mutation, exc) from exc
            raise

    def _record_operator_partial_failure(
        self,
        *,
        owner_user_id: int,
        server_id: int,
        admin_telegram_id: int,
        result: RemoteMutationResult,
    ) -> None:
        try:
            self._repo.record_admin_action(
                admin_telegram_id=admin_telegram_id,
                action="access.create_operator_device.partial_failure",
                target_user_id=owner_user_id,
                metadata={
                    "server_id": server_id,
                    "operation_id": result.operation_id,
                    "consistency_status": result.consistency_status,
                    "remote_applied": result.remote_applied,
                    "local_applied": result.local_applied,
                    "recovery_note": result.recovery_note,
                },
            )
        except Exception:
            # Preserve the original partial-failure result if the audit backend is down.
            return

    def create_operator_device(
        self,
        *,
        owner_user_id: int,
        server_id: int,
        device_name: str,
        duration_days: int | None,
        admin_telegram_id: int,
        expiry: AccessExpiry | None = None,
        config_version: str = "amneziawg_v2",
        assignment_mode: str = DEDICATED_DEVICE,
        config_artifact_writer: Callable[[str], str | Path] | None = None,
        device_context: OperatorDeviceContext = OperatorDeviceContext(
            platform="unknown"
        ),
    ) -> OperatorDeviceCreateResult:
        remote_mutation: RemoteMutationResult | None = None

        def record_remote_mutation(result: RemoteMutationResult) -> None:
            nonlocal remote_mutation
            remote_mutation = result

        try:
            with self._repo.transaction():
                return self._create_operator_device(
                    owner_user_id=owner_user_id,
                    server_id=server_id,
                    device_name=device_name,
                    duration_days=duration_days,
                    expiry=expiry,
                    admin_telegram_id=admin_telegram_id,
                    config_version=config_version,
                    assignment_mode=assignment_mode,
                    config_artifact_writer=config_artifact_writer,
                    device_context=device_context,
                    remote_mutation_observer=record_remote_mutation,
                )
        except Exception as exc:
            if remote_mutation is not None and not remote_mutation.local_applied:
                self._record_operator_partial_failure(
                    owner_user_id=owner_user_id,
                    server_id=server_id,
                    admin_telegram_id=admin_telegram_id,
                    result=remote_mutation,
                )
                raise RemoteOperationPartialFailure(remote_mutation, exc) from exc
            raise

    def _create_operator_device(
        self,
        *,
        owner_user_id: int,
        server_id: int,
        device_name: str,
        duration_days: int | None,
        expiry: AccessExpiry | None,
        admin_telegram_id: int,
        config_version: str,
        assignment_mode: str,
        config_artifact_writer: Callable[[str], str | Path] | None,
        device_context: OperatorDeviceContext,
        remote_mutation_observer: Callable[[RemoteMutationResult], None] | None,
    ) -> OperatorDeviceCreateResult:
        normalized_device_display_name = device_name.strip()
        if admin_telegram_id <= 0:
            raise ValueError("admin_telegram_id must be positive")
        if not normalized_device_display_name:
            raise ValueError("device_name must be non-blank")
        expiry = _resolve_operator_expiry(duration_days=duration_days, expiry=expiry)
        config_version = validate_config_version(config_version)
        assignment_mode = validate_config_assignment_mode(assignment_mode)
        assignment_policy = config_assignment_policy(assignment_mode)
        if assignment_policy.passport_required:
            validate_device_passport_context(
                platform=device_context.platform,
                official_client_type=device_context.official_client_type,
                client_version=device_context.client_version,
                import_method=device_context.import_method,
                config_schema_version=config_version,
            )

        try:
            owner = self._repo.get_user(owner_user_id)
        except LookupError as exc:
            raise OperatorOwnerNotFound(
                f"Operator device owner {owner_user_id} does not exist"
            ) from exc
        if str(owner["status"]) != "active":
            raise OperatorOwnerNotActive(
                f"Operator device owner {owner_user_id} is not active"
            )
        if assignment_mode == OWNER_SHARED and int(owner["is_admin"]) != 1:
            raise OperatorOwnerSharedRequiresAdmin(
                "owner_shared assignment requires an active admin owner account"
            )
        if (
            assignment_policy.physical_device_count_enforceable
            and self._repo.count_active_devices(owner_user_id) >= self._max_devices_per_user
        ):
            raise MaxDevicesReached("User has reached the maximum number of active devices")
        if self._peer_applier is None:
            raise OperatorPeerApplierRequired(
                "Operator device creation requires an explicit live peer applier"
            )

        user_label = _operator_config_user_label(owner, user_id=owner_user_id)
        config_identity = build_config_identity(
            user_label=user_label,
            device_label=normalized_device_display_name,
        )
        server = self._repo.get_server(server_id)
        keypair = generate_keypair()
        preshared_key = generate_key()
        device_id, config_text, config_fingerprint = self._create_device_with_allocated_ip(
            user_id=owner_user_id,
            server_id=server_id,
            device_name=config_identity.display_name,
            server=server,
            expiry=expiry,
            private_key=keypair.private_key,
            public_key=keypair.public_key,
            preshared_key=preshared_key,
            config_version=config_version,
            assignment_mode=assignment_mode,
            remote_operation_id="access.create_operator_device",
            remote_recovery_note=lambda created_device_id: (
                "Remote peer was applied before operator device creation completed. "
                f"Reconcile device {created_device_id} against the explicit owner "
                f"{owner_user_id} and server {server_id}; revoke the remote peer if "
                "the local device record was rolled back, and inspect the private "
                "artifact path because a completed file may still exist."
            ),
            remote_mutation_observer=remote_mutation_observer,
        )

        self._repo.record_admin_action(
            admin_telegram_id=admin_telegram_id,
            action="access.create_operator_device",
            target_user_id=owner_user_id,
            target_device_id=device_id,
            metadata={
                "server_id": server_id,
                "expiry_policy": expiry.policy,
                "duration_days": expiry.duration_days,
                "expires_at": expiry.expires_at,
                "config_version": config_version,
                "assignment_mode": assignment_mode,
                "physical_device_count_enforceable": (
                    assignment_policy.physical_device_count_enforceable
                ),
                "config_artifact_written": config_artifact_writer is not None,
            },
        )
        artifact_path = None
        if config_artifact_writer is not None:
            artifact_path = str(config_artifact_writer(config_text))
        passport_device_id = None
        if assignment_policy.passport_required:
            passport_device_id = generate_device_passport_id()
            create_device_passport(
                self._repo,
                device_id=passport_device_id,
                owner_user_id=owner_user_id,
                local_device_id=device_id,
                platform=device_context.platform,
                official_client_type=device_context.official_client_type,
                client_version=device_context.client_version,
                import_method=device_context.import_method,
                config_schema_version=config_version,
                config_fingerprint=config_fingerprint,
            )
            config_ready_at = datetime.now(timezone.utc)
            record_device_lifecycle_stage(
                self._repo,
                passport_device_id=passport_device_id,
                stage="config_ready",
                status="completed",
                started_at=config_ready_at,
                occurred_at=config_ready_at,
                evidence=LifecycleEvidence(
                    source="operator_config_renderer",
                    reference=f"schema:{config_version}",
                ),
            )
        if assignment_mode != RECIPIENT_UNASSIGNED:
            config_identity = build_config_identity(
                user_label=user_label,
                device_label=normalized_device_display_name,
                collision_device_id=device_id,
            )
        return OperatorDeviceCreateResult(
            device_id=device_id,
            config_text=config_text,
            config_artifact_path=artifact_path,
            config_filename=config_identity.filename,
            config_fingerprint=config_fingerprint,
            passport_device_id=passport_device_id,
            assignment_mode=assignment_mode,
        )

    def _approve_order(
        self,
        *,
        order_id: int,
        server_id: int,
        device_name: str,
        admin_telegram_id: int,
        config_version: str | None,
        remote_mutation_observer: Callable[[RemoteMutationResult], None] | None = None,
    ) -> AccessApprovalResult:
        order = self._repo.get_order(order_id)
        config_version = validate_config_version(
            config_version or str(order["requested_config_version"])
        )
        duration_days = self._duration_days
        plan = None
        if order["plan_id"] is not None:
            plan = self._repo.get_plan(str(order["plan_id"]))
            duration_days = int(plan["duration_days"])
        user_id = int(order["user_id"])
        if order["status"] == "fulfilled" or order["device_id"] is not None:
            raise OrderAlreadyFulfilled("Order has already been fulfilled")
        if order["status"] not in {"manual_review", "approved"}:
            raise OrderNotApprovable(
                f"Order {order_id} cannot be approved from status {order['status']}"
            )

        effective_device_limit = self._max_devices_per_user
        if plan is not None and plan["max_devices"] is not None:
            effective_device_limit = min(effective_device_limit, int(plan["max_devices"]))
        if self._repo.count_active_devices(user_id) >= effective_device_limit:
            raise MaxDevicesReached("User has reached the maximum number of active devices")

        server = self._repo.get_server(server_id)
        keypair = generate_keypair()
        preshared_key = generate_key()

        device_id, config_text, _config_fingerprint = self._create_device_with_allocated_ip(
            user_id=user_id,
            server_id=server_id,
            device_name=device_name,
            server=server,
            expiry=AccessExpiry(DURATION, duration_days, None),
            private_key=keypair.private_key,
            public_key=keypair.public_key,
            preshared_key=preshared_key,
            config_version=config_version,
            assignment_mode=DEDICATED_DEVICE,
            remote_operation_id="access.approve_order",
            remote_recovery_note=lambda created_device_id: (
                "Remote peer was applied before local approval completed. "
                f"Put order {order_id} and device {created_device_id} into manual "
                "review, verify the server peer, and reconcile local state."
            ),
            remote_mutation_observer=remote_mutation_observer,
        )
        self._repo.mark_order_fulfilled(order_id, device_id)
        self._repo.record_admin_action(
            admin_telegram_id=admin_telegram_id,
            action="access.approve_order",
            target_user_id=user_id,
            target_device_id=device_id,
            metadata={
                "order_id": order_id,
                "server_id": server_id,
                "assignment_mode": DEDICATED_DEVICE,
                "effective_device_limit": effective_device_limit,
            },
        )

        return AccessApprovalResult(
            device_id=device_id,
            config_text=config_text,
            assignment_mode=DEDICATED_DEVICE,
        )

    def _create_device_with_allocated_ip(
        self,
        *,
        user_id: int,
        server_id: int,
        device_name: str,
        server,
        expiry: AccessExpiry,
        private_key: str,
        public_key: str,
        preshared_key: str,
        config_version: str,
        assignment_mode: str,
        remote_operation_id: str,
        remote_recovery_note: Callable[[int], str],
        remote_mutation_observer: Callable[[RemoteMutationResult], None] | None,
    ) -> tuple[int, str]:
        last_error: sqlite3.IntegrityError | None = None

        for _ in range(IP_ALLOCATION_ATTEMPTS):
            try:
                vpn_ip = _allocate_vpn_ip(
                    network_cidr=str(server["vpn_network_cidr"]),
                    server_address=server["server_address"],
                    allocated_ips=self._repo.list_allocated_ips(server_id),
                    remote_allocated_ips=_list_remote_allocated_ips(
                        self._peer_applier,
                        server=server,
                    ),
                )
            except RuntimeError as exc:
                raise IpAllocationConflict("Could not allocate a unique VPN IP address") from exc
            config_text = render_client_config_for_version(
                ClientConfigInput(
                    private_key=private_key,
                    address=f"{vpn_ip}/32",
                    dns=self._client_config_defaults.dns,
                    server_public_key=str(server["server_public_key"]),
                    preshared_key=preshared_key,
                    endpoint=f"{server['endpoint_host']}:{server['vpn_port']}",
                    allowed_ips=self._client_config_defaults.allowed_ips,
                    persistent_keepalive=self._client_config_defaults.persistent_keepalive,
                    jc=self._client_config_defaults.jc,
                    jmin=self._client_config_defaults.jmin,
                    jmax=self._client_config_defaults.jmax,
                    s1=self._client_config_defaults.s1,
                    s2=self._client_config_defaults.s2,
                    s3=self._client_config_defaults.s3,
                    s4=self._client_config_defaults.s4,
                    h1=self._client_config_defaults.h1,
                    h2=self._client_config_defaults.h2,
                    h3=self._client_config_defaults.h3,
                    h4=self._client_config_defaults.h4,
                    i1=self._client_config_defaults.i1,
                    i2=self._client_config_defaults.i2,
                    i3=self._client_config_defaults.i3,
                    i4=self._client_config_defaults.i4,
                    i5=self._client_config_defaults.i5,
                ),
                config_version,
                template_dir=self._client_config_template_dir,
            )
            config_fingerprint = fingerprint_config(config_text)

            try:
                device_id = self._repo.create_device(
                    user_id=user_id,
                    server_id=server_id,
                    name=device_name,
                    duration_days=expiry.duration_days,
                    expires_at=expiry.expires_at,
                    expiry_policy=expiry.policy,
                    config_fingerprint=config_fingerprint,
                    vpn_ip=vpn_ip,
                    peer_public_key=public_key,
                    peer_private_key_encrypted=self._secret_box.encrypt_text(private_key),
                    preshared_key_encrypted=self._secret_box.encrypt_text(preshared_key),
                    config_version=config_version,
                    assignment_mode=assignment_mode,
                )
            except sqlite3.IntegrityError as exc:
                if not _is_duplicate_ip_integrity_error(exc):
                    raise
                last_error = exc
            else:
                if self._peer_applier is not None:
                    self._peer_applier.apply_peer(
                        server=server,
                        peer_public_key=public_key,
                        preshared_key=preshared_key,
                        vpn_ip=vpn_ip,
                    )
                    if remote_mutation_observer is not None:
                        remote_mutation_observer(
                            remote_changed_local_failed_result(
                                operation_id=remote_operation_id,
                                recovery_note=remote_recovery_note(device_id),
                            )
                        )
                return device_id, config_text, config_fingerprint

        raise IpAllocationConflict("Could not allocate a unique VPN IP address") from last_error


def _allocate_vpn_ip(
    *,
    network_cidr: str,
    server_address: str | None,
    allocated_ips: list[str],
    remote_allocated_ips: list[str] | None = None,
) -> str:
    network = ipaddress.ip_network(network_cidr, strict=False)
    reserved = {
        parsed_ip
        for raw_ip in [*allocated_ips, *(remote_allocated_ips or [])]
        for parsed_ip in [_parse_allocated_ip(raw_ip)]
        if parsed_ip in network
    }
    if server_address is not None:
        reserved.add(_parse_allocated_ip(server_address))

    hosts = list(network.hosts())
    first_index = 0
    remote_reserved = [
        _parse_allocated_ip(raw_ip)
        for raw_ip in remote_allocated_ips or []
        if _parse_allocated_ip(raw_ip) in network
    ]
    if remote_reserved:
        last_remote_ip = max(remote_reserved)
        first_index = hosts.index(last_remote_ip) + 1 if last_remote_ip in hosts else 0

    for ip_address in hosts[first_index:]:
        if ip_address not in reserved:
            return str(ip_address)

    raise RuntimeError("No available VPN IP addresses")


def _resolve_operator_expiry(
    *, duration_days: int | None, expiry: AccessExpiry | None
) -> AccessExpiry:
    if expiry is not None:
        if duration_days is not None:
            raise ValueError("duration_days conflicts with explicit expiry")
        return expiry
    if duration_days is None:
        return AccessExpiry(INDEFINITE, None, None)
    return AccessExpiry(DURATION, duration_days, None)


def _list_remote_allocated_ips(peer_applier: PeerApplier | None, *, server) -> list[str]:
    if peer_applier is None or not hasattr(peer_applier, "list_allocated_ips"):
        return []
    return list(peer_applier.list_allocated_ips(server=server))


def _parse_allocated_ip(value: str):
    stripped = value.strip()
    try:
        return ipaddress.ip_interface(stripped).ip
    except ValueError:
        return ipaddress.ip_address(stripped)


def _is_duplicate_ip_integrity_error(exc: sqlite3.IntegrityError) -> bool:
    message = str(exc)
    return (
        "vpn_ip" in message
        or "idx_devices_reserved_ip_unique" in message
    ) and "UNIQUE constraint failed" in message


def _operator_config_user_label(owner, *, user_id: int) -> str:
    operator_label = str(owner["operator_label"] or "").strip()
    if operator_label:
        return operator_label
    username = str(owner["username"] or "").strip()
    if username:
        return username
    full_name = " ".join(
        part
        for part in (
            str(owner["first_name"] or "").strip(),
            str(owner["last_name"] or "").strip(),
        )
        if part
    )
    if full_name:
        return full_name
    return f"User-{user_id}"
