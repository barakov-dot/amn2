from __future__ import annotations

import ipaddress
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol

from app.db.repositories import Repository
from app.security.crypto import SecretBox
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


@dataclass(frozen=True)
class RemoteMutationResult:
    operation_id: str
    consistency_status: str
    remote_applied: bool
    local_applied: bool
    recovery_note: str


class RemoteOperationPartialFailure(RuntimeError):
    def __init__(self, result: RemoteMutationResult, cause: Exception) -> None:
        super().__init__(f"{result.operation_id} partial failure: {result.recovery_note}")
        self.result = result
        self.cause = cause


@dataclass(frozen=True)
class AccessApprovalResult:
    device_id: int
    config_text: str


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
        if order["plan_id"] is not None:
            duration_days = int(self._repo.get_plan(str(order["plan_id"]))["duration_days"])
        user_id = int(order["user_id"])
        if order["status"] == "fulfilled" or order["device_id"] is not None:
            raise OrderAlreadyFulfilled("Order has already been fulfilled")
        if order["status"] not in {"manual_review", "approved"}:
            raise OrderNotApprovable(
                f"Order {order_id} cannot be approved from status {order['status']}"
            )

        if self._repo.count_active_devices(user_id) >= self._max_devices_per_user:
            raise MaxDevicesReached("User has reached the maximum number of active devices")

        server = self._repo.get_server(server_id)
        keypair = generate_keypair()
        preshared_key = generate_key()

        device_id, config_text = self._create_device_with_allocated_ip(
            user_id=user_id,
            server_id=server_id,
            device_name=device_name,
            server=server,
            duration_days=duration_days,
            private_key=keypair.private_key,
            public_key=keypair.public_key,
            preshared_key=preshared_key,
            config_version=config_version,
            order_id=order_id,
            remote_mutation_observer=remote_mutation_observer,
        )
        self._repo.mark_order_fulfilled(order_id, device_id)
        self._repo.record_admin_action(
            admin_telegram_id=admin_telegram_id,
            action="access.approve_order",
            target_user_id=user_id,
            target_device_id=device_id,
            metadata={"order_id": order_id, "server_id": server_id},
        )

        return AccessApprovalResult(device_id=device_id, config_text=config_text)

    def _create_device_with_allocated_ip(
        self,
        *,
        user_id: int,
        server_id: int,
        device_name: str,
        server,
        duration_days: int,
        private_key: str,
        public_key: str,
        preshared_key: str,
        config_version: str,
        order_id: int,
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

            try:
                device_id = self._repo.create_device(
                    user_id=user_id,
                    server_id=server_id,
                    name=device_name,
                    duration_days=duration_days,
                    vpn_ip=vpn_ip,
                    peer_public_key=public_key,
                    peer_private_key_encrypted=self._secret_box.encrypt_text(private_key),
                    preshared_key_encrypted=self._secret_box.encrypt_text(preshared_key),
                    config_version=config_version,
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
                            RemoteMutationResult(
                                operation_id="access.approve_order",
                                consistency_status="partial-failure",
                                remote_applied=True,
                                local_applied=False,
                                recovery_note=(
                                    "Remote peer was applied before local approval "
                                    f"completed. Put order {order_id} and device "
                                    f"{device_id} into manual review, verify the "
                                    "server peer, and reconcile local state."
                                ),
                            )
                        )
                return device_id, config_text

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
