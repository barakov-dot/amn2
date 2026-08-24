from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_network
import re
from typing import Literal, Mapping, Protocol, Sequence

from app.vpn.ipam import networks_overlap
from app.vpn.protocol_versions import ProtocolVersion, normalize_protocol_version


RuntimeLifecycleState = Literal[
    "planned", "candidate", "accepted", "rollback_pending", "retired"
]
RuntimeConflictKind = Literal[
    "runtime_identity",
    "interface_name",
    "udp_port",
    "vpn_cidr_overlap",
]

_RECEIPT_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")


def _bounded_one_line(value: object, field: str, *, maximum: int = 255) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError(field)
    if value != value.strip() or "\n" in value or "\r" in value:
        raise ValueError(field)
    return value


@dataclass(frozen=True)
class RuntimeInstanceSpec:
    runtime_instance_id: str
    server_id: int
    protocol_version: ProtocolVersion
    runtime_version: str
    interface_name: str
    udp_port: int
    vpn_cidr: str
    container_name: str | None
    service_name: str | None
    config_path: str
    lifecycle_state: RuntimeLifecycleState
    acceptance_receipt: str | None

    def __post_init__(self) -> None:
        _bounded_one_line(self.runtime_instance_id, "runtime_instance_id")
        if isinstance(self.server_id, bool) or not isinstance(self.server_id, int) or self.server_id <= 0:
            raise ValueError("server_id")
        if not isinstance(self.protocol_version, ProtocolVersion):
            raise ValueError("protocol_version")
        _bounded_one_line(self.runtime_version, "runtime_version")
        _bounded_one_line(self.interface_name, "interface_name", maximum=64)
        if isinstance(self.udp_port, bool) or not isinstance(self.udp_port, int):
            raise ValueError("udp_port")
        if not 1 <= self.udp_port <= 65535:
            raise ValueError("udp_port")
        try:
            network = ip_network(
                self.vpn_cidr,
                strict=self.protocol_version is ProtocolVersion.AWG3,
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("vpn_cidr") from exc
        if self.protocol_version is ProtocolVersion.AWG3 and (
            network.version != 4
            or network.prefixlen != 24
            or str(network) != self.vpn_cidr
        ):
            raise ValueError("vpn_cidr")
        if self.container_name is not None:
            _bounded_one_line(self.container_name, "container_name")
        if self.service_name is not None:
            _bounded_one_line(self.service_name, "service_name")
        _bounded_one_line(self.config_path, "config_path", maximum=1024)
        if self.lifecycle_state not in (
            "planned",
            "candidate",
            "accepted",
            "rollback_pending",
            "retired",
        ):
            raise ValueError("lifecycle_state")
        if self.acceptance_receipt is not None and not _RECEIPT_RE.fullmatch(
            self.acceptance_receipt
        ):
            raise ValueError("acceptance_receipt")
        if self.lifecycle_state == "accepted" and self.acceptance_receipt is None:
            raise ValueError("acceptance_receipt")


@dataclass(frozen=True)
class RuntimeConflict:
    kind: RuntimeConflictKind
    existing_runtime_instance_id: str


@dataclass(frozen=True)
class RuntimePlan:
    candidate: RuntimeInstanceSpec
    conflicts: tuple[RuntimeConflict, ...]

    @property
    def admissible(self) -> bool:
        return not self.conflicts


def plan_runtime_instance(
    candidate: RuntimeInstanceSpec,
    *,
    existing: Sequence[RuntimeInstanceSpec],
) -> RuntimePlan:
    conflicts: list[RuntimeConflict] = []
    for current in existing:
        if current.runtime_instance_id == candidate.runtime_instance_id:
            conflicts.append(RuntimeConflict("runtime_identity", current.runtime_instance_id))
            continue
        if current.server_id != candidate.server_id or current.lifecycle_state == "retired":
            continue
        if current.interface_name == candidate.interface_name:
            conflicts.append(RuntimeConflict("interface_name", current.runtime_instance_id))
        if current.udp_port == candidate.udp_port:
            conflicts.append(RuntimeConflict("udp_port", current.runtime_instance_id))
        if networks_overlap(current.vpn_cidr, candidate.vpn_cidr):
            conflicts.append(RuntimeConflict("vpn_cidr_overlap", current.runtime_instance_id))
    return RuntimePlan(candidate=candidate, conflicts=tuple(conflicts))


def runtime_spec_from_row(row: Mapping[str, object]) -> RuntimeInstanceSpec:
    return RuntimeInstanceSpec(
        runtime_instance_id=row["runtime_instance_id"],
        server_id=row["server_id"],
        protocol_version=normalize_protocol_version(row["protocol_version"]),
        runtime_version=row["runtime_version"],
        interface_name=row["interface_name"],
        udp_port=row["udp_port"],
        vpn_cidr=row["vpn_cidr"],
        container_name=row.get("container_name"),
        service_name=row.get("service_name"),
        config_path=row["config_path"],
        lifecycle_state=row["lifecycle_state"],
        acceptance_receipt=row.get("acceptance_receipt"),
    )


class RuntimePlanningRepository(Protocol):
    def list_vpn_runtime_instances_for_server(
        self, server_id: int
    ) -> Sequence[Mapping[str, object]]: ...


class RuntimePlanningService:
    def __init__(self, repository: RuntimePlanningRepository) -> None:
        self._repository = repository

    def plan(self, candidate: RuntimeInstanceSpec) -> RuntimePlan:
        rows = self._repository.list_vpn_runtime_instances_for_server(candidate.server_id)
        existing = tuple(runtime_spec_from_row(row) for row in rows)
        return plan_runtime_instance(candidate, existing=existing)
