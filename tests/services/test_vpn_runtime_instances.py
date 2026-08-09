from dataclasses import replace

import pytest

from app.services.vpn_runtime_instances import (
    RuntimeInstanceSpec,
    RuntimePlanningService,
    plan_runtime_instance,
)
from app.vpn.protocol_versions import ProtocolVersion


def _accepted_awg2_spec() -> RuntimeInstanceSpec:
    return RuntimeInstanceSpec(
        runtime_instance_id="rt-spain-awg2",
        server_id=1,
        protocol_version=ProtocolVersion.AWG2,
        runtime_version="accepted-phase12",
        interface_name="awg0",
        udp_port=30001,
        vpn_cidr="10.212.12.0/24",
        container_name="amn2-awg",
        service_name=None,
        config_path="/opt/amnezia/awg/wg0.conf",
        lifecycle_state="accepted",
        acceptance_receipt="sha256:" + "a" * 64,
    )


def _planned_awg3_spec() -> RuntimeInstanceSpec:
    return RuntimeInstanceSpec(
        runtime_instance_id="rt-spain-awg3",
        server_id=1,
        protocol_version=ProtocolVersion.AWG3,
        runtime_version="3.0.3",
        interface_name="awg3",
        udp_port=30002,
        vpn_cidr="10.212.13.0/24",
        container_name="amn2-awg3",
        service_name=None,
        config_path="/opt/amn2/awg3/wg0.conf",
        lifecycle_state="planned",
        acceptance_receipt=None,
    )


def test_runtime_plan_rejects_port_interface_and_cidr_conflicts():
    candidate = replace(
        _planned_awg3_spec(),
        interface_name="awg0",
        udp_port=30001,
        vpn_cidr="10.212.12.128/25",
    )
    plan = plan_runtime_instance(candidate, existing=(_accepted_awg2_spec(),))
    assert tuple(item.kind for item in plan.conflicts) == (
        "interface_name",
        "udp_port",
        "vpn_cidr_overlap",
    )
    assert plan.admissible is False


def test_runtime_plan_accepts_isolated_candidate():
    plan = plan_runtime_instance(
        _planned_awg3_spec(), existing=(_accepted_awg2_spec(),)
    )
    assert plan.conflicts == ()
    assert plan.admissible is True


def test_runtime_identity_conflicts_even_when_server_differs():
    other = replace(_accepted_awg2_spec(), server_id=2)
    candidate = replace(_planned_awg3_spec(), runtime_instance_id=other.runtime_instance_id)
    plan = plan_runtime_instance(candidate, existing=(other,))
    assert tuple(item.kind for item in plan.conflicts) == ("runtime_identity",)


def test_accepted_lifecycle_requires_secret_free_receipt():
    with pytest.raises(ValueError, match="acceptance_receipt"):
        replace(_accepted_awg2_spec(), acceptance_receipt=None)


class ReadOnlyRuntimeRepository:
    def __init__(self) -> None:
        self.reads = 0

    def list_vpn_runtime_instances_for_server(self, server_id: int):
        self.reads += 1
        assert server_id == 1
        return [dict(vars(_accepted_awg2_spec()), protocol_version="awg2")]

    def __getattr__(self, name: str):
        if name.startswith(("create_", "update_", "delete_")):
            raise AssertionError(f"runtime planning attempted mutation: {name}")
        raise AttributeError(name)


def test_planning_service_uses_only_read_path():
    repo = ReadOnlyRuntimeRepository()
    result = RuntimePlanningService(repo).plan(_planned_awg3_spec())
    assert result.admissible is True
    assert repo.reads == 1
