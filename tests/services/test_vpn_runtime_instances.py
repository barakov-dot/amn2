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
        vpn_cidr="10.212.12.0/24",
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


@pytest.mark.parametrize(
    ("vpn_cidr", "lifecycle_state", "acceptance_receipt"),
    (
        ("2001:db8::/120", "candidate", None),
        ("2001:db8::/64", "accepted", "sha256:" + "b" * 64),
        ("0.0.0.0/0", "planned", None),
        ("10.9.0.0/16", "planned", None),
        ("10.9.0.0/25", "planned", None),
        ("10.9.0.0/30", "planned", None),
        ("10.9.0.1/24", "planned", None),
        ("10.9.0.0/255.255.255.0", "planned", None),
    ),
    ids=(
        "candidate-ipv6-120",
        "accepted-ipv6-64",
        "ipv4-zero",
        "ipv4-16",
        "ipv4-25",
        "ipv4-30",
        "host-bits",
        "netmask-spelling",
    ),
)
def test_awg3_runtime_requires_canonical_ipv4_24(
    vpn_cidr,
    lifecycle_state,
    acceptance_receipt,
):
    with pytest.raises(ValueError, match="vpn_cidr"):
        replace(
            _planned_awg3_spec(),
            vpn_cidr=vpn_cidr,
            lifecycle_state=lifecycle_state,
            acceptance_receipt=acceptance_receipt,
        )


def test_awg3_runtime_accepts_canonical_ipv4_24():
    candidate = replace(_planned_awg3_spec(), vpn_cidr="10.9.0.0/24")

    assert candidate.vpn_cidr == "10.9.0.0/24"
    assert plan_runtime_instance(candidate, existing=()).admissible is True


@pytest.mark.parametrize(
    "vpn_cidr",
    (
        "2001:db8::1/120",
        "10.8.0.1/24",
        "10.8.0.0/16",
    ),
)
def test_awg2_runtime_cidr_construction_and_planning_remain_unchanged(vpn_cidr):
    runtime = replace(_accepted_awg2_spec(), vpn_cidr=vpn_cidr)

    plan = plan_runtime_instance(runtime, existing=())

    assert runtime.vpn_cidr == vpn_cidr
    assert plan.candidate is runtime
    assert plan.conflicts == ()


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
