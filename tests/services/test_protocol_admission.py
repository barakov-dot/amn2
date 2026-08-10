import importlib
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from app.services.client_compatibility import (
    ClientCompatibilityEvidence,
    ClientIdentity,
    CompatibilityEvidenceStatus,
    SourceReleaseKind,
)
from app.services.protocol_admission import (
    AdmissionRequest,
    ProtocolAdmissionService,
)
from app.services.vpn_runtime_instances import RuntimeInstanceSpec
from app.vpn.protocol_versions import ProtocolVersion


NOW = datetime(2026, 8, 1, 12, 0, tzinfo=timezone.utc)


def runtime(protocol: ProtocolVersion, *, accepted: bool) -> RuntimeInstanceSpec:
    return RuntimeInstanceSpec(
        runtime_instance_id=f"rt-spain-{protocol.value}",
        server_id=1,
        protocol_version=protocol,
        runtime_version="3.0.3" if protocol is ProtocolVersion.AWG3 else "accepted-phase12",
        interface_name="awg3" if protocol is ProtocolVersion.AWG3 else "awg0",
        udp_port=30002 if protocol is ProtocolVersion.AWG3 else 30001,
        vpn_cidr="10.212.13.0/24" if protocol is ProtocolVersion.AWG3 else "10.212.12.0/24",
        container_name=f"amn2-{protocol.value}",
        service_name=None,
        config_path=f"/opt/amn2/{protocol.value}/wg0.conf",
        lifecycle_state="accepted" if accepted else "candidate",
        acceptance_receipt=("sha256:" + "a" * 64) if accepted else None,
    )


def evidence(
    source_kind: str,
    status: CompatibilityEvidenceStatus,
) -> ClientCompatibilityEvidence:
    return ClientCompatibilityEvidence(
        evidence_id=f"compat-win-5005-awg3-{source_kind}-{status.value}",
        client=ClientIdentity(
            "amnezia_vpn", "windows", "5.0.0.5", build_id="exact-build"
        ),
        protocol_version=ProtocolVersion.AWG3,
        source_kind=source_kind,
        status=status,
        observed_at=NOW,
        safe_reference=f"receipt:{status.value}",
        scope="windows exact build 5.0.0.5",
        release_kind=SourceReleaseKind.STABLE,
    )


def complete_evidence() -> tuple[ClientCompatibilityEvidence, ...]:
    return (
        evidence("official_release", CompatibilityEvidenceStatus.CLAIMED),
        evidence("local_import", CompatibilityEvidenceStatus.PASSED),
        evidence("full_data", CompatibilityEvidenceStatus.PASSED),
    )


def request(application: str, version: str) -> AdmissionRequest:
    return AdmissionRequest(
        client=ClientIdentity(
            application, "windows", version, build_id="exact-build"
        ),
        protocol_version=ProtocolVersion.AWG3,
    )


def permitting_awg3_state():
    module = importlib.import_module("app.services.awg3_control")
    return module.Awg3ControlState(
        runtime_accepted=True,
        global_accepted=True,
        issuance_enabled=True,
        emergency_suspended=False,
        runtime_receipt="sha256:" + "a" * 64,
    )


def decide_exact_awg3(
    runtime_accepted: bool,
    build_accepted: bool,
    issuance_enabled: bool,
    emergency_suspended: bool,
):
    module = importlib.import_module("app.services.awg3_control")
    client = request("amnezia_vpn", "5.0.0.5").client
    control_state = module.Awg3ControlState(
        runtime_accepted=runtime_accepted,
        global_accepted=build_accepted,
        issuance_enabled=issuance_enabled,
        emergency_suspended=emergency_suspended,
        runtime_receipt=("sha256:" + "a" * 64) if runtime_accepted else None,
    )
    return ProtocolAdmissionService(
        evidence=complete_evidence(),
        runtimes=(runtime(ProtocolVersion.AWG3, accepted=True),),
        now=NOW,
        awg3_control_state=control_state,
        accepted_awg3_builds=frozenset({client}) if build_accepted else frozenset(),
    ).decide(AdmissionRequest(client=client, protocol_version=ProtocolVersion.AWG3))


@pytest.mark.parametrize(
    ("runtime", "build", "enabled", "suspended", "decision"),
    [
        (False, False, False, False, "blocked_global_acceptance"),
        (True, False, False, False, "blocked_global_acceptance"),
        (True, True, False, False, "blocked_issuance_disabled"),
        (True, True, True, True, "blocked_runtime_suspended"),
        (True, True, True, False, "admitted_awg3"),
    ],
)
def test_awg3_gate_order(runtime, build, enabled, suspended, decision):
    result = decide_exact_awg3(runtime, build, enabled, suspended)
    assert result.decision == decision


def test_awg3_admission_without_injected_controls_fails_closed():
    result = ProtocolAdmissionService(
        evidence=complete_evidence(),
        runtimes=(runtime(ProtocolVersion.AWG3, accepted=True),),
        now=NOW,
    ).decide(request("amnezia_vpn", "5.0.0.5"))

    assert result.decision == "blocked_global_acceptance"
    assert result.admitted is False


def test_awg2_admission_does_not_access_awg3_control_state():
    class ForbiddenAwg3State:
        def __getattribute__(self, name):
            raise AssertionError(f"AWG2 read AWG3 state: {name}")

        def __setattr__(self, name, value):
            raise AssertionError(f"AWG2 mutated AWG3 state: {name}")

    client = ClientIdentity("amnezia_vpn", "windows", "5.0.0.5")
    awg2_evidence = ClientCompatibilityEvidence(
        evidence_id="compat-win-5005-awg2-passed-independent",
        client=client,
        protocol_version=ProtocolVersion.AWG2,
        source_kind="full_data",
        status=CompatibilityEvidenceStatus.PASSED,
        observed_at=NOW,
        safe_reference="receipt:awg2-independent",
        scope="windows exact version 5.0.0.5",
    )

    result = ProtocolAdmissionService(
        evidence=(awg2_evidence,),
        runtimes=(runtime(ProtocolVersion.AWG2, accepted=True),),
        now=NOW,
        awg3_control_state=ForbiddenAwg3State(),
        accepted_awg3_builds=ForbiddenAwg3State(),
    ).decide(AdmissionRequest(client=client, protocol_version=ProtocolVersion.AWG2))

    assert result.decision == "admitted_awg2"


def test_official_claim_alone_does_not_admit_awg3():
    service = ProtocolAdmissionService(
        evidence=(
            evidence("official_release", CompatibilityEvidenceStatus.CLAIMED),
        ),
        runtimes=(runtime(ProtocolVersion.AWG3, accepted=True),),
        now=NOW,
    )
    result = service.decide(request("amnezia_vpn", "5.0.0.5"))
    assert result.decision == "candidate_awg3"
    assert result.admitted is False
    assert result.compatibility_evidence_id is None


def test_future_dated_passed_evidence_fails_closed():
    future = replace(
        evidence("full_data", CompatibilityEvidenceStatus.PASSED),
        observed_at=NOW + timedelta(seconds=1),
    )
    result = ProtocolAdmissionService(
        evidence=(
            evidence("official_release", CompatibilityEvidenceStatus.CLAIMED),
            evidence("local_import", CompatibilityEvidenceStatus.PASSED),
            future,
        ),
        runtimes=(runtime(ProtocolVersion.AWG3, accepted=True),),
        now=NOW,
    ).decide(request("amnezia_vpn", "5.0.0.5"))
    assert result.decision == "blocked_evidence_stale_or_failed"


def test_passed_exact_client_and_accepted_runtime_admit_awg3():
    client = request("amnezia_vpn", "5.0.0.5").client
    service = ProtocolAdmissionService(
        evidence=complete_evidence(),
        runtimes=(runtime(ProtocolVersion.AWG3, accepted=True),),
        now=NOW,
        awg3_control_state=permitting_awg3_state(),
        accepted_awg3_builds=frozenset({client}),
    )
    result = service.decide(
        AdmissionRequest(client=client, protocol_version=ProtocolVersion.AWG3)
    )
    assert result.decision == "admitted_awg3"
    assert result.runtime_instance_id == "rt-spain-awg3"


def test_passed_client_with_candidate_runtime_stays_candidate():
    client = request("amnezia_vpn", "5.0.0.5").client
    service = ProtocolAdmissionService(
        evidence=complete_evidence(),
        runtimes=(runtime(ProtocolVersion.AWG3, accepted=False),),
        now=NOW,
        awg3_control_state=permitting_awg3_state(),
        accepted_awg3_builds=frozenset({client}),
    )
    result = service.decide(
        AdmissionRequest(client=client, protocol_version=ProtocolVersion.AWG3)
    )
    assert result.decision == "candidate_awg3"
    assert result.admitted is False


def test_unknown_awg3_does_not_silently_fallback_to_awg2():
    service = ProtocolAdmissionService(
        evidence=(),
        runtimes=(runtime(ProtocolVersion.AWG2, accepted=True),),
        now=NOW,
    )
    result = service.decide(request("unknown", "1.0.0"))
    assert result.decision == "blocked_unknown_client"
    assert result.protocol_version is ProtocolVersion.AWG3


def test_legacy_awg2_passed_evidence_remains_admitted():
    client = ClientIdentity("amnezia_vpn", "windows", "5.0.0.5")
    awg2_evidence = ClientCompatibilityEvidence(
        evidence_id="compat-win-5005-awg2-passed",
        client=client,
        protocol_version=ProtocolVersion.AWG2,
        source_kind="full_data",
        status=CompatibilityEvidenceStatus.PASSED,
        observed_at=NOW,
        safe_reference="receipt:passed",
        scope="windows exact version 5.0.0.5",
    )
    result = ProtocolAdmissionService(
        evidence=(awg2_evidence,),
        runtimes=(runtime(ProtocolVersion.AWG2, accepted=True),),
        now=NOW,
    ).decide(
        AdmissionRequest(client=client, protocol_version=ProtocolVersion.AWG2)
    )

    assert result.decision == "admitted_awg2"
    assert result.compatibility_evidence_id == awg2_evidence.evidence_id
