from dataclasses import replace
from datetime import datetime, timedelta, timezone

from app.services.client_compatibility import (
    ClientCompatibilityEvidence,
    ClientIdentity,
    CompatibilityEvidenceStatus,
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


def evidence(status: CompatibilityEvidenceStatus) -> ClientCompatibilityEvidence:
    return ClientCompatibilityEvidence(
        evidence_id=f"compat-win-5005-awg3-{status.value}",
        client=ClientIdentity("amnezia_vpn", "windows", "5.0.0.5"),
        protocol_version=ProtocolVersion.AWG3,
        source_kind="full_data" if status is CompatibilityEvidenceStatus.PASSED else "official_release",
        status=status,
        observed_at=NOW,
        safe_reference=f"receipt:{status.value}",
        scope="windows exact build 5.0.0.5",
    )


def request(application: str, version: str) -> AdmissionRequest:
    return AdmissionRequest(
        client=ClientIdentity(application, "windows", version),
        protocol_version=ProtocolVersion.AWG3,
    )


def test_official_claim_alone_does_not_admit_awg3():
    service = ProtocolAdmissionService(
        evidence=(evidence(CompatibilityEvidenceStatus.CLAIMED),),
        runtimes=(runtime(ProtocolVersion.AWG3, accepted=True),),
        now=NOW,
    )
    result = service.decide(request("amnezia_vpn", "5.0.0.5"))
    assert result.decision == "blocked_unverified_version"
    assert result.compatibility_evidence_id is None


def test_future_dated_passed_evidence_fails_closed():
    future = replace(
        evidence(CompatibilityEvidenceStatus.PASSED),
        observed_at=NOW + timedelta(seconds=1),
    )
    result = ProtocolAdmissionService(
        evidence=(future,),
        runtimes=(runtime(ProtocolVersion.AWG3, accepted=True),),
        now=NOW,
    ).decide(request("amnezia_vpn", "5.0.0.5"))
    assert result.decision == "blocked_evidence_stale_or_failed"


def test_passed_exact_client_and_accepted_runtime_admit_awg3():
    service = ProtocolAdmissionService(
        evidence=(evidence(CompatibilityEvidenceStatus.PASSED),),
        runtimes=(runtime(ProtocolVersion.AWG3, accepted=True),),
        now=NOW,
    )
    result = service.decide(request("amnezia_vpn", "5.0.0.5"))
    assert result.decision == "admitted_awg3"
    assert result.runtime_instance_id == "rt-spain-awg3"


def test_passed_client_with_candidate_runtime_stays_candidate():
    service = ProtocolAdmissionService(
        evidence=(evidence(CompatibilityEvidenceStatus.PASSED),),
        runtimes=(runtime(ProtocolVersion.AWG3, accepted=False),),
        now=NOW,
    )
    result = service.decide(request("amnezia_vpn", "5.0.0.5"))
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
