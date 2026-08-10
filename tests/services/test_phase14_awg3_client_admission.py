from datetime import datetime, timedelta, timezone

import pytest

from app.services.client_compatibility import (
    ClientCompatibilityEvidence,
    ClientIdentity,
    CompatibilityEvidenceStatus,
    SourceReleaseKind,
    classify_awg3_compatibility,
)
from app.services.protocol_admission import AdmissionRequest, ProtocolAdmissionService
from app.services.vpn_runtime_instances import RuntimeInstanceSpec
from app.vpn.protocol_versions import ProtocolVersion


NOW = datetime(2026, 8, 9, 12, 0, tzinfo=timezone.utc)


def accepted_runtime() -> RuntimeInstanceSpec:
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
        lifecycle_state="accepted",
        acceptance_receipt="sha256:" + "a" * 64,
    )


def build_awg3_evidence(
    *,
    platform: str,
    app_version: str,
    build_id: str,
    release_kind: str,
    import_status: str,
    full_data_status: str,
    import_observed_at: datetime = NOW,
    full_data_observed_at: datetime = NOW,
) -> tuple[ClientCompatibilityEvidence, ...]:
    client = ClientIdentity(
        "amnezia_vpn", platform, app_version, build_id=build_id
    )
    statuses = {
        "unknown": CompatibilityEvidenceStatus.CLAIMED,
        "passed": CompatibilityEvidenceStatus.PASSED,
    }
    source_release_kind = SourceReleaseKind(release_kind)
    return (
        ClientCompatibilityEvidence(
            evidence_id="compat-release",
            client=client,
            protocol_version=ProtocolVersion.AWG3,
            source_kind="official_release",
            release_kind=source_release_kind,
            status=CompatibilityEvidenceStatus.CLAIMED,
            observed_at=NOW,
            safe_reference="release:exact-version",
            scope=f"{platform} {app_version} {build_id}",
        ),
        ClientCompatibilityEvidence(
            evidence_id="compat-local-import",
            client=client,
            protocol_version=ProtocolVersion.AWG3,
            source_kind="local_import",
            release_kind=source_release_kind,
            status=statuses[import_status],
            observed_at=import_observed_at,
            safe_reference="local:import",
            scope=f"{platform} {app_version} {build_id}",
        ),
        ClientCompatibilityEvidence(
            evidence_id="compat-local-full-data",
            client=client,
            protocol_version=ProtocolVersion.AWG3,
            source_kind="full_data",
            release_kind=source_release_kind,
            status=statuses[full_data_status],
            observed_at=full_data_observed_at,
            safe_reference="local:full-data",
            scope=f"{platform} {app_version} {build_id}",
        ),
    )


@pytest.mark.parametrize(
    ("release_kind", "import_status", "full_data_status", "expected"),
    [
        ("stable", "passed", "passed", "accepted"),
        ("stable", "unknown", "unknown", "candidate"),
        ("prerelease", "unknown", "unknown", "candidate"),
        ("unreleased", "unknown", "unknown", "rejected"),
    ],
)
def test_awg3_admission_requires_exact_local_compatibility_evidence(
    release_kind, import_status, full_data_status, expected
):
    evidence = build_awg3_evidence(
        platform="test-platform",
        app_version="exact-version",
        build_id="exact-build",
        release_kind=release_kind,
        import_status=import_status,
        full_data_status=full_data_status,
    )

    assert (
        classify_awg3_compatibility(
            evidence,
            client=evidence[0].client,
            now=NOW,
        ).value
        == expected
    )


@pytest.mark.parametrize("release_kind", ["prerelease", "unreleased"])
def test_nonstable_awg3_release_never_reaches_accepted(release_kind):
    evidence = build_awg3_evidence(
        platform="test-platform",
        app_version="exact-version",
        build_id="exact-build",
        release_kind=release_kind,
        import_status="passed",
        full_data_status="passed",
    )

    assert (
        classify_awg3_compatibility(
            evidence,
            client=evidence[0].client,
            now=NOW,
        ).value
        != "accepted"
    )


@pytest.mark.parametrize(
    ("import_observed_at", "full_data_observed_at"),
    [
        (NOW - timedelta(days=91), NOW),
        (NOW, NOW + timedelta(seconds=1)),
    ],
)
def test_awg3_acceptance_requires_fresh_local_evidence(
    import_observed_at, full_data_observed_at
):
    evidence = build_awg3_evidence(
        platform="test-platform",
        app_version="exact-version",
        build_id="exact-build",
        release_kind="stable",
        import_status="passed",
        full_data_status="passed",
        import_observed_at=import_observed_at,
        full_data_observed_at=full_data_observed_at,
    )

    assert (
        classify_awg3_compatibility(
            evidence,
            client=evidence[0].client,
            now=NOW,
        ).value
        != "accepted"
    )


def test_awg3_release_note_passed_alone_cannot_admit_client():
    evidence = ClientCompatibilityEvidence(
        evidence_id="compat-release-only",
        client=ClientIdentity(
            "amnezia_vpn",
            "test-platform",
            "exact-version",
            build_id="exact-build",
        ),
        protocol_version=ProtocolVersion.AWG3,
        source_kind="official_release",
        status=CompatibilityEvidenceStatus.PASSED,
        observed_at=NOW,
        safe_reference="release:exact-version",
        scope="test-platform exact-version exact-build",
        release_kind=SourceReleaseKind.STABLE,
    )

    result = ProtocolAdmissionService(
        evidence=(evidence,),
        runtimes=(accepted_runtime(),),
        now=NOW,
    ).decide(
        AdmissionRequest(
            client=ClientIdentity(
                "amnezia_vpn",
                "test-platform",
                "exact-version",
                build_id="exact-build",
            ),
            protocol_version=ProtocolVersion.AWG3,
        )
    )

    assert result.admitted is False


@pytest.mark.parametrize(
    ("platform", "version", "build_id"),
    [
        ("other-platform", "exact-version", "exact-build"),
        ("test-platform", "other-version", "exact-build"),
        ("test-platform", "exact-version", "other-build"),
        ("test-platform", "exact-version", None),
    ],
)
def test_awg3_evidence_cannot_admit_another_exact_client_identity(
    platform, version, build_id
):
    evidence = build_awg3_evidence(
        platform="test-platform",
        app_version="exact-version",
        build_id="exact-build",
        release_kind="stable",
        import_status="passed",
        full_data_status="passed",
    )

    result = ProtocolAdmissionService(
        evidence=evidence,
        runtimes=(accepted_runtime(),),
        now=NOW,
    ).decide(
        AdmissionRequest(
            client=ClientIdentity(
                "amnezia_vpn", platform, version, build_id=build_id
            ),
            protocol_version=ProtocolVersion.AWG3,
        )
    )

    assert result.admitted is False
