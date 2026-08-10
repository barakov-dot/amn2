from datetime import datetime, timezone

import pytest

from app.services.client_compatibility import (
    ClientCompatibilityEvidence,
    ClientIdentity,
    CompatibilityEvidenceStatus,
    SourceReleaseKind,
)
from app.vpn.protocol_versions import ProtocolVersion


@pytest.mark.parametrize("version", [None, "", "latest", " 5.0.0.5", "5.0.0.5 "])
def test_client_identity_rejects_unknown_or_ambiguous_version(version):
    with pytest.raises(ValueError, match="exact client_version"):
        ClientIdentity("amnezia_vpn", "windows", version)


def test_client_identity_normalizes_known_application_and_platform():
    identity = ClientIdentity("AmneziaVPN", "Windows", "5.0.0.5")
    assert identity == ClientIdentity("amnezia_vpn", "windows", "5.0.0.5")


@pytest.mark.parametrize("build_id", ["", "latest", " exact-build", "exact-build "])
def test_client_identity_rejects_ambiguous_build_identity(build_id):
    with pytest.raises(ValueError, match="exact client_build is required"):
        ClientIdentity(
            "amnezia_vpn",
            "windows",
            "5.0.0.5",
            build_id=build_id,
        )


def test_compatibility_evidence_requires_timezone_aware_timestamp():
    with pytest.raises(ValueError, match="observed_at"):
        ClientCompatibilityEvidence(
            evidence_id="compat-win-5005-awg3",
            client=ClientIdentity("amnezia_vpn", "windows", "5.0.0.5"),
            protocol_version=ProtocolVersion.AWG3,
            source_kind="full_data",
            status=CompatibilityEvidenceStatus.PASSED,
            observed_at=datetime(2026, 8, 1, 12, 0),
            safe_reference="receipt:passed",
            scope="windows exact build 5.0.0.5",
        )


def test_compatibility_evidence_is_secret_free_and_bounded():
    with pytest.raises(ValueError, match="safe_reference"):
        ClientCompatibilityEvidence(
            evidence_id="compat-win-5005-awg3",
            client=ClientIdentity("amnezia_vpn", "windows", "5.0.0.5"),
            protocol_version=ProtocolVersion.AWG3,
            source_kind="full_data",
            status=CompatibilityEvidenceStatus.PASSED,
            observed_at=datetime(2026, 8, 1, 12, 0, tzinfo=timezone.utc),
            safe_reference="x" * 1025,
            scope="windows exact build 5.0.0.5",
        )


def test_compatibility_evidence_rejects_open_release_kind_value():
    with pytest.raises(ValueError, match="release_kind"):
        ClientCompatibilityEvidence(
            evidence_id="compat-win-5005-awg3",
            client=ClientIdentity(
                "amnezia_vpn", "windows", "5.0.0.5", build_id="exact-build"
            ),
            protocol_version=ProtocolVersion.AWG3,
            source_kind="official_release",
            status=CompatibilityEvidenceStatus.CLAIMED,
            observed_at=datetime(2026, 8, 1, 12, 0, tzinfo=timezone.utc),
            safe_reference="release:5.0.0.5",
            scope="windows exact build 5.0.0.5",
            release_kind="stable",
        )


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("stable", SourceReleaseKind.STABLE),
        ("prerelease", SourceReleaseKind.PRERELEASE),
        ("unreleased", SourceReleaseKind.UNRELEASED),
    ],
)
def test_source_release_kind_has_closed_values(value, expected):
    assert SourceReleaseKind(value) is expected
