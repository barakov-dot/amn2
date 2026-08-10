import importlib
import sqlite3
from datetime import datetime, timezone

import pytest

from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.services.client_compatibility import (
    ClientCompatibilityEvidence,
    ClientIdentity,
    CompatibilityEvidenceStatus,
    SourceReleaseKind,
)
from app.vpn.protocol_versions import ProtocolVersion


NOW = datetime(2026, 8, 10, 12, 0, tzinfo=timezone.utc)
RUNTIME_RECEIPT = "sha256:" + "a" * 64
FRESH_RUNTIME_RECEIPT = "sha256:" + "b" * 64


@pytest.fixture
def repo():
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    initialize_schema(connection)
    try:
        yield Repository(connection)
    finally:
        connection.close()


def awg3_control_module():
    return importlib.import_module("app.services.awg3_control")


def exact_client() -> ClientIdentity:
    return ClientIdentity(
        "amnezia_vpn", "windows", "5.0.0.5", build_id="exact-build"
    )


def complete_evidence() -> tuple[ClientCompatibilityEvidence, ...]:
    client = exact_client()
    return tuple(
        ClientCompatibilityEvidence(
            evidence_id=f"compat-{source_kind}",
            client=client,
            protocol_version=ProtocolVersion.AWG3,
            source_kind=source_kind,
            status=(
                CompatibilityEvidenceStatus.CLAIMED
                if source_kind == "official_release"
                else CompatibilityEvidenceStatus.PASSED
            ),
            observed_at=NOW,
            safe_reference=f"receipt:{source_kind}",
            scope="windows 5.0.0.5 exact-build",
            release_kind=SourceReleaseKind.STABLE,
        )
        for source_kind in ("official_release", "local_import", "full_data")
    )


def test_accept_runtime_and_exact_build_allow_explicit_issuance_enable(repo):
    module = awg3_control_module()
    service = module.Awg3ControlService(repo, now=NOW)

    runtime_state = service.accept_runtime(
        runtime_receipt=RUNTIME_RECEIPT,
        actor_id=14001,
        reason="local runtime accepted",
    )
    build_state = service.accept_build(
        client=exact_client(),
        evidence=complete_evidence(),
        actor_id=14001,
        reason="exact stable build accepted",
    )
    enabled_state = service.set_issuance_enabled(
        True,
        accepted_build=exact_client(),
        actor_id=14001,
        reason="enable after local acceptance",
    )

    assert runtime_state.runtime_accepted is True
    assert build_state is module.ClientBuildState.ACCEPTED
    assert enabled_state.permits_new_issuance is True
    build_row = repo.get_client_build_acceptance(
        application="amnezia_vpn",
        platform="windows",
        client_version="5.0.0.5",
        client_build="exact-build",
    )
    assert build_row is not None
    assert build_row["state"] == "accepted"
    assert build_row["evidence_ids_json"] == (
        '["compat-official_release","compat-local_import","compat-full_data"]'
    )


def test_build_without_all_three_current_evidence_kinds_stays_candidate(repo):
    module = awg3_control_module()
    state = module.Awg3ControlService(repo, now=NOW).accept_build(
        client=exact_client(),
        evidence=complete_evidence()[:-1],
        actor_id=14001,
        reason="incomplete local evidence",
    )

    assert state is module.ClientBuildState.CANDIDATE
    row = repo.get_client_build_acceptance(
        application="amnezia_vpn",
        platform="windows",
        client_version="5.0.0.5",
        client_build="exact-build",
    )
    assert row is not None
    assert row["state"] == "candidate"
    assert repo.get_awg3_control_state()["global_accepted"] == 0


def test_enabling_issuance_fails_closed_without_runtime_and_accepted_build(repo):
    module = awg3_control_module()
    service = module.Awg3ControlService(repo, now=NOW)

    with pytest.raises(ValueError, match="runtime acceptance is required"):
        service.set_issuance_enabled(
            True,
            accepted_build=exact_client(),
            actor_id=14001,
            reason="must fail closed",
        )

    service.accept_runtime(
        runtime_receipt=RUNTIME_RECEIPT,
        actor_id=14001,
        reason="runtime accepted",
    )
    with pytest.raises(ValueError, match="accepted exact build is required"):
        service.set_issuance_enabled(
            True,
            accepted_build=exact_client(),
            actor_id=14001,
            reason="must still fail closed",
        )

    state = repo.get_awg3_control_state()
    assert state["issuance_enabled"] == 0
    assert state["global_accepted"] == 0


def test_emergency_suspend_disables_issuance_and_resume_requires_fresh_receipt(repo):
    module = awg3_control_module()
    service = module.Awg3ControlService(repo, now=NOW)
    service.accept_runtime(
        runtime_receipt=RUNTIME_RECEIPT,
        actor_id=14001,
        reason="runtime accepted",
    )
    service.accept_build(
        client=exact_client(),
        evidence=complete_evidence(),
        actor_id=14001,
        reason="build accepted",
    )
    service.set_issuance_enabled(
        True,
        accepted_build=exact_client(),
        actor_id=14001,
        reason="issuance enabled",
    )

    suspended = service.emergency_suspend(
        actor_id=14001,
        reason="controlled emergency suspension",
    )
    assert suspended.emergency_suspended is True
    assert suspended.issuance_enabled is False

    with pytest.raises(ValueError, match="fresh runtime receipt is required"):
        service.resume_after_preflight(
            runtime_receipt=RUNTIME_RECEIPT,
            actor_id=14001,
            reason="stale preflight receipt",
        )
    with pytest.raises(ValueError, match="valid runtime receipt is required"):
        service.resume_after_preflight(
            runtime_receipt="sha256:" + "A" * 64,
            actor_id=14001,
            reason="malformed preflight receipt",
        )

    resumed = service.resume_after_preflight(
        runtime_receipt=FRESH_RUNTIME_RECEIPT,
        actor_id=14001,
        reason="fresh preflight passed",
    )
    assert resumed.runtime_accepted is True
    assert resumed.emergency_suspended is False
    assert resumed.issuance_enabled is False
    assert resumed.runtime_receipt == FRESH_RUNTIME_RECEIPT
