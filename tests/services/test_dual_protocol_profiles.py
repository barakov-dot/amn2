from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass

import pytest

from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.services.device_passports import create_device_passport
from app.vpn.protocol_versions import ProtocolVersion


@dataclass(frozen=True)
class ProfileHarness:
    conn: sqlite3.Connection
    repo: Repository
    passport_device_id: str
    awg2_device_id: int
    awg3_device_id: int
    replacement_device_id: int


@pytest.fixture
def harness() -> ProfileHarness:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    initialize_schema(conn)
    repo = Repository(conn)
    user_id = repo.upsert_user(
        telegram_id=9301,
        username="dual-profile-user",
        first_name="Dual",
        last_name="Profile",
    )
    server_id = repo.ensure_default_server(
        name="dual-profile-server",
        network_cidr="10.213.0.0/24",
    )
    awg2_device_id = _create_local_device(
        repo,
        user_id=user_id,
        server_id=server_id,
        sequence=2,
        protocol=ProtocolVersion.AWG2,
    )
    awg3_device_id = _create_local_device(
        repo,
        user_id=user_id,
        server_id=server_id,
        sequence=3,
        protocol=ProtocolVersion.AWG3,
    )
    replacement_device_id = _create_local_device(
        repo,
        user_id=user_id,
        server_id=server_id,
        sequence=4,
        protocol=ProtocolVersion.AWG3,
    )
    passport = create_device_passport(
        repo,
        owner_user_id=user_id,
        local_device_id=awg2_device_id,
        platform="windows",
        official_client_type="amnezia_vpn",
        import_method="conf_file",
        config_schema_version="amneziawg_v2",
        config_text="safe-config-fingerprint-source",
        protocol_version="awg2",
    )
    return ProfileHarness(
        conn=conn,
        repo=repo,
        passport_device_id=passport.device_id,
        awg2_device_id=awg2_device_id,
        awg3_device_id=awg3_device_id,
        replacement_device_id=replacement_device_id,
    )


def test_one_passport_can_hold_one_active_profile_per_protocol(
    harness: ProfileHarness,
):
    service = _service(harness.repo)
    awg2 = service.attach_active(
        harness.passport_device_id,
        ProtocolVersion.AWG2,
        harness.awg2_device_id,
    )
    awg3 = service.attach_active(
        harness.passport_device_id,
        ProtocolVersion.AWG3,
        harness.awg3_device_id,
    )

    assert (awg2.local_device_id, awg3.local_device_id) == (
        harness.awg2_device_id,
        harness.awg3_device_id,
    )
    with pytest.raises(ValueError, match="active awg3 profile already exists"):
        service.attach_active(
            harness.passport_device_id,
            ProtocolVersion.AWG3,
            harness.replacement_device_id,
        )


def test_normal_replacement_keeps_old_effective_until_activation_and_is_protocol_local(
    harness: ProfileHarness,
):
    service = _service(harness.repo)
    awg2 = service.attach_active(
        harness.passport_device_id,
        ProtocolVersion.AWG2,
        harness.awg2_device_id,
    )
    old = service.attach_active(
        harness.passport_device_id,
        ProtocolVersion.AWG3,
        harness.awg3_device_id,
    )

    pending = service.start_replacement(
        old.profile_id,
        replacement_device_id=harness.replacement_device_id,
    )

    assert pending.lifecycle_state == "pending_replacement"
    assert pending.local_device_id == harness.awg3_device_id
    assert pending.replacement_device_id == harness.replacement_device_id
    assert service.get(awg2.profile_id).lifecycle_state == "active"
    assert service.get(awg2.profile_id).local_device_id == harness.awg2_device_id

    activated = service.activate_replacement(old.profile_id)

    assert activated.lifecycle_state == "active"
    assert activated.local_device_id == harness.replacement_device_id
    assert activated.replacement_device_id is None
    assert service.by_local_device_id(
        harness.awg3_device_id
    ).lifecycle_state == "revoked"
    assert service.get(awg2.profile_id).lifecycle_state == "active"


def test_start_replacement_rejects_a_second_pending_replacement(
    harness: ProfileHarness,
):
    service = _service(harness.repo)
    old = service.attach_active(
        harness.passport_device_id,
        ProtocolVersion.AWG3,
        harness.awg3_device_id,
    )
    service.start_replacement(
        old.profile_id,
        replacement_device_id=harness.replacement_device_id,
    )

    with pytest.raises(ValueError, match="replacement already pending"):
        service.start_replacement(
            old.profile_id,
            replacement_device_id=harness.awg2_device_id,
        )


def test_compromise_reissue_revokes_old_before_new_issue(
    harness: ProfileHarness,
):
    service = _service(harness.repo)
    old = service.attach_active(
        harness.passport_device_id,
        ProtocolVersion.AWG3,
        harness.awg3_device_id,
    )
    observations: list[str] = []

    def issue_device(protocol: ProtocolVersion) -> int:
        assert protocol is ProtocolVersion.AWG3
        observations.append(
            service.by_local_device_id(
                harness.awg3_device_id
            ).lifecycle_state
        )
        observations.append("replacement_issued")
        return harness.replacement_device_id

    result = service.compromise_reissue(
        old.profile_id,
        replacement_factory=issue_device,
        actor_id=700,
        reason="suspected config leak",
    )

    assert observations == ["revoked", "replacement_issued"]
    assert service.by_local_device_id(
        harness.awg3_device_id
    ).lifecycle_state == "revoked"
    assert result.protocol_version is ProtocolVersion.AWG3
    assert result.local_device_id == harness.replacement_device_id


def test_compromise_reissue_failure_stays_revoked_and_records_secret_safe_event(
    harness: ProfileHarness,
):
    service = _service(harness.repo)
    old = service.attach_active(
        harness.passport_device_id,
        ProtocolVersion.AWG3,
        harness.awg3_device_id,
    )
    factory_secret = "factory-private-key-never-log"

    def failing_factory(_protocol: ProtocolVersion) -> int:
        assert service.by_local_device_id(
            harness.awg3_device_id
        ).lifecycle_state == "revoked"
        raise RuntimeError(factory_secret)

    with pytest.raises(RuntimeError, match=factory_secret):
        service.compromise_reissue(
            old.profile_id,
            replacement_factory=failing_factory,
            actor_id=700,
            reason="suspected config leak",
        )

    assert service.by_local_device_id(
        harness.awg3_device_id
    ).lifecycle_state == "revoked"
    with pytest.raises(ValueError, match="profile is revoked"):
        service.mark_review_required(old.profile_id)
    with pytest.raises(ValueError, match="profile is revoked"):
        service.mark_temporarily_unavailable(old.profile_id)
    rows = harness.conn.execute(
        "SELECT event_type, metadata_json FROM protocol_config_events ORDER BY id"
    ).fetchall()
    assert [str(row["event_type"]) for row in rows][-2:] == [
        "compromise_reissue_revoked",
        "compromise_reissue_failed",
    ]
    serialized_events = json.dumps(
        [dict(row) for row in rows], sort_keys=True
    )
    assert factory_secret not in serialized_events
    assert "RuntimeError" not in serialized_events


def test_review_and_temporary_unavailable_transitions_append_one_event_each(
    harness: ProfileHarness,
):
    service = _service(harness.repo)
    profile = service.attach_active(
        harness.passport_device_id,
        ProtocolVersion.AWG2,
        harness.awg2_device_id,
    )
    before = harness.conn.execute(
        "SELECT COUNT(*) FROM protocol_config_events"
    ).fetchone()[0]

    reviewed = service.mark_review_required(
        profile.profile_id,
        actor_id=700,
        reason="operator review",
    )
    unavailable = service.mark_temporarily_unavailable(
        profile.profile_id,
        actor_id=700,
        reason="runtime maintenance",
    )

    assert reviewed.lifecycle_state == "review_required"
    assert unavailable.lifecycle_state == "temporarily_unavailable"
    rows = harness.conn.execute(
        "SELECT event_type FROM protocol_config_events ORDER BY id"
    ).fetchall()
    assert [str(row["event_type"]) for row in rows][-2:] == [
        "protocol_profile_review_required",
        "protocol_profile_temporarily_unavailable",
    ]
    assert len(rows) == before + 2


def _service(repo: Repository):
    from app.services.dual_protocol_profiles import DualProtocolProfileService

    return DualProtocolProfileService(repo)


def _create_local_device(
    repo: Repository,
    *,
    user_id: int,
    server_id: int,
    sequence: int,
    protocol: ProtocolVersion,
) -> int:
    return repo.create_device(
        user_id=user_id,
        server_id=server_id,
        name=f"dual-profile-{sequence}",
        duration_days=30,
        vpn_ip=f"10.213.0.{sequence}",
        peer_public_key=f"public-key-{sequence}",
        peer_private_key_encrypted=f"encrypted-private-{sequence}",
        preshared_key_encrypted=f"encrypted-psk-{sequence}",
        config_version=(
            "amneziawg_v3"
            if protocol is ProtocolVersion.AWG3
            else "amneziawg_v2"
        ),
        protocol_version=protocol.value,
    )
