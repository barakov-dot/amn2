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


def test_fresh_service_uses_direct_durable_profile_lookups(
    harness: ProfileHarness,
    monkeypatch: pytest.MonkeyPatch,
):
    profile = _service(harness.repo).attach_active(
        harness.passport_device_id,
        ProtocolVersion.AWG3,
        harness.awg3_device_id,
    )

    def fail_if_passports_are_scanned(*_args, **_kwargs):
        raise AssertionError("profile lookup must not scan passports")

    monkeypatch.setattr(
        harness.repo,
        "list_device_passports",
        fail_if_passports_are_scanned,
    )
    fresh = _service(harness.repo)

    assert fresh.get(profile.profile_id) == profile
    assert fresh.by_local_device_id(harness.awg3_device_id) == profile


def test_profile_lookup_is_not_limited_to_the_latest_100_passports(
    harness: ProfileHarness,
):
    profile = _service(harness.repo).attach_active(
        harness.passport_device_id,
        ProtocolVersion.AWG3,
        harness.awg3_device_id,
    )
    harness.conn.execute(
        "UPDATE device_passports SET updated_at = ? WHERE device_id = ?",
        ("2026-01-01 00:00:00", harness.passport_device_id),
    )
    harness.conn.commit()
    owner_user_id = int(
        harness.repo.get_device(harness.awg2_device_id)["user_id"]
    )
    for sequence in range(101):
        create_device_passport(
            harness.repo,
            owner_user_id=owner_user_id,
            local_device_id=None,
            platform="unknown",
            official_client_type="unknown_official",
            import_method="unknown",
            config_schema_version="amneziawg_v2",
            config_text=f"bounded-scan-regression-{sequence}",
        )

    fresh = _service(harness.repo)

    assert fresh.get(profile.profile_id) == profile
    assert fresh.by_local_device_id(harness.awg3_device_id) == profile


def test_repeated_replacement_swaps_current_identity_and_retires_each_old_device(
    harness: ProfileHarness,
):
    owner = harness.repo.get_device(harness.awg3_device_id)
    second_replacement_device_id = _create_local_device(
        harness.repo,
        user_id=int(owner["user_id"]),
        server_id=int(owner["server_id"]),
        sequence=5,
        protocol=ProtocolVersion.AWG3,
    )
    service = _service(harness.repo)
    original = service.attach_active(
        harness.passport_device_id,
        ProtocolVersion.AWG3,
        harness.awg3_device_id,
    )
    service.start_replacement(
        original.profile_id,
        replacement_device_id=harness.replacement_device_id,
    )
    first = service.activate_replacement(original.profile_id)
    first_row = harness.repo.get_device_protocol_profile(
        passport_device_id=harness.passport_device_id,
        protocol_version="awg3",
    )

    assert first.local_device_id == harness.replacement_device_id
    assert int(first_row["local_device_id"]) == harness.replacement_device_id
    assert first_row["replacement_device_id"] is None

    restarted = _service(harness.repo)
    pending = restarted.start_replacement(
        original.profile_id,
        replacement_device_id=second_replacement_device_id,
    )
    second = restarted.activate_replacement(original.profile_id)

    assert pending.local_device_id == harness.replacement_device_id
    assert second.local_device_id == second_replacement_device_id
    assert second.replacement_device_id is None
    after_second_restart = _service(harness.repo)
    assert after_second_restart.get(original.profile_id) == second
    assert after_second_restart.by_local_device_id(
        harness.awg3_device_id
    ).lifecycle_state == "revoked"
    assert after_second_restart.by_local_device_id(
        harness.replacement_device_id
    ).lifecycle_state == "revoked"
    assert after_second_restart.by_local_device_id(
        second_replacement_device_id
    ) == second
    retirements = harness.conn.execute(
        """
        SELECT local_device_id, metadata_json
        FROM protocol_config_events
        WHERE event_type = 'protocol_profile_retired'
        ORDER BY id
        """
    ).fetchall()
    assert [int(row["local_device_id"]) for row in retirements] == [
        harness.awg3_device_id,
        harness.replacement_device_id,
    ]
    assert [json.loads(str(row["metadata_json"])) for row in retirements] == [
        {"lifecycle_state": "revoked", "profile_id": original.profile_id},
        {"lifecycle_state": "revoked", "profile_id": original.profile_id},
    ]


def test_activation_event_failure_rolls_back_without_cache_divergence(
    harness: ProfileHarness,
    monkeypatch: pytest.MonkeyPatch,
):
    service = _service(harness.repo)
    original = service.attach_active(
        harness.passport_device_id,
        ProtocolVersion.AWG3,
        harness.awg3_device_id,
    )
    pending = service.start_replacement(
        original.profile_id,
        replacement_device_id=harness.replacement_device_id,
    )
    before_events = harness.conn.execute(
        "SELECT COUNT(*) FROM protocol_config_events"
    ).fetchone()[0]

    def fail_event(**_kwargs):
        raise RuntimeError("forced event failure")

    monkeypatch.setattr(
        harness.repo,
        "append_protocol_config_event",
        fail_event,
    )

    with pytest.raises(RuntimeError, match="forced event failure"):
        service.activate_replacement(original.profile_id)

    assert service.get(original.profile_id) == pending
    assert service.by_local_device_id(harness.awg3_device_id) == pending
    assert _service(harness.repo).get(original.profile_id) == pending
    assert harness.conn.execute(
        "SELECT COUNT(*) FROM protocol_config_events"
    ).fetchone()[0] == before_events


def test_activation_revalidates_pending_device_owner_before_cas_and_event(
    harness: ProfileHarness,
):
    service = _service(harness.repo)
    original = service.attach_active(
        harness.passport_device_id,
        ProtocolVersion.AWG3,
        harness.awg3_device_id,
    )
    pending = service.start_replacement(
        original.profile_id,
        replacement_device_id=harness.replacement_device_id,
    )
    other_user_id = harness.repo.upsert_user(
        telegram_id=9304,
        username="activation-other-user",
        first_name="Activation",
        last_name="Other",
    )
    harness.conn.execute(
        "UPDATE devices SET user_id = ? WHERE id = ?",
        (other_user_id, harness.replacement_device_id),
    )
    harness.conn.commit()
    before_events = harness.conn.execute(
        "SELECT COUNT(*) FROM protocol_config_events"
    ).fetchone()[0]

    with pytest.raises(ValueError, match="does not belong to passport owner"):
        service.activate_replacement(original.profile_id)

    assert service.get(original.profile_id) == pending
    assert harness.conn.execute(
        "SELECT COUNT(*) FROM protocol_config_events"
    ).fetchone()[0] == before_events


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
    before_events = harness.conn.execute(
        "SELECT COUNT(*) FROM protocol_config_events"
    ).fetchone()[0]

    with pytest.raises(ValueError, match="replacement already pending"):
        service.start_replacement(
            old.profile_id,
            replacement_device_id=harness.awg2_device_id,
        )
    assert harness.conn.execute(
        "SELECT COUNT(*) FROM protocol_config_events"
    ).fetchone()[0] == before_events


def test_cas_conflict_raises_before_transition_event(
    harness: ProfileHarness,
    monkeypatch: pytest.MonkeyPatch,
):
    service = _service(harness.repo)
    profile = service.attach_active(
        harness.passport_device_id,
        ProtocolVersion.AWG3,
        harness.awg3_device_id,
    )
    before_events = harness.conn.execute(
        "SELECT COUNT(*) FROM protocol_config_events"
    ).fetchone()[0]
    monkeypatch.setattr(
        harness.repo,
        "transition_device_protocol_profile",
        lambda **_kwargs: False,
        raising=False,
    )

    with pytest.raises(RuntimeError, match="protocol profile changed concurrently"):
        service.start_replacement(
            profile.profile_id,
            replacement_device_id=harness.replacement_device_id,
        )

    assert service.get(profile.profile_id) == profile
    assert harness.conn.execute(
        "SELECT COUNT(*) FROM protocol_config_events"
    ).fetchone()[0] == before_events


def test_repository_profile_cas_compares_state_and_both_device_identities(
    harness: ProfileHarness,
):
    profile = _service(harness.repo).attach_active(
        harness.passport_device_id,
        ProtocolVersion.AWG3,
        harness.awg3_device_id,
    )

    stale = harness.repo.transition_device_protocol_profile(
        profile_id=profile.profile_id,
        expected_lifecycle_state="active",
        expected_local_device_id=harness.replacement_device_id,
        expected_replacement_device_id=None,
        lifecycle_state="pending_replacement",
        local_device_id=harness.awg3_device_id,
        replacement_device_id=harness.replacement_device_id,
    )

    assert stale is False
    assert _service(harness.repo).get(profile.profile_id) == profile

    changed = harness.repo.transition_device_protocol_profile(
        profile_id=profile.profile_id,
        expected_lifecycle_state="active",
        expected_local_device_id=harness.awg3_device_id,
        expected_replacement_device_id=None,
        lifecycle_state="pending_replacement",
        local_device_id=harness.awg3_device_id,
        replacement_device_id=harness.replacement_device_id,
    )
    repeated_stale = harness.repo.transition_device_protocol_profile(
        profile_id=profile.profile_id,
        expected_lifecycle_state="active",
        expected_local_device_id=harness.awg3_device_id,
        expected_replacement_device_id=None,
        lifecycle_state="review_required",
        local_device_id=harness.awg3_device_id,
        replacement_device_id=None,
    )

    assert changed is True
    assert repeated_stale is False
    pending = _service(harness.repo).get(profile.profile_id)
    assert pending.lifecycle_state == "pending_replacement"
    assert pending.local_device_id == harness.awg3_device_id
    assert pending.replacement_device_id == harness.replacement_device_id


def test_attach_rejects_device_owned_by_another_passport_owner(
    harness: ProfileHarness,
):
    other_user_id = harness.repo.upsert_user(
        telegram_id=9302,
        username="other-profile-user",
        first_name="Other",
        last_name="Owner",
    )
    server_id = int(
        harness.repo.get_device(harness.awg3_device_id)["server_id"]
    )
    other_device_id = _create_local_device(
        harness.repo,
        user_id=other_user_id,
        server_id=server_id,
        sequence=6,
        protocol=ProtocolVersion.AWG3,
    )
    before_events = harness.conn.execute(
        "SELECT COUNT(*) FROM protocol_config_events"
    ).fetchone()[0]

    with pytest.raises(ValueError, match="does not belong to passport owner"):
        _service(harness.repo).attach_active(
            harness.passport_device_id,
            ProtocolVersion.AWG3,
            other_device_id,
        )

    assert harness.repo.get_device_protocol_profile(
        passport_device_id=harness.passport_device_id,
        protocol_version="awg3",
    ) is None
    assert harness.conn.execute(
        "SELECT COUNT(*) FROM protocol_config_events"
    ).fetchone()[0] == before_events


def test_replacement_rejects_cross_owner_but_allows_same_owner_other_server(
    harness: ProfileHarness,
):
    owner_device = harness.repo.get_device(harness.awg3_device_id)
    other_user_id = harness.repo.upsert_user(
        telegram_id=9303,
        username="replacement-other-user",
        first_name="Replacement",
        last_name="Other",
    )
    other_owner_device_id = _create_local_device(
        harness.repo,
        user_id=other_user_id,
        server_id=int(owner_device["server_id"]),
        sequence=7,
        protocol=ProtocolVersion.AWG3,
    )
    other_server_id = harness.repo.ensure_default_server(
        name="same-owner-other-server",
        network_cidr="10.214.0.0/24",
    )
    same_owner_other_server_device_id = _create_local_device(
        harness.repo,
        user_id=int(owner_device["user_id"]),
        server_id=other_server_id,
        sequence=8,
        protocol=ProtocolVersion.AWG3,
    )
    service = _service(harness.repo)
    profile = service.attach_active(
        harness.passport_device_id,
        ProtocolVersion.AWG3,
        harness.awg3_device_id,
    )
    before_events = harness.conn.execute(
        "SELECT COUNT(*) FROM protocol_config_events"
    ).fetchone()[0]

    with pytest.raises(ValueError, match="does not belong to passport owner"):
        service.start_replacement(
            profile.profile_id,
            replacement_device_id=other_owner_device_id,
        )

    assert harness.conn.execute(
        "SELECT COUNT(*) FROM protocol_config_events"
    ).fetchone()[0] == before_events
    pending = service.start_replacement(
        profile.profile_id,
        replacement_device_id=same_owner_other_server_device_id,
    )
    assert pending.replacement_device_id == same_owner_other_server_device_id


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


def test_compromise_completion_rejects_post_factory_state_and_identity_change(
    harness: ProfileHarness,
):
    original_device = harness.repo.get_device(harness.awg3_device_id)
    factory_device_id = _create_local_device(
        harness.repo,
        user_id=int(original_device["user_id"]),
        server_id=int(original_device["server_id"]),
        sequence=9,
        protocol=ProtocolVersion.AWG3,
    )
    service = _service(harness.repo)
    old = service.attach_active(
        harness.passport_device_id,
        ProtocolVersion.AWG3,
        harness.awg3_device_id,
    )

    def issue_with_interleaving(_protocol: ProtocolVersion) -> int:
        with harness.repo.transaction():
            changed = harness.repo.transition_device_protocol_profile(
                profile_id=old.profile_id,
                expected_lifecycle_state="revoked",
                expected_local_device_id=harness.awg3_device_id,
                expected_replacement_device_id=None,
                lifecycle_state="review_required",
                local_device_id=harness.replacement_device_id,
                replacement_device_id=None,
            )
            assert changed is True
            harness.repo.append_protocol_config_event(
                event_type="protocol_profile_review_required",
                actor_kind="system",
                actor_id=0,
                reason="interleaving review",
                passport_device_id=harness.passport_device_id,
                protocol_version="awg3",
                local_device_id=harness.replacement_device_id,
                metadata={
                    "profile_id": old.profile_id,
                    "lifecycle_state": "review_required",
                    "replacement_device_id": None,
                },
            )
        return factory_device_id

    conflict: RuntimeError | None = None
    try:
        service.compromise_reissue(
            old.profile_id,
            replacement_factory=issue_with_interleaving,
            actor_id=700,
            reason="suspected config leak",
        )
    except RuntimeError as exc:
        conflict = exc

    after = service.get(old.profile_id)
    event_types = [
        str(row["event_type"])
        for row in harness.conn.execute(
            "SELECT event_type FROM protocol_config_events ORDER BY id"
        ).fetchall()
    ]
    assert conflict is not None, (
        "completion overwrote interleaving: "
        f"state={after.lifecycle_state}, local_device_id={after.local_device_id}, "
        f"events={event_types}"
    )
    assert str(conflict) == "protocol profile changed concurrently"
    assert after.lifecycle_state == "review_required"
    assert after.local_device_id == harness.replacement_device_id
    assert after.replacement_device_id is None
    assert "compromise_reissue_completed" not in event_types
    assert service.by_local_device_id(
        harness.awg3_device_id
    ).lifecycle_state == "revoked"


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
