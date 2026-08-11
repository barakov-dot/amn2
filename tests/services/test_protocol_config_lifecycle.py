from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass

import pytest

from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.services.client_compatibility import ClientIdentity
from app.services.dual_protocol_profiles import DualProtocolProfileService
from app.services.protocol_config_lifecycle import ProtocolConfigLifecycleService
from app.vpn.protocol_versions import ProtocolVersion


@dataclass(frozen=True)
class LifecycleHarness:
    conn: sqlite3.Connection
    repo: Repository
    lifecycle: ProtocolConfigLifecycleService
    user_id: int
    device_1_awg2: int
    device_1_awg3: int
    device_2_awg2: int


@pytest.fixture
def harness() -> LifecycleHarness:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    initialize_schema(conn)
    repo = Repository(conn)
    user_id = repo.upsert_user(
        telegram_id=14006,
        username="lifecycle-user",
        first_name="Lifecycle",
        last_name="User",
    )
    server_id = repo.ensure_default_server(
        name="lifecycle-server",
        network_cidr="10.214.0.0/24",
    )
    device_1_awg2 = _create_device(
        repo, user_id=user_id, server_id=server_id, sequence=2, protocol="awg2"
    )
    device_1_awg3 = _create_device(
        repo, user_id=user_id, server_id=server_id, sequence=3, protocol="awg3"
    )
    device_2_awg2 = _create_device(
        repo, user_id=user_id, server_id=server_id, sequence=4, protocol="awg2"
    )
    _create_passport(repo, "device-1", user_id, device_1_awg2)
    _create_passport(repo, "device-2", user_id, device_2_awg2)
    attempt = repo.reserve_protocol_issuance_attempt(
        passport_device_id="device-1",
        protocol_version="awg3",
        request_fingerprint="sha256:" + "1" * 64,
        actor_kind="user",
        actor_id=user_id,
        client_application="amnezia_vpn",
        client_platform="windows",
        client_version="5.0.0.5",
        client_build="build-14",
        runtime_instance_id="runtime-awg3",
        compatibility_evidence_id="compat-build-14",
    )
    assert attempt is not None
    profiles = DualProtocolProfileService(repo)
    profiles.attach_active("device-1", ProtocolVersion.AWG2, device_1_awg2)
    profiles.attach_active("device-1", ProtocolVersion.AWG3, device_1_awg3)
    profiles.attach_active("device-2", ProtocolVersion.AWG2, device_2_awg2)
    repo.complete_protocol_issuance_attempt(
        int(attempt["id"]), local_device_id=device_1_awg3
    )
    repo.upsert_client_build_acceptance(
        application="amnezia_vpn",
        platform="windows",
        client_version="5.0.0.5",
        client_build="build-14",
        state="accepted",
        evidence_ids=("compat-build-14",),
        actor_id=1,
        reason="accepted fixture",
    )
    return LifecycleHarness(
        conn=conn,
        repo=repo,
        lifecycle=ProtocolConfigLifecycleService(repo),
        user_id=user_id,
        device_1_awg2=device_1_awg2,
        device_1_awg3=device_1_awg3,
        device_2_awg2=device_2_awg2,
    )


def test_user_disable_targets_every_protocol_profile(harness: LifecycleHarness):
    result = harness.lifecycle.disable_user(
        user_id=harness.user_id,
        actor_id=1,
        reason="operator block",
    )

    assert {
        (item.passport_device_id, item.protocol_version.value) for item in result
    } == {
        ("device-1", "awg2"),
        ("device-1", "awg3"),
        ("device-2", "awg2"),
    }
    assert all(item.plan.risk_class == "remote-state-write" for item in result)
    assert all(item.plan.consistency_status == "dry-run" for item in result)


def test_device_disable_targets_both_profiles_for_one_passport(
    harness: LifecycleHarness,
):
    result = harness.lifecycle.disable_device(
        passport_device_id="device-1",
        actor_id=1,
        reason="lost physical device",
    )

    assert [(item.protocol_version.value, item.local_device_id) for item in result] == [
        ("awg2", harness.device_1_awg2),
        ("awg3", harness.device_1_awg3),
    ]


def test_config_revoke_targets_only_selected_local_device(
    harness: LifecycleHarness,
):
    result = harness.lifecycle.revoke_config(
        local_device_id=harness.device_1_awg3,
        actor_id=1,
        reason="replace selected config",
    )

    assert len(result) == 1
    assert result[0].local_device_id == harness.device_1_awg3
    assert result[0].protocol_version is ProtocolVersion.AWG3


def test_superseded_build_continues_existing_configs_and_offers_update(
    harness: LifecycleHarness,
):
    result = harness.lifecycle.apply_build_state(_exact_build(), "superseded")

    assert result.new_issuance_allowed is False
    assert result.existing_config_action == "continue"
    assert result.operator_action == "offer_update"
    assert result.configs_revoked == 0
    assert harness.lifecycle.profile(harness.device_1_awg3).lifecycle_state == "active"


def test_compatibility_rejected_build_projects_review_required(
    harness: LifecycleHarness,
):
    result = harness.lifecycle.apply_build_state(
        _exact_build(), "compatibility_rejected"
    )

    assert result.new_issuance_allowed is False
    assert result.existing_config_action == "review_required"
    assert result.operator_action == "no_auto_revoke"
    assert result.configs_revoked == 0
    assert harness.lifecycle.profile(
        harness.device_1_awg3
    ).lifecycle_state == "review_required"
    assert harness.lifecycle.profile(harness.device_1_awg2).lifecycle_state == "active"


def test_security_revoked_build_never_mass_revokes(harness: LifecycleHarness):
    result = harness.lifecycle.apply_build_state(_exact_build(), "security_revoked")

    assert result.new_issuance_allowed is False
    assert result.configs_revoked == 0
    assert result.emergency_proposal_required is True
    assert harness.lifecycle.profile(harness.device_1_awg3).lifecycle_state == "active"
    assert harness.repo.get_device(harness.device_1_awg3)["status"] == "active"


def test_emergency_projection_changes_only_awg3_state_and_keeps_material_rows(
    harness: LifecycleHarness,
):
    before_devices = harness.conn.execute(
        "SELECT id, peer_private_key_encrypted, preshared_key_encrypted FROM devices ORDER BY id"
    ).fetchall()
    before_profiles = harness.conn.execute(
        "SELECT id, protocol_version, local_device_id FROM device_protocol_profiles ORDER BY id"
    ).fetchall()

    result = harness.lifecycle.project_emergency_suspend(
        actor_id=1,
        reason="emergency runtime suspension",
    )

    assert [(item.passport_device_id, item.protocol_version.value) for item in result] == [
        ("device-1", "awg3")
    ]
    assert harness.lifecycle.profile(
        harness.device_1_awg3
    ).lifecycle_state == "temporarily_unavailable"
    assert harness.lifecycle.profile(harness.device_1_awg2).lifecycle_state == "active"
    assert harness.lifecycle.profile(harness.device_2_awg2).lifecycle_state == "active"
    after_devices = harness.conn.execute(
        "SELECT id, peer_private_key_encrypted, preshared_key_encrypted FROM devices ORDER BY id"
    ).fetchall()
    after_profiles = harness.conn.execute(
        "SELECT id, protocol_version, local_device_id FROM device_protocol_profiles ORDER BY id"
    ).fetchall()
    assert [tuple(row) for row in after_devices] == [tuple(row) for row in before_devices]
    assert [tuple(row) for row in after_profiles] == [tuple(row) for row in before_profiles]
    events = harness.conn.execute(
        "SELECT metadata_json FROM protocol_config_events ORDER BY id"
    ).fetchall()
    serialized = json.dumps([json.loads(row["metadata_json"]) for row in events])
    assert "private-awg" not in serialized
    assert "psk-awg" not in serialized


def test_user_disable_pages_beyond_old_owner_limit_without_duplicates():
    conn, repo, user_id, server_id = _empty_harness()
    passport_ids = [f"owner-page-{index:05d}" for index in range(10_001)]
    _bulk_insert_passports(conn, user_id=user_id, passport_ids=passport_ids)
    profiles = DualProtocolProfileService(repo)
    expected: set[tuple[str, int]] = set()
    for sequence, passport_id in enumerate(
        (passport_ids[10_000], passport_ids[1], passport_ids[0]),
        start=10,
    ):
        local_device_id = _create_device(
            repo,
            user_id=user_id,
            server_id=server_id,
            sequence=sequence,
            protocol="awg2",
        )
        profiles.attach_active(
            passport_id,
            ProtocolVersion.AWG2,
            local_device_id,
        )
        expected.add((passport_id, local_device_id))

    result = ProtocolConfigLifecycleService(repo).disable_user(
        user_id=user_id,
        actor_id=1,
        reason="operator block",
    )

    actual = [(item.passport_device_id, item.local_device_id) for item in result]
    assert len(actual) == len(set(actual))
    assert set(actual) == expected


def test_emergency_projection_pages_all_global_profiles_without_duplicates():
    conn, repo, user_id, server_id = _empty_harness()
    passport_ids = [f"global-page-{index:03d}" for index in range(201)]
    _bulk_insert_passports(conn, user_id=user_id, passport_ids=passport_ids)
    profiles = DualProtocolProfileService(repo)
    expected = {passport_ids[index] for index in (0, 99, 100, 199, 200)}
    for sequence, passport_id in enumerate(sorted(expected), start=20):
        local_device_id = _create_device(
            repo,
            user_id=user_id,
            server_id=server_id,
            sequence=sequence,
            protocol="awg3",
        )
        profiles.attach_active(
            passport_id,
            ProtocolVersion.AWG3,
            local_device_id,
        )

    result = ProtocolConfigLifecycleService(repo).project_emergency_suspend(
        actor_id=1,
        reason="emergency runtime suspension",
    )

    actual = [item.passport_device_id for item in result]
    assert len(actual) == len(set(actual))
    assert set(actual) == expected
    assert all(item.lifecycle_state == "temporarily_unavailable" for item in result)


def test_build_projection_finds_matching_awg3_profile_after_first_global_page():
    conn, repo, user_id, server_id = _empty_harness()
    passport_ids = [f"build-page-{index:03d}" for index in range(101)]
    _bulk_insert_passports(conn, user_id=user_id, passport_ids=passport_ids)
    target_passport_id = passport_ids[100]
    local_device_id = _create_device(
        repo,
        user_id=user_id,
        server_id=server_id,
        sequence=30,
        protocol="awg3",
    )
    attempt = repo.reserve_protocol_issuance_attempt(
        passport_device_id=target_passport_id,
        protocol_version="awg3",
        request_fingerprint="sha256:" + "3" * 64,
        actor_kind="user",
        actor_id=user_id,
        client_application="amnezia_vpn",
        client_platform="windows",
        client_version="5.0.0.5",
        client_build="build-14",
        runtime_instance_id="runtime-awg3",
        compatibility_evidence_id="compat-build-14",
    )
    assert attempt is not None
    profile = DualProtocolProfileService(repo).attach_active(
        target_passport_id,
        ProtocolVersion.AWG3,
        local_device_id,
    )
    repo.complete_protocol_issuance_attempt(
        int(attempt["id"]), local_device_id=local_device_id
    )
    repo.upsert_client_build_acceptance(
        application="amnezia_vpn",
        platform="windows",
        client_version="5.0.0.5",
        client_build="build-14",
        state="accepted",
        evidence_ids=("compat-build-14",),
        actor_id=1,
        reason="accepted fixture",
    )

    result = ProtocolConfigLifecycleService(repo).apply_build_state(
        _exact_build(), "compatibility_rejected"
    )

    assert [item.profile_id for item in result.affected_profiles] == [profile.profile_id]
    assert DualProtocolProfileService(repo).get(
        profile.profile_id
    ).lifecycle_state == "review_required"


def test_passport_pagination_rejects_negative_offsets_with_value_error():
    _, repo, user_id, _ = _empty_harness()
    calls = (
        lambda: repo.list_device_passports_for_owner(user_id, offset=-1),
        lambda: repo.list_device_passports(offset=-1),
    )

    for call in calls:
        try:
            call()
        except Exception as exc:
            assert type(exc) is ValueError
        else:
            raise AssertionError("negative offset must fail")


def _exact_build() -> ClientIdentity:
    return ClientIdentity(
        "amnezia_vpn",
        "windows",
        "5.0.0.5",
        build_id="build-14",
    )


def _empty_harness() -> tuple[sqlite3.Connection, Repository, int, int]:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    initialize_schema(conn)
    repo = Repository(conn)
    user_id = repo.upsert_user(
        telegram_id=14007,
        username="pagination-user",
        first_name="Pagination",
        last_name="User",
    )
    server_id = repo.ensure_default_server(
        name="pagination-server",
        network_cidr="10.215.0.0/16",
    )
    return conn, repo, user_id, server_id


def _bulk_insert_passports(
    conn: sqlite3.Connection,
    *,
    user_id: int,
    passport_ids: list[str],
) -> None:
    conn.executemany(
        """
        INSERT INTO device_passports (
            device_id,
            owner_user_id,
            local_device_id,
            platform,
            official_client_type,
            client_version,
            import_method,
            config_schema_version,
            config_fingerprint,
            created_at,
            updated_at
        ) VALUES (?, ?, NULL, 'windows', 'amnezia_vpn', '5.0.0.5',
                  'conf_file', 'amneziawg_v2', ?, ?, ?)
        """,
        [
            (
                passport_id,
                user_id,
                "sha256:" + f"{index:x}".ljust(64, "0")[:64],
                "2026-08-11 00:00:00",
                "2026-08-11 00:00:00",
            )
            for index, passport_id in enumerate(passport_ids)
        ],
    )
    conn.commit()


def _create_device(
    repo: Repository,
    *,
    user_id: int,
    server_id: int,
    sequence: int,
    protocol: str,
) -> int:
    return repo.create_device(
        user_id=user_id,
        server_id=server_id,
        name=f"{protocol}-{sequence}",
        duration_days=30,
        vpn_ip=f"10.214.0.{sequence}",
        peer_public_key=f"public-{protocol}-{sequence}",
        peer_private_key_encrypted=f"private-{protocol}-{sequence}",
        preshared_key_encrypted=f"psk-{protocol}-{sequence}",
        config_version="amneziawg_v2" if protocol == "awg2" else "amneziawg_v3",
        protocol_version=protocol,
    )


def _create_passport(
    repo: Repository,
    passport_device_id: str,
    user_id: int,
    local_device_id: int,
) -> None:
    repo.create_device_passport(
        device_id=passport_device_id,
        owner_user_id=user_id,
        local_device_id=local_device_id,
        platform="windows",
        official_client_type="amnezia_vpn",
        client_version="5.0.0.5",
        import_method="conf_file",
        config_schema_version="amneziawg_v2",
        config_fingerprint="sha256:" + passport_device_id.encode().hex().ljust(64, "0")[:64],
        last_seen_at=None,
        acceptance_evidence=None,
        protocol_version="awg2",
    )
