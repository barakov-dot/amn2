import sqlite3

import pytest

from app.db.repositories import Repository
from app.db.schema import initialize_schema


@pytest.fixture
def conn():
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
    finally:
        connection.close()


def seed_user_server_device_and_passport(conn: sqlite3.Connection) -> None:
    initialize_schema(conn)
    repo = Repository(conn)
    user_id = repo.upsert_user(
        telegram_id=14001,
        username="phase14",
        first_name="Phase",
        last_name="Fourteen",
    )
    server_id = repo.ensure_default_server(
        name="phase14-local",
        network_cidr="10.214.0.0/24",
    )
    for sequence in (1, 2):
        repo.create_device(
            user_id=user_id,
            server_id=server_id,
            name=f"phase14-device-{sequence}",
            duration_days=None,
            expiry_policy="indefinite",
            vpn_ip=f"10.214.0.{sequence + 1}",
            peer_public_key=f"phase14-public-{sequence}",
            peer_private_key_encrypted=f"encrypted-private-{sequence}",
            preshared_key_encrypted=f"encrypted-preshared-{sequence}",
            config_version="amneziawg_v2",
        )
    repo.create_device_passport(
        device_id="device-1",
        owner_user_id=user_id,
        local_device_id=1,
        platform="windows",
        official_client_type="amnezia_vpn",
        client_version="5.0.0.5",
        import_method="file",
        config_schema_version="amneziawg_v2",
        config_fingerprint="sha256:" + "a" * 64,
        last_seen_at=None,
        acceptance_evidence=None,
    )


def test_phase14_schema_is_idempotent_and_additive(conn):
    initialize_schema(conn)
    initialize_schema(conn)
    tables = {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }
    assert {
        "awg3_control_state",
        "client_build_acceptances",
        "device_protocol_profiles",
        "protocol_config_events",
        "protocol_issuance_attempts",
    } <= tables
    columns = {
        row[1]
        for row in conn.execute("PRAGMA table_info(client_compatibility_evidence)")
    }
    assert {"client_build", "release_kind"} <= columns
    receipt_columns = {
        row[1]
        for row in conn.execute("PRAGMA table_info(admin_config_issuance_receipts)")
    }
    assert "client_build" in receipt_columns


def test_one_protocol_profile_per_passport_is_enforced(conn):
    seed_user_server_device_and_passport(conn)
    conn.execute(
        "INSERT INTO device_protocol_profiles"
        "(passport_device_id, protocol_version, local_device_id, lifecycle_state)"
        " VALUES ('device-1', 'awg3', 1, 'active')"
    )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO device_protocol_profiles"
            "(passport_device_id, protocol_version, local_device_id, lifecycle_state)"
            " VALUES ('device-1', 'awg3', 2, 'active')"
        )


def test_only_one_blocking_issuance_attempt_per_passport_protocol(conn):
    seed_user_server_device_and_passport(conn)
    values = (
        "device-1",
        "awg3",
        "sha256:" + "b" * 64,
        "user",
        14001,
        "amnezia_vpn",
        "windows",
        "5.0.0.5",
        "exact-build",
        "rt-phase14-awg3",
        "compat-phase14-awg3",
    )
    sql = (
        "INSERT INTO protocol_issuance_attempts ("
        "passport_device_id, protocol_version, request_fingerprint, "
        "actor_kind, actor_id, client_application, client_platform, "
        "client_version, client_build, runtime_instance_id, "
        "compatibility_evidence_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )

    conn.execute(sql, values)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(sql, values)
    conn.execute(
        "UPDATE protocol_issuance_attempts SET state = 'completed' WHERE id = 1"
    )
    conn.execute(sql, values)
    conn.execute(
        "UPDATE protocol_issuance_attempts "
        "SET state = 'recovery_required' WHERE id = 2"
    )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(sql, values)


def test_repository_reservation_transitions_are_atomic_and_profile_aware(conn):
    seed_user_server_device_and_passport(conn)
    repo = Repository(conn)

    reserved = repo.reserve_protocol_issuance_attempt(
        passport_device_id="device-1",
        protocol_version="awg3",
        request_fingerprint="sha256:" + "c" * 64,
        actor_kind="user",
        actor_id=14001,
        client_application="amnezia_vpn",
        client_platform="windows",
        client_version="5.0.0.5",
        client_build="exact-build",
        runtime_instance_id="rt-phase14-awg3",
        compatibility_evidence_id="compat-phase14-awg3",
    )
    assert reserved is not None
    assert reserved["state"] == "reserved"
    assert repo.reserve_protocol_issuance_attempt(
        passport_device_id="device-1",
        protocol_version="awg3",
        request_fingerprint="sha256:" + "d" * 64,
        actor_kind="admin",
        actor_id=700,
        client_application="amnezia_vpn",
        client_platform="windows",
        client_version="5.0.0.5",
        client_build="exact-build",
        runtime_instance_id="rt-phase14-awg3",
        compatibility_evidence_id="compat-phase14-awg3",
    ) is None

    cancelled = repo.cancel_protocol_issuance_attempt(
        int(reserved["id"]), reason_code="pre_issuer_cancelled"
    )
    assert cancelled["state"] == "cancelled"
    replacement = repo.reserve_protocol_issuance_attempt(
        passport_device_id="device-1",
        protocol_version="awg3",
        request_fingerprint="sha256:" + "e" * 64,
        actor_kind="user",
        actor_id=14001,
        client_application="amnezia_vpn",
        client_platform="windows",
        client_version="5.0.0.5",
        client_build="exact-build",
        runtime_instance_id="rt-phase14-awg3",
        compatibility_evidence_id="compat-phase14-awg3",
    )
    assert replacement is not None
    recovery = repo.mark_protocol_issuance_attempt_recovery_required(
        int(replacement["id"]),
        local_device_id=None,
        reason_code="issuer_failed",
    )
    assert recovery["state"] == "recovery_required"
    assert repo.get_protocol_issuance_attempt(int(replacement["id"]))["reason_code"] == (
        "issuer_failed"
    )

    conn.execute(
        "UPDATE protocol_issuance_attempts SET state = 'cancelled' WHERE id = ?",
        (int(replacement["id"]),),
    )
    conn.execute(
        "INSERT INTO device_protocol_profiles"
        "(passport_device_id, protocol_version, local_device_id, lifecycle_state)"
        " VALUES ('device-1', 'awg3', 2, 'active')"
    )
    conn.commit()
    assert repo.reserve_protocol_issuance_attempt(
        passport_device_id="device-1",
        protocol_version="awg3",
        request_fingerprint="sha256:" + "f" * 64,
        actor_kind="user",
        actor_id=14001,
        client_application="amnezia_vpn",
        client_platform="windows",
        client_version="5.0.0.5",
        client_build="exact-build",
        runtime_instance_id="rt-phase14-awg3",
        compatibility_evidence_id="compat-phase14-awg3",
    ) is None
