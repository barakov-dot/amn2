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
        1,
        "device-1",
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
        "owner_user_id, intended_passport_device_id, passport_device_id, "
        "protocol_version, request_fingerprint, "
        "actor_kind, actor_id, client_application, client_platform, "
        "client_version, client_build, runtime_instance_id, "
        "compatibility_evidence_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
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


def test_phase14_migration_preserves_legacy_attempt_state_and_adds_owner_lineage(conn):
    seed_user_server_device_and_passport(conn)
    conn.execute("DROP INDEX uq_protocol_issuance_blocking_attempt")
    conn.execute("DROP TABLE protocol_issuance_attempts")
    conn.executescript(
        """
        CREATE TABLE protocol_issuance_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            passport_device_id TEXT NOT NULL,
            protocol_version TEXT NOT NULL,
            request_fingerprint TEXT NOT NULL,
            actor_kind TEXT NOT NULL,
            actor_id INTEGER NOT NULL,
            client_application TEXT NOT NULL,
            client_platform TEXT NOT NULL,
            client_version TEXT NOT NULL,
            client_build TEXT,
            runtime_instance_id TEXT,
            compatibility_evidence_id TEXT,
            state TEXT NOT NULL DEFAULT 'reserved',
            local_device_id INTEGER,
            reason_code TEXT,
            reserved_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            completed_at TEXT,
            cancelled_at TEXT,
            recovery_required_at TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE UNIQUE INDEX uq_protocol_issuance_blocking_attempt
        ON protocol_issuance_attempts(passport_device_id, protocol_version)
        WHERE state IN ('reserved','recovery_required');
        """
    )
    conn.execute(
        "INSERT INTO protocol_issuance_attempts ("
        "passport_device_id, protocol_version, request_fingerprint, actor_kind, "
        "actor_id, client_application, client_platform, client_version, state, "
        "reason_code) VALUES (?, 'awg3', ?, 'user', 14001, 'amnezia_vpn', "
        "'windows', '5.0.0.5', 'recovery_required', 'legacy_recovery')",
        ("device-1", "sha256:" + "9" * 64),
    )
    conn.commit()

    initialize_schema(conn)
    initialize_schema(conn)

    attempt = conn.execute(
        "SELECT * FROM protocol_issuance_attempts WHERE reason_code = 'legacy_recovery'"
    ).fetchone()
    assert attempt["state"] == "recovery_required"
    assert attempt["owner_user_id"] == 1
    assert attempt["intended_passport_device_id"] == "device-1"
    assert attempt["passport_device_id"] == "device-1"
    columns = {
        row[1]: row[3]
        for row in conn.execute("PRAGMA table_info(protocol_issuance_attempts)")
    }
    assert columns["passport_device_id"] == 0


def test_reservation_requires_active_exact_owner_without_barrier(conn):
    seed_user_server_device_and_passport(conn)
    repo = Repository(conn)
    other_user_id = repo.upsert_user(
        telegram_id=14002,
        username="other",
        first_name="Other",
        last_name="Owner",
    )
    base = {
        "owner_user_id": 1,
        "intended_passport_device_id": "device-1",
        "passport_device_id": "device-1",
        "protocol_version": "awg3",
        "request_fingerprint": "sha256:" + "8" * 64,
        "actor_kind": "user",
        "actor_id": 14001,
        "client_application": "amnezia_vpn",
        "client_platform": "windows",
        "client_version": "5.0.0.5",
        "client_build": "exact-build",
        "runtime_instance_id": "rt-phase14-awg3",
        "compatibility_evidence_id": "compat-phase14-awg3",
    }
    conn.execute("UPDATE users SET status = 'blocked' WHERE id = 1")
    conn.commit()
    assert repo.reserve_protocol_issuance_attempt(**base) is None
    conn.execute("UPDATE users SET status = 'active' WHERE id = 1")
    conn.execute(
        "INSERT INTO protocol_issuance_user_barriers(user_id, state) VALUES (1, 'blocking')"
    )
    conn.commit()
    assert repo.reserve_protocol_issuance_attempt(**base) is None
    conn.execute("DELETE FROM protocol_issuance_user_barriers WHERE user_id = 1")
    conn.commit()
    assert repo.reserve_protocol_issuance_attempt(
        **{**base, "owner_user_id": other_user_id}
    ) is None
