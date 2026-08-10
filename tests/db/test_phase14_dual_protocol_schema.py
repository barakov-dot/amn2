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
    } <= tables
    columns = {
        row[1]
        for row in conn.execute("PRAGMA table_info(client_compatibility_evidence)")
    }
    assert {"client_build", "release_kind"} <= columns


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
