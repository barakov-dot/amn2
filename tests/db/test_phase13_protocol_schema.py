import json
import sqlite3

import pytest

from app.db.repositories import Repository
from app.db.schema import initialize_schema


@pytest.fixture
def database():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    initialize_schema(conn)
    yield conn, Repository(conn)
    conn.close()


def _seed_user_and_server(repo: Repository) -> tuple[int, int]:
    user_id = repo.upsert_user(
        telegram_id=13001,
        username="phase13",
        first_name="Phase",
        last_name="Thirteen",
    )
    server_id = repo.ensure_default_server(
        name="spain",
        network_cidr="10.212.12.0/24",
    )
    return user_id, server_id


def _seed_existing_awg2_device(
    repo: Repository, *, user_id: int, server_id: int
) -> int:
    return repo.create_device(
        user_id=user_id,
        server_id=server_id,
        name="accepted-device",
        duration_days=None,
        expiry_policy="indefinite",
        vpn_ip="10.212.12.2",
        peer_public_key="phase13-public",
        peer_private_key_encrypted="encrypted-private",
        preshared_key_encrypted="encrypted-psk",
        config_version="amneziawg_v2",
    )


def assert_phase13_protocol_schema(conn: sqlite3.Connection) -> None:
    passport_columns = {
        row["name"] for row in conn.execute("PRAGMA table_info(device_passports)")
    }
    receipt_columns = {
        row["name"]
        for row in conn.execute("PRAGMA table_info(admin_config_issuance_receipts)")
    }
    assert {
        "protocol_version",
        "runtime_instance_id",
        "client_identity_evidence_status",
        "compatibility_evidence_id",
    } <= passport_columns
    assert {
        "config_version",
        "protocol_version",
        "runtime_instance_id",
        "compatibility_evidence_id",
        "client_application",
        "client_platform",
        "client_version",
    } <= receipt_columns


def test_phase13_schema_is_additive_and_leaves_legacy_rows_unclassified(database):
    conn, repo = database
    user_id, server_id = _seed_user_and_server(repo)
    device_id = _seed_existing_awg2_device(
        repo, user_id=user_id, server_id=server_id
    )

    device = repo.get_device(device_id)
    assert device["protocol_version"] is None
    assert device["runtime_instance_id"] is None
    assert device["compatibility_evidence_id"] is None

    assert_phase13_protocol_schema(conn)


def test_runtime_identity_is_unique_per_physical_server(database):
    _, repo = database
    _, server_id = _seed_user_and_server(repo)
    repo.create_vpn_runtime_instance(
        runtime_instance_id="rt-spain-awg2",
        server_id=server_id,
        protocol_version="awg2",
        runtime_version="accepted-phase12",
        interface_name="awg0",
        udp_port=30001,
        vpn_cidr="10.212.12.0/24",
        container_name="amn2-awg",
        service_name=None,
        config_path="/opt/amnezia/awg/wg0.conf",
        lifecycle_state="accepted",
        acceptance_receipt="sha256:" + "a" * 64,
    )

    with pytest.raises(sqlite3.IntegrityError):
        repo.create_vpn_runtime_instance(
            runtime_instance_id="rt-conflict",
            server_id=server_id,
            protocol_version="awg3",
            runtime_version="3.0.3",
            interface_name="awg0",
            udp_port=30002,
            vpn_cidr="10.212.13.0/24",
            container_name="amn2-awg3",
            service_name=None,
            config_path="/opt/amn2/awg3/wg0.conf",
            lifecycle_state="planned",
            acceptance_receipt=None,
        )


def test_runtime_repository_lists_only_requested_server(database):
    _, repo = database
    _, server_id = _seed_user_and_server(repo)
    other_server_id = repo.ensure_default_server(
        name="other", network_cidr="10.99.0.0/24"
    )
    for current_server_id, suffix, port in (
        (server_id, "spain", 30001),
        (other_server_id, "other", 30002),
    ):
        repo.create_vpn_runtime_instance(
            runtime_instance_id=f"rt-{suffix}-awg2",
            server_id=current_server_id,
            protocol_version="awg2",
            runtime_version="test",
            interface_name=f"awg-{suffix}",
            udp_port=port,
            vpn_cidr=f"10.{20 if suffix == 'spain' else 21}.0.0/24",
            container_name=None,
            service_name=f"amn2-{suffix}.service",
            config_path=f"/opt/amn2/{suffix}/wg0.conf",
            lifecycle_state="planned",
            acceptance_receipt=None,
        )
    rows = repo.list_vpn_runtime_instances_for_server(server_id)
    assert [row["runtime_instance_id"] for row in rows] == ["rt-spain-awg2"]


def test_compatibility_evidence_stores_only_safe_reference(database):
    _, repo = database
    row = repo.create_client_compatibility_evidence(
        evidence_id="compat-amneziavpn-win-5005-awg3",
        application="amnezia_vpn",
        platform="windows",
        client_version="5.0.0.5",
        protocol_version="awg3",
        source_kind="official_release",
        status="claimed",
        observed_at="2026-08-01T00:00:00Z",
        safe_reference="release:amnezia-vpn:5.0.0.5",
        scope="windows exact build",
    )
    serialized = json.dumps(dict(row), sort_keys=True)
    assert "PrivateKey" not in serialized
    assert "HeaderProtectionKey" not in serialized
    assert row["status"] == "claimed"


def test_compatibility_lookup_is_exact_and_bounded(database):
    _, repo = database
    repo.create_client_compatibility_evidence(
        evidence_id="compat-exact",
        application="amnezia_vpn",
        platform="windows",
        client_version="5.0.0.5",
        protocol_version="awg3",
        source_kind="full_data",
        status="passed",
        observed_at="2026-08-01T00:00:00Z",
        safe_reference="receipt:exact",
        scope="windows exact build",
    )
    assert len(
        repo.find_client_compatibility_evidence(
            application="amnezia_vpn",
            platform="windows",
            client_version="5.0.0.5",
            protocol_version="awg3",
        )
    ) == 1
    assert repo.find_client_compatibility_evidence(
        application="amnezia_vpn",
        platform="windows",
        client_version="5.0.0.6",
        protocol_version="awg3",
    ) == []


@pytest.mark.parametrize("field", ["application", "safe_reference", "scope"])
def test_compatibility_repository_rejects_multiline_metadata(database, field):
    _, repo = database
    values = {
        "evidence_id": "compat-invalid",
        "application": "amnezia_vpn",
        "platform": "windows",
        "client_version": "5.0.0.5",
        "protocol_version": "awg3",
        "source_kind": "full_data",
        "status": "passed",
        "observed_at": "2026-08-01T00:00:00Z",
        "safe_reference": "receipt:invalid",
        "scope": "windows exact build",
    }
    values[field] += "\nunsafe"
    with pytest.raises(ValueError, match=field):
        repo.create_client_compatibility_evidence(**values)
