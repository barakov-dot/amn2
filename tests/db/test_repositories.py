import sqlite3
from datetime import datetime, timezone

import pytest

from app.db.connection import connect
from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.services.config_share_tokens import hash_config_share_token, redeem_config_share_download


def test_repository_creates_user_server_order_and_device(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)

    user_id = repo.upsert_user(
        telegram_id=1001,
        username="alice",
        first_name="Alice",
        last_name=None,
    )
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    order_id = repo.create_order(user_id=user_id, plan_id=None, payment_mode="free_test")
    device_id = repo.create_device(
        user_id=user_id,
        server_id=server_id,
        name="iPhone",
        duration_days=7,
        vpn_ip="10.8.0.2",
        peer_public_key="public",
        peer_private_key_encrypted="v1:encrypted",
        preshared_key_encrypted="v1:psk",
        config_version="amneziawg_v2",
    )

    assert repo.count_active_devices(user_id) == 1
    assert repo.get_order(order_id)["status"] == "manual_review"
    assert repo.get_device(device_id)["vpn_ip"] == "10.8.0.2"


def test_upsert_server_config_updates_existing_server_for_live_vps(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)

    first_id = repo.upsert_server_config(
        name="debian-vps-1",
        host="203.0.113.10",
        ssh_port=22,
        endpoint_host="203.0.113.10",
        vpn_port=30001,
        vpn_network_cidr="10.8.0.0/24",
        server_address="10.8.0.1/24",
        server_public_key="server-public-v1",
        runtime="host_systemd",
        firewall="ufw",
        max_devices=254,
    )
    second_id = repo.upsert_server_config(
        name="debian-vps-1",
        host="203.0.113.11",
        ssh_port=2222,
        endpoint_host="vpn.example.com",
        vpn_port=30002,
        vpn_network_cidr="10.9.0.0/24",
        server_address="10.9.0.1/24",
        server_public_key="server-public-v2",
        runtime="host_systemd",
        firewall="ufw",
        max_devices=128,
    )

    server = repo.get_server(first_id)
    assert second_id == first_id
    assert server["host"] == "203.0.113.11"
    assert server["ssh_port"] == 2222
    assert server["endpoint_host"] == "vpn.example.com"
    assert server["vpn_port"] == 30002
    assert server["vpn_network_cidr"] == "10.9.0.0/24"
    assert server["server_address"] == "10.9.0.1"
    assert server["server_public_key"] == "server-public-v2"
    assert server["max_devices"] == 128


def test_invalid_device_status_fails(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)

    user_id, server_id = _create_user_and_server(repo)

    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            """
            INSERT INTO devices (
                user_id,
                server_id,
                name,
                duration_days,
                status,
                vpn_ip,
                peer_public_key,
                peer_private_key_encrypted,
                preshared_key_encrypted,
                config_version
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                server_id,
                "invalid",
                7,
                "unknown",
                "10.8.0.20",
                "invalid-public",
                "v1:invalid-private",
                "v1:invalid-psk",
                "amneziawg_v2",
            ),
        )


def test_schema_migrates_existing_devices_table_to_allow_disabled_status(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    conn.executescript(
        """
        CREATE TABLE devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            server_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            activated_at TEXT,
            expires_at TEXT,
            duration_days INTEGER NOT NULL CHECK (duration_days > 0),
            status TEXT NOT NULL DEFAULT 'active'
                CHECK (status IN ('pending', 'active', 'expired', 'revoked', 'failed')),
            vpn_ip TEXT NOT NULL,
            peer_public_key TEXT NOT NULL,
            peer_private_key_encrypted TEXT NOT NULL,
            preshared_key_encrypted TEXT NOT NULL,
            config_version TEXT NOT NULL,
            last_config_sent_at TEXT,
            first_connected_at TEXT,
            last_connected_at TEXT,
            revoked_at TEXT,
            revoke_reason TEXT,
            UNIQUE (server_id, peer_public_key)
        );
        CREATE UNIQUE INDEX idx_devices_reserved_ip_unique
            ON devices(server_id, vpn_ip)
            WHERE status IN ('pending', 'active');
        """
    )
    conn.commit()

    initialize_schema(conn)
    repo = Repository(conn)
    user_id, server_id = _create_user_and_server(repo)

    _insert_device(
        conn,
        user_id=user_id,
        server_id=server_id,
        vpn_ip="10.8.0.44",
        peer_public_key="disabled-after-migration",
        status="disabled",
    )
    assert repo.list_allocated_ips(server_id) == ["10.8.0.44"]


def test_list_allocated_ips_only_returns_reserved_statuses(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)

    user_id, server_id = _create_user_and_server(repo)
    for index, status in enumerate(
        ["pending", "active", "disabled", "revoked", "expired", "failed"],
        start=2,
    ):
        _insert_device(
            conn,
            user_id=user_id,
            server_id=server_id,
            vpn_ip=f"10.8.0.{index}",
            peer_public_key=f"public-{status}",
            status=status,
        )

    assert repo.list_allocated_ips(server_id) == ["10.8.0.2", "10.8.0.3", "10.8.0.4"]


def test_disabled_device_keeps_ip_reserved_for_reenable(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)

    user_id, server_id = _create_user_and_server(repo)
    _insert_device(
        conn,
        user_id=user_id,
        server_id=server_id,
        vpn_ip="10.8.0.44",
        peer_public_key="disabled-public",
        status="disabled",
    )

    with pytest.raises(sqlite3.IntegrityError):
        repo.create_device(
            user_id=user_id,
            server_id=server_id,
            name="replacement",
            duration_days=7,
            vpn_ip="10.8.0.44",
            peer_public_key="new-public",
            peer_private_key_encrypted="v1:new-private",
            preshared_key_encrypted="v1:new-psk",
            config_version="amneziawg_v2",
        )


def test_disable_and_enable_user_devices_preserve_existing_keys_and_ip(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)

    user_id, server_id = _create_user_and_server(repo)
    active_id = repo.create_device(
        user_id=user_id,
        server_id=server_id,
        name="phone",
        duration_days=7,
        vpn_ip="10.8.0.44",
        peer_public_key="active-public",
        peer_private_key_encrypted="v1:active-private",
        preshared_key_encrypted="v1:active-psk",
        config_version="amneziawg_v2",
    )
    revoked_id = repo.create_device(
        user_id=user_id,
        server_id=server_id,
        name="old-phone",
        duration_days=7,
        vpn_ip="10.8.0.45",
        peer_public_key="revoked-public",
        peer_private_key_encrypted="v1:revoked-private",
        preshared_key_encrypted="v1:revoked-psk",
        config_version="amneziawg_v2",
    )
    repo.revoke_device(revoked_id, reason="test", revoked_at="2026-05-29T10:00:00Z")

    disabled_count = repo.disable_user_devices(
        user_id,
        reason="web_disable_vpn",
        disabled_at="2026-05-30T10:00:00Z",
    )
    disabled_devices = repo.list_user_devices_for_vpn_enable(user_id)

    assert disabled_count == 1
    assert len(disabled_devices) == 1
    disabled = disabled_devices[0]
    assert disabled["id"] == active_id
    assert disabled["vpn_ip"] == "10.8.0.44"
    assert disabled["peer_public_key"] == "active-public"
    assert disabled["peer_private_key_encrypted"] == "v1:active-private"
    assert disabled["preshared_key_encrypted"] == "v1:active-psk"
    assert repo.get_device(revoked_id)["status"] == "revoked"

    enabled_count = repo.enable_user_devices(user_id)

    assert enabled_count == 1
    assert repo.get_device(active_id)["status"] == "active"
    assert repo.get_device(active_id)["vpn_ip"] == "10.8.0.44"


def test_hard_delete_device_for_admin_cleans_references_without_deleting_user(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)

    user_id, server_id = _create_user_and_server(repo)
    device_id = repo.create_device(
        user_id=user_id,
        server_id=server_id,
        name="phone",
        duration_days=7,
        vpn_ip="10.8.0.44",
        peer_public_key="active-public",
        peer_private_key_encrypted="v1:active-private",
        preshared_key_encrypted="v1:active-psk",
        config_version="amneziawg_v2",
    )
    order_id = repo.create_order(user_id=user_id, plan_id=None, payment_mode="free_test")
    repo.mark_order_fulfilled(order_id, device_id)
    repo.record_admin_action(
        admin_telegram_id=9001,
        action="seed_device_action",
        target_user_id=user_id,
        target_device_id=device_id,
        metadata={"source": "test"},
    )
    repo.record_device_traffic_snapshot(
        device_id=device_id,
        server_id=server_id,
        peer_public_key="active-public",
        rx_bytes=10,
        tx_bytes=20,
        source="test",
        collected_at="2026-05-30T10:00:00Z",
    )

    repo.hard_delete_device_for_admin(user_id=user_id, device_id=device_id)

    assert repo.get_user(user_id)["id"] == user_id
    with pytest.raises(LookupError):
        repo.get_device(device_id)
    assert repo.get_order(order_id)["device_id"] is None
    action = conn.execute(
        "SELECT target_device_id FROM admin_actions WHERE action = ?",
        ("seed_device_action",),
    ).fetchone()
    assert action["target_device_id"] is None
    traffic_count = conn.execute(
        "SELECT COUNT(*) AS count FROM device_traffic_snapshots WHERE device_id = ?",
        (device_id,),
    ).fetchone()
    assert traffic_count["count"] == 0


def test_device_ip_can_be_reused_after_revocation(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)

    user_id, server_id = _create_user_and_server(repo)
    _insert_device(
        conn,
        user_id=user_id,
        server_id=server_id,
        vpn_ip="10.8.0.44",
        peer_public_key="old-public",
        status="revoked",
    )

    device_id = repo.create_device(
        user_id=user_id,
        server_id=server_id,
        name="replacement",
        duration_days=7,
        vpn_ip="10.8.0.44",
        peer_public_key="new-public",
        peer_private_key_encrypted="v1:new-private",
        preshared_key_encrypted="v1:new-psk",
        config_version="amneziawg_v2",
    )

    assert repo.get_device(device_id)["vpn_ip"] == "10.8.0.44"


def test_device_requires_existing_user_and_server(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)

    with pytest.raises(sqlite3.IntegrityError):
        repo.create_device(
            user_id=999,
            server_id=999,
            name="orphan",
            duration_days=7,
            vpn_ip="10.8.0.50",
            peer_public_key="orphan-public",
            peer_private_key_encrypted="v1:orphan-private",
            preshared_key_encrypted="v1:orphan-psk",
            config_version="amneziawg_v2",
        )


def test_mark_order_fulfilled_rejects_device_owned_by_another_user(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)

    user_a_id, server_id = _create_user_and_server(repo)
    user_b_id = repo.upsert_user(
        telegram_id=2002,
        username="carol",
        first_name="Carol",
        last_name=None,
    )
    order_a_id = repo.create_order(
        user_id=user_a_id,
        plan_id=None,
        payment_mode="free_test",
    )
    device_b_id = repo.create_device(
        user_id=user_b_id,
        server_id=server_id,
        name="Carol phone",
        duration_days=7,
        vpn_ip="10.8.0.80",
        peer_public_key="carol-public",
        peer_private_key_encrypted="v1:carol-private",
        preshared_key_encrypted="v1:carol-psk",
        config_version="amneziawg_v2",
    )

    with pytest.raises(ValueError):
        repo.mark_order_fulfilled(order_a_id, device_b_id)

    order = repo.get_order(order_a_id)
    assert order["status"] == "manual_review"
    assert order["device_id"] is None


def test_mark_order_fulfilled_requires_existing_order(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)

    user_id, server_id = _create_user_and_server(repo)
    device_id = repo.create_device(
        user_id=user_id,
        server_id=server_id,
        name="known device",
        duration_days=7,
        vpn_ip="10.8.0.90",
        peer_public_key="known-public",
        peer_private_key_encrypted="v1:known-private",
        preshared_key_encrypted="v1:known-psk",
        config_version="amneziawg_v2",
    )

    with pytest.raises(LookupError):
        repo.mark_order_fulfilled(999, device_id)


def test_repository_records_latest_server_health(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")

    repo.record_server_health(
        server_id=server_id,
        status="online",
        latency_ms=42,
        ssh_ok=True,
        awg_ok=True,
        udp_port_ok=True,
        error=None,
    )

    latest = repo.get_latest_server_health(server_id)
    assert latest["status"] == "online"
    assert latest["latency_ms"] == 42
    assert latest["ssh_ok"] == 1
    assert latest["awg_ok"] == 1
    assert latest["udp_port_ok"] == 1
    assert latest["error"] is None


def test_list_servers_for_admin_includes_counts_and_latest_health(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    user_id, server_id = _create_user_and_server(repo)
    _insert_device(
        conn,
        user_id=user_id,
        server_id=server_id,
        vpn_ip="10.8.0.2",
        peer_public_key="active-public",
        status="active",
    )
    _insert_device(
        conn,
        user_id=user_id,
        server_id=server_id,
        vpn_ip="10.8.0.3",
        peer_public_key="revoked-public",
        status="revoked",
    )
    repo.record_server_health(
        server_id=server_id,
        status="degraded",
        latency_ms=120,
        ssh_ok=True,
        awg_ok=False,
        udp_port_ok=True,
        error="awg service down",
    )

    servers = repo.list_servers_for_admin()

    assert len(servers) == 1
    assert servers[0]["total_device_count"] == 2
    assert servers[0]["active_device_count"] == 1
    assert servers[0]["health_status"] == "degraded"
    assert servers[0]["health_latency_ms"] == 120
    assert servers[0]["health_checked_at"] is not None
    assert servers[0]["health_error"] == "awg service down"


def test_list_orders_for_admin_joins_users_newest_first(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    user_id = repo.upsert_user(
        telegram_id=3001,
        username="dana",
        first_name="Dana",
        last_name="D",
    )
    first_order_id = repo.create_order(
        user_id=user_id,
        plan_id=None,
        payment_mode="free_test",
    )
    second_order_id = repo.create_order(
        user_id=user_id,
        plan_id=None,
        payment_mode="free_test",
    )

    orders = repo.list_orders_for_admin()

    assert [order["id"] for order in orders] == [second_order_id, first_order_id]
    assert orders[0]["telegram_id"] == 3001
    assert orders[0]["username"] == "dana"
    assert orders[0]["first_name"] == "Dana"
    assert orders[0]["last_name"] == "D"


def test_list_active_devices_with_users_omits_encrypted_device_secrets(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    user_id, server_id = _create_user_and_server(repo)
    _insert_device(
        conn,
        user_id=user_id,
        server_id=server_id,
        vpn_ip="10.8.0.2",
        peer_public_key="active-public",
        status="active",
    )

    devices = repo.list_active_devices_with_users()

    assert len(devices) == 1
    keys = set(devices[0].keys())
    assert "peer_private_key_encrypted" not in keys
    assert "preshared_key_encrypted" not in keys
    assert devices[0]["name"] == "active-device"
    assert devices[0]["config_version"] == "amneziawg_v2"
    assert "expires_at" in keys
    assert devices[0]["telegram_id"] == 2001


def test_list_ignored_remote_peers_returns_rows_for_admin_display(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    _user_id, server_id = _create_user_and_server(repo)

    repo.ignore_remote_peer(
        server_id=server_id,
        peer_public_key="amnezia-created-peer",
        allowed_ips="10.8.0.10/32",
    )

    ignored = repo.list_ignored_remote_peers(server_id)

    assert len(ignored) == 1
    assert ignored[0]["peer_public_key"] == "amnezia-created-peer"
    assert ignored[0]["allowed_ips"] == "10.8.0.10/32"
    assert ignored[0]["created_at"] is not None


def test_unignore_remote_peer_removes_amnezia_created_marker(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    _user_id, server_id = _create_user_and_server(repo)
    repo.ignore_remote_peer(
        server_id=server_id,
        peer_public_key="amnezia-created-peer",
        allowed_ips="10.8.0.10/32",
    )

    removed = repo.unignore_remote_peer(
        server_id=server_id,
        peer_public_key="amnezia-created-peer",
    )

    assert removed is True
    assert repo.list_ignored_remote_peers(server_id) == []
    assert repo.unignore_remote_peer(
        server_id=server_id,
        peer_public_key="amnezia-created-peer",
    ) is False


def test_update_user_email_stores_email_and_clears_verification_on_change(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    user_id, _server_id = _create_user_and_server(repo)

    repo.update_user_email(user_id, "bob@example.com")
    repo.mark_user_email_verified(user_id, "2026-05-29T10:00:00Z")
    repo.update_user_email(user_id, "new-bob@example.com")

    user = repo.get_user(user_id)
    assert user["email"] == "new-bob@example.com"
    assert user["email_verified_at"] is None


def test_update_user_email_keeps_verification_when_address_is_unchanged(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    user_id, _server_id = _create_user_and_server(repo)

    repo.update_user_email(user_id, "bob@example.com")
    repo.mark_user_email_verified(user_id, "2026-05-29T10:00:00Z")
    repo.update_user_email(user_id, "bob@example.com")

    user = repo.get_user(user_id)
    assert user["email"] == "bob@example.com"
    assert user["email_verified_at"] == "2026-05-29T10:00:00Z"


def test_mark_user_email_verified_stores_timestamp(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    user_id, _server_id = _create_user_and_server(repo)
    repo.update_user_email(user_id, "bob@example.com")

    repo.mark_user_email_verified(user_id, "2026-05-29T10:00:00Z")

    assert repo.get_user(user_id)["email_verified_at"] == "2026-05-29T10:00:00Z"


def test_email_recovery_token_lifecycle(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    user_id, server_id = _create_user_and_server(repo)
    device_id = repo.create_device(
        user_id=user_id,
        server_id=server_id,
        name="Bob phone",
        duration_days=7,
        vpn_ip="10.8.0.22",
        peer_public_key="token-device-public",
        peer_private_key_encrypted="v1:token-device-private",
        preshared_key_encrypted="v1:token-device-psk",
        config_version="amneziawg_v2",
    )

    token_id = repo.create_email_recovery_token(
        user_id=user_id,
        email="bob@example.com",
        token_hash="sha256:token-hash",
        purpose="recover_config",
        expires_at="2026-05-29T12:00:00Z",
        device_id=device_id,
    )

    token = repo.get_valid_email_recovery_token(
        token_hash="sha256:token-hash",
        purpose="recover_config",
        now="2026-05-29T11:00:00Z",
    )
    assert token["id"] == token_id
    assert token["user_id"] == user_id
    assert token["email"] == "bob@example.com"
    assert token["token_hash"] == "sha256:token-hash"
    assert token["purpose"] == "recover_config"
    assert token["expires_at"] == "2026-05-29T12:00:00Z"
    assert token["device_id"] == device_id

    assert (
        repo.get_valid_email_recovery_token(
            token_hash="sha256:token-hash",
            purpose="verify_email",
            now="2026-05-29T11:00:00Z",
        )
        is None
    )
    assert (
        repo.get_valid_email_recovery_token(
            token_hash="sha256:token-hash",
            purpose="recover_config",
            now="2026-05-29T12:00:00Z",
        )
        is None
    )

    assert repo.mark_email_recovery_token_used(token_id, "2026-05-29T11:30:00Z")
    assert not repo.mark_email_recovery_token_used(token_id, "2026-05-29T11:35:00Z")

    assert (
        repo.get_valid_email_recovery_token(
            token_hash="sha256:token-hash",
            purpose="recover_config",
            now="2026-05-29T11:45:00Z",
        )
        is None
    )


def test_api_token_lifecycle_stores_hash_scopes_and_revoke_state(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    user_id, _server_id = _create_user_and_server(repo)

    repo.create_api_token(
        token_id="api-token-1",
        name="Monitoring",
        owner_user_id=user_id,
        owner_label="ops",
        token_hash="sha256:api-token-hash",
        scopes=["metrics:read", "server:read"],
        expires_at="2026-06-08T10:00:00Z",
        rotated_from_token_id=None,
    )

    token = repo.get_valid_api_token(
        token_hash="sha256:api-token-hash",
        now="2026-06-01T10:00:00Z",
    )
    assert token is not None
    assert token["id"] == "api-token-1"
    assert token["name"] == "Monitoring"
    assert token["owner_user_id"] == user_id
    assert token["owner_status"] == "active"
    assert token["owner_label"] == "ops"
    assert token["token_hash"] == "sha256:api-token-hash"
    assert token["scopes_json"] == '["metrics:read", "server:read"]'
    assert "raw-api-token" not in dict(token).values()

    assert (
        repo.get_valid_api_token(
            token_hash="sha256:api-token-hash",
            now="2026-06-08T10:00:00Z",
        )
        is None
    )
    assert repo.mark_api_token_used("api-token-1", "2026-06-01T10:01:00Z")
    assert repo.revoke_api_token(
        "api-token-1",
        "2026-06-01T10:02:00Z",
        reason="operator-requested",
    )
    stored = conn.execute("SELECT * FROM api_tokens WHERE id = ?", ("api-token-1",)).fetchone()
    assert stored["revoke_reason"] == "operator-requested"
    assert not repo.revoke_api_token(
        "api-token-1",
        "2026-06-01T10:03:00Z",
        reason="operator-requested",
    )
    assert (
        repo.get_valid_api_token(
            token_hash="sha256:api-token-hash",
            now="2026-06-01T10:04:00Z",
        )
        is None
    )


def test_api_token_rotation_lineage_is_stored_without_raw_token(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    user_id, _server_id = _create_user_and_server(repo)

    repo.create_api_token(
        token_id="old-token",
        name="Monitoring",
        owner_user_id=user_id,
        owner_label="ops",
        token_hash="sha256:old-token-hash",
        scopes=["server:read"],
        expires_at="2026-06-08T10:00:00Z",
    )
    repo.create_api_token(
        token_id="new-token",
        name="Monitoring",
        owner_user_id=user_id,
        owner_label="ops",
        token_hash="sha256:new-token-hash",
        scopes=["server:read"],
        expires_at="2026-07-01T10:00:00Z",
        rotated_from_token_id="old-token",
    )

    rotated = conn.execute("SELECT * FROM api_tokens WHERE id = ?", ("new-token",)).fetchone()
    assert rotated["rotated_from_token_id"] == "old-token"
    assert "new-raw-token" not in dict(rotated).values()


def test_config_share_token_lifecycle_stores_hash_policy_and_usage_state(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    user_id, server_id = _create_user_and_server(repo)
    device_id = repo.create_device(
        user_id=user_id,
        server_id=server_id,
        name="phone",
        duration_days=7,
        vpn_ip="10.8.0.99",
        peer_public_key="share-public",
        peer_private_key_encrypted="v1:share-private",
        preshared_key_encrypted="v1:share-psk",
        config_version="amneziawg_v2",
    )

    repo.create_config_share_token(
        token_id="share-token-1",
        token_hash="sha256:share-token-hash",
        token_prefix="share-to",
        purpose="config_share",
        created_by_actor="web-admin:7",
        owner_user_id=user_id,
        bound_device_ids=[device_id],
        bound_server_ids=[server_id],
        allowed_artifact_kinds=["wireguard_conf", "amnezia_import_uri"],
        target_client="amnezia_generic",
        expires_at="2026-06-01T12:30:00Z",
        one_time=True,
        max_downloads=1,
    )

    token = repo.get_config_share_token_for_auth(
        token_hash="sha256:share-token-hash",
        now="2026-06-01T12:00:00Z",
    )
    assert token is not None
    assert token["id"] == "share-token-1"
    assert token["owner_user_id"] == user_id
    assert token["owner_status"] == "active"
    assert token["token_hash"] == "sha256:share-token-hash"
    assert token["token_prefix"] == "share-to"
    assert token["purpose"] == "config_share"
    assert token["bound_device_ids_json"] == f"[{device_id}]"
    assert token["bound_server_ids_json"] == f"[{server_id}]"
    assert token["allowed_artifact_kinds_json"] == '["amnezia_import_uri", "wireguard_conf"]'
    assert token["target_client"] == "amnezia_generic"
    assert token["download_count"] == 0
    assert "raw-share-token" not in dict(token).values()

    assert (
        repo.get_config_share_token_for_auth(
            token_hash="sha256:share-token-hash",
            now="2026-06-01T12:30:00Z",
        )
        is None
    )
    assert repo.mark_config_share_token_used(
        "share-token-1",
        "2026-06-01T12:05:00Z",
        ip_hash="sha256:ip-hash",
    )
    used = conn.execute(
        "SELECT * FROM config_share_tokens WHERE id = ?",
        ("share-token-1",),
    ).fetchone()
    assert used["download_count"] == 1
    assert used["last_used_at"] == "2026-06-01T12:05:00Z"
    assert used["last_used_ip_hash"] == "sha256:ip-hash"
    assert (
        repo.get_config_share_token_for_auth(
            token_hash="sha256:share-token-hash",
            now="2026-06-01T12:06:00Z",
        )
        is None
    )
    assert repo.revoke_config_share_token(
        "share-token-1",
        "2026-06-01T12:07:00Z",
        revoked_by_actor="web-admin:7",
    )
    assert not repo.revoke_config_share_token(
        "share-token-1",
        "2026-06-01T12:08:00Z",
        revoked_by_actor="web-admin:7",
    )


def test_config_share_token_auth_lookup_includes_bound_device_and_server_status(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    user_id, server_id = _create_user_and_server(repo)
    device_id = repo.create_device(
        user_id=user_id,
        server_id=server_id,
        name="phone",
        duration_days=7,
        vpn_ip="10.8.0.99",
        peer_public_key="share-public",
        peer_private_key_encrypted="v1:share-private",
        preshared_key_encrypted="v1:share-psk",
        config_version="amneziawg_v2",
    )
    repo.create_config_share_token(
        token_id="share-token-1",
        token_hash="sha256:share-token-hash",
        token_prefix="share-to",
        purpose="config_share",
        created_by_actor="web-admin:7",
        owner_user_id=user_id,
        bound_device_ids=[device_id],
        bound_server_ids=[server_id],
        allowed_artifact_kinds=["wireguard_conf"],
        target_client="amnezia_generic",
        expires_at="2026-06-01T12:30:00Z",
        one_time=True,
        max_downloads=1,
    )

    assert repo.revoke_device(
        device_id,
        reason="operator-review",
        revoked_at="2026-06-01T12:02:00Z",
    )
    repo.set_server_status_for_admin(server_id, "disabled")

    token = repo.get_config_share_token_for_auth(
        token_hash="sha256:share-token-hash",
        now="2026-06-01T12:05:00Z",
    )

    assert token is not None
    assert token["device_status"] == "revoked"
    assert token["server_status"] == "disabled"
    assert token["owner_status"] == "active"
    assert "raw-share-token" not in dict(token).values()


def test_config_share_token_auth_lookup_prefers_requested_device_status(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    user_id, server_id = _create_user_and_server(repo)
    active_device_id = repo.create_device(
        user_id=user_id,
        server_id=server_id,
        name="active-phone",
        duration_days=7,
        vpn_ip="10.8.0.99",
        peer_public_key="share-public-active",
        peer_private_key_encrypted="v1:share-private-active",
        preshared_key_encrypted="v1:share-psk-active",
        config_version="amneziawg_v2",
    )
    revoked_device_id = repo.create_device(
        user_id=user_id,
        server_id=server_id,
        name="revoked-phone",
        duration_days=7,
        vpn_ip="10.8.0.100",
        peer_public_key="share-public-revoked",
        peer_private_key_encrypted="v1:share-private-revoked",
        preshared_key_encrypted="v1:share-psk-revoked",
        config_version="amneziawg_v2",
    )
    repo.create_config_share_token(
        token_id="share-token-1",
        token_hash="sha256:share-token-hash",
        token_prefix="share-to",
        purpose="config_share",
        created_by_actor="web-admin:7",
        owner_user_id=user_id,
        bound_device_ids=[active_device_id, revoked_device_id],
        bound_server_ids=[server_id],
        allowed_artifact_kinds=["wireguard_conf"],
        target_client="amnezia_generic",
        expires_at="2026-06-01T12:30:00Z",
        one_time=True,
        max_downloads=1,
    )
    assert repo.revoke_device(
        revoked_device_id,
        reason="operator-review",
        revoked_at="2026-06-01T12:02:00Z",
    )

    active_lookup = repo.get_config_share_token_for_auth(
        token_hash="sha256:share-token-hash",
        now="2026-06-01T12:05:00Z",
        requested_device_id=active_device_id,
    )
    revoked_lookup = repo.get_config_share_token_for_auth(
        token_hash="sha256:share-token-hash",
        now="2026-06-01T12:05:00Z",
        requested_device_id=revoked_device_id,
    )

    assert active_lookup is not None
    assert active_lookup["device_status"] == "active"
    assert active_lookup["server_status"] == "active"
    assert revoked_lookup is not None
    assert revoked_lookup["device_status"] == "revoked"
    assert revoked_lookup["server_status"] == "active"


def test_redeem_config_share_token_for_auth_is_one_time_and_atomic(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    user_id, server_id = _create_user_and_server(repo)
    device_id = repo.create_device(
        user_id=user_id,
        server_id=server_id,
        name="phone",
        duration_days=7,
        vpn_ip="10.8.0.99",
        peer_public_key="share-public",
        peer_private_key_encrypted="v1:share-private",
        preshared_key_encrypted="v1:share-psk",
        config_version="amneziawg_v2",
    )
    repo.create_config_share_token(
        token_id="share-token-1",
        token_hash="sha256:share-token-hash",
        token_prefix="share-to",
        purpose="config_share",
        created_by_actor="web-admin:7",
        owner_user_id=user_id,
        bound_device_ids=[device_id],
        bound_server_ids=[server_id],
        allowed_artifact_kinds=["wireguard_conf"],
        target_client="amnezia_generic",
        expires_at="2026-06-01T12:30:00Z",
        one_time=True,
        max_downloads=1,
    )

    redeemed = repo.redeem_config_share_token_for_auth(
        token_hash="sha256:share-token-hash",
        now="2026-06-01T12:05:00Z",
        used_at="2026-06-01T12:05:01Z",
        ip_hash="sha256:ip-hash",
    )

    assert redeemed is not None
    assert redeemed["id"] == "share-token-1"
    assert redeemed["download_count"] == 1
    assert redeemed["last_used_at"] == "2026-06-01T12:05:01Z"
    assert redeemed["last_used_ip_hash"] == "sha256:ip-hash"
    assert "raw-share-token" not in dict(redeemed).values()
    assert (
        repo.redeem_config_share_token_for_auth(
            token_hash="sha256:share-token-hash",
            now="2026-06-01T12:06:00Z",
            used_at="2026-06-01T12:06:01Z",
        )
        is None
    )

    repo.create_config_share_token(
        token_id="share-token-expired",
        token_hash="sha256:expired-share-token-hash",
        token_prefix="expired",
        purpose="config_share",
        created_by_actor="web-admin:7",
        owner_user_id=user_id,
        bound_device_ids=[device_id],
        bound_server_ids=[server_id],
        allowed_artifact_kinds=["wireguard_conf"],
        target_client="amnezia_generic",
        expires_at="2026-06-01T12:30:00Z",
    )
    assert (
        repo.redeem_config_share_token_for_auth(
            token_hash="sha256:expired-share-token-hash",
            now="2026-06-01T12:30:00Z",
            used_at="2026-06-01T12:30:01Z",
        )
        is None
    )


def test_config_share_redeem_audit_records_safe_admin_action(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    user_id, server_id = _create_user_and_server(repo)
    device_id = repo.create_device(
        user_id=user_id,
        server_id=server_id,
        name="phone",
        duration_days=7,
        vpn_ip="10.8.0.99",
        peer_public_key="share-public",
        peer_private_key_encrypted="v1:share-private",
        preshared_key_encrypted="v1:share-psk",
        config_version="amneziawg_v2",
    )
    repo.create_config_share_token(
        token_id="share-token-1",
        token_hash=hash_config_share_token("raw-share-token"),
        token_prefix="raw-shar",
        purpose="config_share",
        created_by_actor="web-admin:7",
        owner_user_id=user_id,
        bound_device_ids=[device_id],
        bound_server_ids=[server_id],
        allowed_artifact_kinds=["wireguard_conf"],
        target_client="amnezia_generic",
        expires_at="2026-06-01T12:30:00Z",
        one_time=True,
        max_downloads=1,
    )

    decision = redeem_config_share_download(
        repo,
        raw_token="raw-share-token",
        requested_device_id=device_id,
        requested_artifact_kinds=("wireguard_conf",),
        target_client="amnezia_generic",
        now=datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc),
        used_at=datetime(2026, 6, 1, 12, 0, 1, tzinfo=timezone.utc),
        audit_store=repo,
    )

    assert decision.allowed is True
    actions = repo.list_admin_actions_for_target_user(user_id)
    assert len(actions) == 1
    action = actions[0]
    assert action["admin_telegram_id"] == 0
    assert action["action"] == "config.share.download_allowed"
    assert action["target_user_id"] == user_id
    assert action["target_device_id"] == device_id
    metadata = action["metadata_json"]
    assert metadata is not None
    assert '"event": "config.share.download_allowed"' in metadata
    assert '"secret_class": "client-config-secret"' in metadata
    assert "raw-share-token" not in metadata
    assert hash_config_share_token("raw-share-token") not in metadata
    assert "vpn://" not in metadata
    assert "PrivateKey" not in metadata
    assert "PresharedKey" not in metadata


def test_config_share_redeem_rate_limit_persists_safe_attempts_and_blocks_scope(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    scope_key = "config-share-redeem:ip:sha256:ip-hash"

    for minute in range(4):
        repo.record_config_share_redeem_attempt(
            scope_key=scope_key,
            now=f"2026-06-01T12:0{minute}:00Z",
            allowed=False,
            denial_category="expired_token",
        )

    assert not repo.is_config_share_redeem_rate_limited(
        scope_key=scope_key,
        now="2026-06-01T12:04:00Z",
    )

    repo.record_config_share_redeem_attempt(
        scope_key=scope_key,
        now="2026-06-01T12:04:00Z",
        allowed=False,
        denial_category="expired_token",
    )

    assert repo.is_config_share_redeem_rate_limited(
        scope_key=scope_key,
        now="2026-06-01T12:05:00Z",
    )
    rows = conn.execute(
        "SELECT * FROM config_share_redeem_attempts ORDER BY id"
    ).fetchall()
    assert len(rows) == 5
    assert rows[0]["scope_key"] == scope_key
    assert rows[0]["allowed"] == 0
    assert rows[0]["denial_category"] == "expired_token"
    serialized_rows = "\n".join(str(dict(row)) for row in rows)
    assert "raw-share-token" not in serialized_rows
    assert hash_config_share_token("raw-share-token") not in serialized_rows
    assert "vpn://" not in serialized_rows
    assert "PrivateKey" not in serialized_rows
    assert "PresharedKey" not in serialized_rows


def test_config_share_redeem_rate_limit_ignores_allowed_and_old_attempts(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    scope_key = "config-share-redeem:ip:sha256:ip-hash"

    for minute in range(5):
        repo.record_config_share_redeem_attempt(
            scope_key=scope_key,
            now=f"2026-06-01T11:4{minute}:00Z",
            allowed=False,
            denial_category="expired_token",
        )
        repo.record_config_share_redeem_attempt(
            scope_key=scope_key,
            now=f"2026-06-01T12:0{minute}:00Z",
            allowed=True,
        )

    assert not repo.is_config_share_redeem_rate_limited(
        scope_key=scope_key,
        now="2026-06-01T12:05:00Z",
    )


def test_config_share_redeem_repository_rate_limit_blocks_before_consume(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    user_id, server_id = _create_user_and_server(repo)
    device_id = repo.create_device(
        user_id=user_id,
        server_id=server_id,
        name="phone",
        duration_days=7,
        vpn_ip="10.8.0.99",
        peer_public_key="share-public",
        peer_private_key_encrypted="v1:share-private",
        preshared_key_encrypted="v1:share-psk",
        config_version="amneziawg_v2",
    )
    repo.create_config_share_token(
        token_id="share-token-1",
        token_hash=hash_config_share_token("raw-share-token"),
        token_prefix="raw-shar",
        purpose="config_share",
        created_by_actor="web-admin:7",
        owner_user_id=user_id,
        bound_device_ids=[device_id],
        bound_server_ids=[server_id],
        allowed_artifact_kinds=["wireguard_conf"],
        target_client="amnezia_generic",
        expires_at="2026-06-01T12:30:00Z",
        one_time=True,
        max_downloads=1,
    )
    for minute in range(5):
        repo.record_config_share_redeem_attempt(
            scope_key="config-share-redeem:ip:sha256:ip-hash",
            now=f"2026-06-01T12:0{minute}:00Z",
            allowed=False,
            denial_category="expired_token",
        )

    decision = redeem_config_share_download(
        repo,
        raw_token="raw-share-token",
        requested_device_id=device_id,
        requested_artifact_kinds=("wireguard_conf",),
        target_client="amnezia_generic",
        now=datetime(2026, 6, 1, 12, 5, tzinfo=timezone.utc),
        used_at=datetime(2026, 6, 1, 12, 5, 1, tzinfo=timezone.utc),
        ip_hash="sha256:ip-hash",
        audit_store=repo,
        rate_limit_store=repo,
    )

    assert decision.allowed is False
    assert decision.denial_category == "rate_limited"
    token = conn.execute(
        "SELECT download_count, last_used_at FROM config_share_tokens WHERE id = ?",
        ("share-token-1",),
    ).fetchone()
    assert token["download_count"] == 0
    assert token["last_used_at"] is None
    actions = conn.execute(
        "SELECT * FROM admin_actions ORDER BY id DESC LIMIT 1"
    ).fetchall()
    assert len(actions) == 1
    action = actions[0]
    assert action["action"] == "config.share.download_denied"
    assert action["target_user_id"] is None
    assert action["target_device_id"] == device_id
    assert '"denial_category": "rate_limited"' in action["metadata_json"]
    attempts = conn.execute(
        "SELECT * FROM config_share_redeem_attempts ORDER BY id"
    ).fetchall()
    assert len(attempts) == 6
    assert attempts[-1]["denial_category"] == "rate_limited"
    serialized = "\n".join(
        [action["metadata_json"], *(str(dict(row)) for row in attempts)]
    )
    assert "raw-share-token" not in serialized
    assert hash_config_share_token("raw-share-token") not in serialized
    assert "vpn://" not in serialized
    assert "PrivateKey" not in serialized
    assert "PresharedKey" not in serialized


def _create_user_and_server(repo: Repository) -> tuple[int, int]:
    user_id = repo.upsert_user(
        telegram_id=2001,
        username="bob",
        first_name="Bob",
        last_name=None,
    )
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    return user_id, server_id


def _insert_device(
    conn: sqlite3.Connection,
    *,
    user_id: int,
    server_id: int,
    vpn_ip: str,
    peer_public_key: str,
    status: str,
) -> None:
    conn.execute(
        """
        INSERT INTO devices (
            user_id,
            server_id,
            name,
            duration_days,
            status,
            vpn_ip,
            peer_public_key,
            peer_private_key_encrypted,
            preshared_key_encrypted,
            config_version
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            server_id,
            f"{status}-device",
            7,
            status,
            vpn_ip,
            peer_public_key,
            f"v1:{status}-private",
            f"v1:{status}-psk",
            "amneziawg_v2",
        ),
    )
    conn.commit()
