import sqlite3

import pytest

from app.db import repositories
from app.db.connection import connect
from app.db.repositories import Repository
from app.db.schema import initialize_schema


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
    assert repo.get_device(device_id)["assignment_mode"] == "dedicated_device"


def test_repository_creates_operator_recipient_without_telegram_identity(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)

    recipient_id = repo.create_operator_recipient(operator_label="Alice — Pixel 8")
    recipient = repo.get_user(recipient_id)

    assert recipient["telegram_id"] is None
    assert recipient["operator_label"] == "Alice — Pixel 8"
    assert repo.get_user_by_operator_label("Alice — Pixel 8")["id"] == recipient_id
    assert repositories.user_display_label(recipient) == "Alice — Pixel 8"


def test_operator_recipient_rejects_blank_and_normalized_duplicate_labels(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)

    with pytest.raises(ValueError, match="operator_label must not be blank"):
        repo.create_operator_recipient(operator_label="   ")

    recipient_id = repo.create_operator_recipient(operator_label="  Alice — Pixel 8  ")
    assert repo.get_user(recipient_id)["operator_label"] == "Alice — Pixel 8"

    with pytest.raises(ValueError, match="operator_label already exists"):
        repo.create_operator_recipient(operator_label="alice — pixel 8")


def test_operator_identity_keeps_telegram_upsert_behavior_unchanged(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)

    user_id = repo.upsert_user(
        telegram_id=1001,
        username="alice",
        first_name="Alice",
        last_name=None,
    )
    updated_id = repo.upsert_user(
        telegram_id=1001,
        username="alice-updated",
        first_name="Alice",
        last_name="Telegram",
    )

    assert updated_id == user_id
    user = repo.get_user(user_id)
    assert user["telegram_id"] == 1001
    assert user["operator_label"] is None
    assert user["username"] == "alice-updated"


def test_schema_migrates_legacy_users_without_losing_dependent_rows(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    conn.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            telegram_id INTEGER NOT NULL UNIQUE,
            username TEXT,
            first_name TEXT,
            last_name TEXT,
            status TEXT NOT NULL DEFAULT 'active',
            locale TEXT NOT NULL DEFAULT 'ru',
            is_admin INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            email TEXT,
            email_verified_at TEXT
        );
        CREATE TABLE devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            server_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            duration_days INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'active'
                CHECK (status IN ('pending', 'active', 'disabled', 'expired', 'revoked', 'failed')),
            vpn_ip TEXT NOT NULL,
            peer_public_key TEXT NOT NULL,
            peer_private_key_encrypted TEXT NOT NULL,
            preshared_key_encrypted TEXT NOT NULL,
            config_version TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        INSERT INTO users (
            id, telegram_id, username, first_name, last_name
        ) VALUES (41, 1001, 'legacy', 'Legacy', 'User');
        INSERT INTO devices (
            id, user_id, server_id, name, duration_days, status, vpn_ip,
            peer_public_key, peer_private_key_encrypted,
            preshared_key_encrypted, config_version
        ) VALUES (
            73, 41, 1, 'Legacy phone', 7, 'active', '10.8.0.2',
            'legacy-public', 'legacy-private', 'legacy-psk', 'amneziawg_v2'
        );
        """
    )
    conn.execute("PRAGMA foreign_keys = ON")

    initialize_schema(conn)
    repo = Repository(conn)

    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
    assert repo.get_user(41)["telegram_id"] == 1001
    assert repo.get_user(41)["operator_label"] is None
    assert repo.get_device(73)["user_id"] == 41


def test_plan_max_devices_is_optional_configurable_and_validated(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)

    repo.upsert_plan(
        plan_id="family_6",
        name="Family 6",
        duration_days=30,
        max_devices=6,
    )

    assert repo.get_plan("family_6")["max_devices"] == 6

    with pytest.raises(ValueError, match="max_devices must be positive"):
        repo.upsert_plan(
            plan_id="invalid",
            name="Invalid",
            duration_days=30,
            max_devices=0,
        )

    repo.seed_default_plans()
    repo.upsert_plan(
        plan_id="days_30",
        name="30 days",
        duration_days=30,
        max_devices=6,
    )
    repo.seed_default_plans()

    assert repo.get_plan("days_30")["max_devices"] == 6


def test_schema_migrates_existing_plan_and_device_assignment_columns(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    conn.executescript(
        """
        CREATE TABLE plans (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            duration_days INTEGER NOT NULL,
            price INTEGER NOT NULL DEFAULT 0,
            currency TEXT NOT NULL DEFAULT 'RUB',
            is_free INTEGER NOT NULL DEFAULT 1,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        INSERT INTO plans (id, name, duration_days) VALUES ('legacy', 'Legacy', 30);
        """
    )
    conn.commit()

    initialize_schema(conn)

    plan_columns = {row[1] for row in conn.execute("PRAGMA table_info(plans)")}
    device_columns = {row[1] for row in conn.execute("PRAGMA table_info(devices)")}
    assert "max_devices" in plan_columns
    assert "assignment_mode" in device_columns
    assert conn.execute("SELECT max_devices FROM plans WHERE id = 'legacy'").fetchone()[0] is None


def test_user_locale_defaults_to_russian_and_can_be_updated(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)

    user_id = repo.upsert_user(
        telegram_id=1001,
        username="alice",
        first_name="Alice",
        last_name=None,
    )

    assert repo.get_user(user_id)["locale"] == "ru"
    assert repo.get_user_locale(1001) == "ru"
    assert repo.get_user_locale(404) == "ru"

    assert repo.set_user_locale(telegram_id=1001, locale="en") is True
    assert repo.get_user(user_id)["locale"] == "en"

    repo.upsert_user(
        telegram_id=1001,
        username="alice2",
        first_name="Alice",
        last_name=None,
    )

    assert repo.get_user(user_id)["locale"] == "en"
    assert repo.set_user_locale(telegram_id=404, locale="ru") is False
    with pytest.raises(ValueError):
        repo.set_user_locale(telegram_id=1001, locale="de")


def test_schema_migrates_existing_users_table_to_locale_default(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    conn.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            telegram_id INTEGER NOT NULL UNIQUE,
            username TEXT,
            first_name TEXT,
            last_name TEXT,
            status TEXT NOT NULL DEFAULT 'active'
                CHECK (status IN ('active', 'blocked', 'deleted')),
            is_admin INTEGER NOT NULL DEFAULT 0
                CHECK (is_admin IN (0, 1)),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        INSERT INTO users (telegram_id, username, first_name, last_name)
        VALUES (1001, 'alice', 'Alice', NULL);
        """
    )
    conn.commit()

    initialize_schema(conn)
    repo = Repository(conn)

    assert repo.get_user_locale(1001) == "ru"


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


def test_api_server_summary_queries_expose_safe_aggregate_fields(tmp_path):
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
        peer_public_key="disabled-public",
        status="disabled",
    )
    repo.record_server_health(
        server_id=server_id,
        status="online",
        latency_ms=20,
        ssh_ok=True,
        awg_ok=True,
        udp_port_ok=True,
        error="redacted from API",
    )

    summaries = repo.list_api_server_summaries()
    summary = repo.get_api_server_summary("local")

    assert len(summaries) == 1
    assert summaries[0]["name"] == "local"
    assert summary is not None
    assert summary["name"] == "local"
    assert summary["status"] == "active"
    assert summary["runtime"] == "host_systemd"
    assert summary["active_device_count"] == 1
    assert summary["total_device_count"] == 2
    assert summary["health_status"] == "online"
    assert summary["health_latency_ms"] == 20
    assert summary["health_ssh_ok"] == 1
    assert summary["health_awg_ok"] == 1
    assert summary["health_udp_port_ok"] == 1
    assert repo.get_api_server_summary("missing") is None
    assert "host" not in summary.keys()
    assert "ssh_port" not in summary.keys()
    assert "endpoint_host" not in summary.keys()
    assert "server_public_key" not in summary.keys()
    assert "health_error" not in summary.keys()


def test_api_metrics_summary_aggregates_counts_and_latest_traffic(tmp_path):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    user_id, server_id = _create_user_and_server(repo)
    active_device_id = _insert_device(
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
    repo.record_device_traffic_snapshot(
        device_id=active_device_id,
        server_id=server_id,
        peer_public_key="active-public",
        rx_bytes=100,
        tx_bytes=200,
        source="test",
        collected_at="2026-06-01T10:00:00Z",
    )
    repo.record_device_traffic_snapshot(
        device_id=active_device_id,
        server_id=server_id,
        peer_public_key="active-public",
        rx_bytes=150,
        tx_bytes=250,
        source="test",
        collected_at="2026-06-01T10:05:00Z",
    )

    summary = repo.get_api_metrics_summary()

    assert summary == {
        "users_total": 1,
        "users_active": 1,
        "users_blocked": 0,
        "users_deleted": 0,
        "servers_total": 1,
        "servers_active": 1,
        "servers_degraded": 0,
        "servers_disabled": 0,
        "devices_total": 2,
        "devices_active": 1,
        "devices_disabled": 0,
        "devices_revoked": 1,
        "traffic_rx_bytes": 150,
        "traffic_tx_bytes": 250,
    }


def test_api_users_summary_aggregates_without_personal_fields(tmp_path):
    conn = sqlite3.connect(tmp_path / "test.sqlite3")
    conn.row_factory = sqlite3.Row
    initialize_schema(conn)
    repo = Repository(conn)
    active_user_id = repo.upsert_user(
        telegram_id=1001,
        username="alice-secret",
        first_name="Alice",
        last_name="A",
    )
    blocked_user_id = repo.create_user_for_admin(
        telegram_id=1002,
        username="blocked-secret",
        first_name="Blocked",
        last_name="B",
        email="blocked@example.com",
        status="blocked",
        is_admin=False,
    )
    admin_user_id = repo.create_user_for_admin(
        telegram_id=1003,
        username="admin-secret",
        first_name="Admin",
        last_name="C",
        email="admin@example.com",
        status="active",
        is_admin=True,
    )
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    _insert_device(
        conn,
        user_id=active_user_id,
        server_id=server_id,
        vpn_ip="10.8.0.2",
        peer_public_key="active-public",
        status="active",
    )
    repo.create_order(user_id=blocked_user_id, plan_id=None, payment_mode="manual")
    fulfilled_order_id = repo.create_order(
        user_id=admin_user_id,
        plan_id=None,
        payment_mode="manual",
    )
    conn.execute(
        "UPDATE orders SET status = 'fulfilled' WHERE id = ?",
        (fulfilled_order_id,),
    )
    conn.commit()

    summary = repo.get_api_users_summary()

    assert summary == {
        "users_total": 3,
        "users_active": 2,
        "users_blocked": 1,
        "users_deleted": 0,
        "users_admins": 1,
        "users_with_devices": 1,
        "users_without_devices": 2,
        "orders_total": 2,
        "orders_manual_review": 1,
        "orders_approved": 0,
        "orders_fulfilled": 1,
        "orders_payment_pending": 0,
        "orders_rejected": 0,
    }
    assert "alice-secret" not in str(summary)
    assert "blocked@example.com" not in str(summary)


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
        integration_kind="monitoring",
        purpose="VPS health polling",
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
    assert token["integration_kind"] == "monitoring"
    assert token["purpose"] == "VPS health polling"
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
        integration_kind="monitoring",
        purpose="VPS health polling",
        token_hash="sha256:old-token-hash",
        scopes=["server:read"],
        expires_at="2026-06-08T10:00:00Z",
    )
    repo.create_api_token(
        token_id="new-token",
        name="Monitoring",
        owner_user_id=user_id,
        owner_label="ops",
        integration_kind="monitoring",
        purpose="VPS health polling",
        token_hash="sha256:new-token-hash",
        scopes=["server:read"],
        expires_at="2026-07-01T10:00:00Z",
        rotated_from_token_id="old-token",
    )

    rotated = conn.execute("SELECT * FROM api_tokens WHERE id = ?", ("new-token",)).fetchone()
    assert rotated["rotated_from_token_id"] == "old-token"
    assert rotated["integration_kind"] == "monitoring"
    assert rotated["purpose"] == "VPS health polling"
    assert "new-raw-token" not in dict(rotated).values()


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
) -> int:
    cursor = conn.execute(
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
    return int(cursor.lastrowid)
