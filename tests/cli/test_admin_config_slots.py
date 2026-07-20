import sys

import pytest

from app import cli
from app.cli import (
    build_admin_config_slot_lifecycle_plan,
    build_parser,
    run_admin_config_slot_lifecycle,
)
from app.db.connection import connect
from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.server_config.loader import load_server_config, select_server
from tests.server_config.test_loader import DOCKER_YAML


def test_admin_slot_commands_are_dry_run_by_default():
    assign = build_parser().parse_args(
        [
            "admin-config",
            "assign-slot",
            "--request-id",
            "assign-001",
            "--device-id",
            "7",
            "--device-label",
            "Pixel 8",
            "--platform",
            "android",
        ]
    )
    disable = build_parser().parse_args(
        [
            "admin-config",
            "disable-slot",
            "--server",
            "Spain-Madrid",
            "--device-id",
            "7",
            "--reason",
            "operator disabled",
        ]
    )

    assert assign.apply is False
    assert disable.apply is False


def test_admin_slot_apply_checks_exact_live_gate_before_settings(monkeypatch):
    calls = []

    def stop_at_gate():
        calls.append(True)
        raise SystemExit("slot gate closed")

    monkeypatch.setattr(cli, "require_vps_apply_enabled_for_cli_apply", stop_at_gate)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "amneziya",
            "admin-config",
            "assign-slot",
            "--request-id",
            "assign-001",
            "--device-id",
            "7",
            "--device-label",
            "Pixel 8",
            "--platform",
            "android",
            "--admin-telegram-id",
            "7001",
            "--apply",
        ],
    )

    with pytest.raises(SystemExit, match="slot gate closed"):
        cli.main()
    assert calls == [True]


def test_lifecycle_dry_run_does_not_create_or_migrate_database(tmp_path):
    missing = tmp_path / "must-not-be-created.sqlite3"

    with pytest.raises(Exception):
        build_admin_config_slot_lifecycle_plan(
            db_path=missing,
            local_device_id=7,
            action="disable",
        )

    assert not missing.exists()


def test_lifecycle_apply_rejects_same_name_with_different_private_target(tmp_path):
    config_path = tmp_path / "servers.yml"
    config_path.write_text(DOCKER_YAML, encoding="utf-8")
    server = select_server(load_server_config(config_path), "debian-vps-1")
    db_path = tmp_path / "slots.sqlite3"
    conn = connect(db_path)
    initialize_schema(conn)
    repo = Repository(conn)
    user_id = repo.create_operator_recipient(operator_label="Recipient")
    server_id = repo.create_server_for_admin(
        name="debian-vps-1",
        host="wrong-target.example",
        ssh_port=22,
        endpoint_host="wrong-vpn.example",
        vpn_port=30001,
        vpn_network_cidr="10.8.0.0/24",
        server_address="10.8.0.1/24",
        server_public_key="public",
        runtime="docker",
        firewall="iptables",
        status="active",
        max_devices=5,
    )
    device_id = repo.create_device(
        user_id=user_id,
        server_id=server_id,
        name="slot-01",
        duration_days=7,
        vpn_ip="10.8.0.2",
        peer_public_key="peer-public",
        peer_private_key_encrypted="v1:private",
        preshared_key_encrypted="v1:psk",
        config_version="amneziawg_v2",
    )
    conn.close()

    with pytest.raises(ValueError, match="target does not match"):
        run_admin_config_slot_lifecycle(
            db_path=db_path,
            server=server,
            local_device_id=device_id,
            action="disable",
            reason="operator disabled",
            admin_telegram_id=7001,
            authorized_admin_telegram_ids={7001},
        )
