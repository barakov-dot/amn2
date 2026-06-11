import json
from pathlib import Path

import pytest

from app.cli import build_parser, run_device_backfill_external, run_device_import_external
from app.db.connection import connect
from app.db.repositories import Repository
from app.db.schema import initialize_schema


def test_cli_accepts_device_import_external_arguments():
    parser = build_parser()

    args = parser.parse_args(
        [
            "device",
            "import-external",
            "--db",
            "data/amneziya.sqlite3",
            "--telegram-id",
            "1001",
            "--name",
            "Neobyatnaya-AMNZ-4",
            "--vpn-ip",
            "10.8.0.44",
            "--peer-public-key",
            "external-peer-4",
            "--status",
            "revoked",
            "--revoked-at",
            "2026-06-09T10:00:00Z",
            "--revoke-reason",
            "phase3_test_revoked",
        ]
    )

    assert args.command == "device"
    assert args.device_command == "import-external"
    assert args.telegram_id == 1001
    assert args.name == "Neobyatnaya-AMNZ-4"
    assert args.status == "revoked"


def test_cli_accepts_device_backfill_external_rehearsal_arguments():
    parser = build_parser()

    args = parser.parse_args(
        [
            "device",
            "backfill-external",
            "--db-copy",
            "tmp/amneziya-copy.sqlite3",
            "--input",
            "external-devices.json",
            "--dry-run",
            "--pretty",
        ]
    )

    assert args.command == "device"
    assert args.device_command == "backfill-external"
    assert args.db_copy == "tmp/amneziya-copy.sqlite3"
    assert args.input == "external-devices.json"
    assert args.dry_run is True
    assert args.apply is False


def test_run_device_import_external_creates_safe_external_only_record(tmp_path: Path):
    db_path = tmp_path / "amneziya.sqlite3"

    output = run_device_import_external(
        db_path=db_path,
        telegram_id=1001,
        username="alice",
        first_name="Alice",
        last_name=None,
        server_name="local",
        server_network_cidr="10.8.0.0/24",
        name="Neobyatnaya-AMNZ-4",
        duration_days=30,
        vpn_ip="10.8.0.44",
        peer_public_key="external-peer-4",
        config_version="amneziawg_v2",
        status="revoked",
        expires_at=None,
        revoked_at="2026-06-09T10:00:00Z",
        revoke_reason="phase3_test_revoked",
        pretty=True,
    )

    payload = json.loads(output)
    assert payload["device"]["name"] == "Neobyatnaya-AMNZ-4"
    assert payload["device"]["status"] == "revoked"
    assert payload["device"]["config_material_status"] == "external_only"
    assert payload["delivery"]["config_resend_available"] is False
    assert "peer_public_key" not in output
    assert "private" not in output.lower()
    assert "preshared" not in output.lower()

    conn = connect(db_path)
    initialize_schema(conn)
    repo = Repository(conn)
    device = repo.get_device(payload["device"]["id"])
    assert device["name"] == "Neobyatnaya-AMNZ-4"
    assert device["config_material_status"] == "external_only"


def test_run_device_backfill_external_dry_run_does_not_write_db_copy(tmp_path: Path):
    db_copy_path = tmp_path / "amneziya-copy.sqlite3"
    input_path = tmp_path / "external-devices.json"
    input_path.write_text(
        json.dumps(
            [
                {
                    "telegram_id": 1001,
                    "username": "alice",
                    "first_name": "Alice",
                    "server_name": "local",
                    "server_network_cidr": "10.8.0.0/24",
                    "name": "Neobyatnaya-AMNZ-1",
                    "duration_days": 30,
                    "vpn_ip": "10.8.0.41",
                    "peer_public_key": "external-peer-1",
                    "config_version": "amneziawg_v2",
                    "status": "active",
                },
                {
                    "telegram_id": 1002,
                    "username": "bob",
                    "first_name": "Bob",
                    "server_name": "local",
                    "server_network_cidr": "10.8.0.0/24",
                    "name": "Neobyatnaya-AMNZ-2",
                    "duration_days": 30,
                    "vpn_ip": "10.8.0.42",
                    "peer_public_key": "external-peer-2",
                    "config_version": "amneziawg_v2",
                    "status": "active",
                },
            ]
        ),
        encoding="utf-8",
    )

    output = run_device_backfill_external(
        db_copy_path=db_copy_path,
        input_path=input_path,
        apply=False,
        pretty=True,
    )

    payload = json.loads(output)
    assert payload["action"] == "device.external_backfill_rehearsal"
    assert payload["mode"] == "dry-run"
    assert payload["records_seen"] == 2
    assert payload["records_planned"] == 2
    assert payload["records_imported"] == 0
    assert payload["safety"]["local_only"] is True
    assert payload["safety"]["live_vps_commands"] is False
    assert payload["safety"]["config_material_resurrected"] is False
    assert payload["delivery"]["config_resend_available"] is False
    assert [device["name"] for device in payload["devices"]] == [
        "Neobyatnaya-AMNZ-1",
        "Neobyatnaya-AMNZ-2",
    ]
    assert all(
        device["config_material_status"] == "external_only"
        for device in payload["devices"]
    )
    _assert_external_backfill_output_is_safe(output)
    assert not db_copy_path.exists()


def test_run_device_backfill_external_apply_imports_external_only_records_to_copy(
    tmp_path: Path,
):
    db_copy_path = tmp_path / "amneziya-copy.sqlite3"
    input_path = tmp_path / "external-devices.json"
    input_path.write_text(
        json.dumps(
            [
                {
                    "telegram_id": 1001,
                    "username": "alice",
                    "first_name": "Alice",
                    "last_name": None,
                    "server_name": "local",
                    "server_network_cidr": "10.8.0.0/24",
                    "name": "Neobyatnaya-AMNZ-3",
                    "duration_days": 30,
                    "vpn_ip": "10.8.0.43",
                    "peer_public_key": "external-peer-3",
                    "config_version": "amneziawg_v2",
                    "status": "revoked",
                    "revoked_at": "2026-06-09T10:00:00Z",
                    "revoke_reason": "phase3_test_revoked",
                },
                {
                    "telegram_id": 1002,
                    "username": "bob",
                    "first_name": "Bob",
                    "server_name": "local",
                    "server_network_cidr": "10.8.0.0/24",
                    "name": "Neobyatnaya-AMNZ-4",
                    "duration_days": 30,
                    "vpn_ip": "10.8.0.44",
                    "peer_public_key": "external-peer-4",
                    "config_version": "amneziawg_v2",
                    "status": "revoked",
                    "revoked_at": "2026-06-09T10:05:00Z",
                    "revoke_reason": "phase3_test_revoked",
                },
            ]
        ),
        encoding="utf-8",
    )

    output = run_device_backfill_external(
        db_copy_path=db_copy_path,
        input_path=input_path,
        apply=True,
        pretty=True,
    )

    payload = json.loads(output)
    assert payload["mode"] == "apply"
    assert payload["records_seen"] == 2
    assert payload["records_planned"] == 2
    assert payload["records_imported"] == 2
    assert payload["delivery"]["config_resend_available"] is False
    assert payload["devices"][0]["status"] == "revoked"
    assert payload["devices"][1]["status"] == "revoked"
    _assert_external_backfill_output_is_safe(output)

    conn = connect(db_copy_path)
    initialize_schema(conn)
    try:
        rows = conn.execute(
            """
            SELECT
                name,
                status,
                config_material_status,
                peer_private_key_encrypted,
                preshared_key_encrypted
            FROM devices
            ORDER BY id ASC
            """
        ).fetchall()
    finally:
        conn.close()
    assert [row["name"] for row in rows] == [
        "Neobyatnaya-AMNZ-3",
        "Neobyatnaya-AMNZ-4",
    ]
    assert {row["config_material_status"] for row in rows} == {"external_only"}
    assert {
        row["peer_private_key_encrypted"]
        for row in rows
    } == {"external-only-client-private-key-unavailable"}
    assert {
        row["preshared_key_encrypted"]
        for row in rows
    } == {"external-only-preshared-key-unavailable"}


def test_run_device_backfill_external_rejects_secret_material_fields(
    tmp_path: Path,
):
    db_copy_path = tmp_path / "amneziya-copy.sqlite3"
    input_path = tmp_path / "external-devices.json"
    input_path.write_text(
        json.dumps(
            [
                {
                    "telegram_id": 1001,
                    "name": "Neobyatnaya-AMNZ-5",
                    "vpn_ip": "10.8.0.45",
                    "peer_public_key": "external-peer-5",
                    "client_private_key": "must-not-import",
                }
            ]
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="secret-bearing fields"):
        run_device_backfill_external(
            db_copy_path=db_copy_path,
            input_path=input_path,
            apply=True,
        )
    assert not db_copy_path.exists()


def _assert_external_backfill_output_is_safe(output: str) -> None:
    lower_output = output.lower()
    assert "peer_public_key" not in output
    assert "external-peer-" not in output
    assert "privatekey" not in lower_output
    assert "private_key" not in lower_output
    assert "presharedkey" not in lower_output
    assert "preshared_key" not in lower_output
    assert "vpn://" not in lower_output
    assert "qr" not in lower_output
    assert ".conf" not in lower_output
