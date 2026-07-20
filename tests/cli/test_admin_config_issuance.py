import json
import sys

import pytest

from app.cli import (
    build_admin_config_issuance_plan,
    build_parser,
    run_admin_config_issue_manifest,
)
from app import cli
from app.db.connection import connect
from app.server.ssh import CommandResult
from app.server_config.loader import load_server_config, select_server
from tests.server_config.test_loader import DOCKER_YAML


def _manifest_file(tmp_path):
    path = tmp_path / "issuance.json"
    path.write_text(
        json.dumps(
            {
                "request_id": "spain-first-real-001",
                "server": "Spain-Madrid",
                "items": [
                    {
                        "recipient_label": "Example Recipient",
                        "device_label": "Example Device",
                        "platform": "android",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def test_admin_config_issue_manifest_is_dry_run_by_default(tmp_path):
    manifest = _manifest_file(tmp_path)
    args = build_parser().parse_args(
        [
            "admin-config",
            "issue-manifest",
            "--manifest",
            str(manifest),
            "--server",
            "Spain-Madrid",
        ]
    )

    assert args.admin_config_command == "issue-manifest"
    assert args.apply is False
    assert args.admin_telegram_id is None

    plan = json.loads(
        build_admin_config_issuance_plan(
            manifest_path=manifest,
            server_name="Spain-Madrid",
        )
    )
    assert plan == {
        "action": "admin_config.issue_manifest",
        "database_mutation": False,
        "item_count": 1,
        "expanded_slot_count": 1,
        "mode": "dry-run",
        "remote_mutation": False,
        "request_id": "spain-first-real-001",
        "server": "Spain-Madrid",
        "slots": [
            {
                "assignment_mode": "dedicated_device",
                "expiry_policy": "indefinite",
                "filename": "NEOBYATNAYA.NET-Example-Recipient-Example-Device.conf",
                "quota_delta": 1,
                "recipient_label": "Example Recipient",
                "slot_sequence": 1,
            }
        ],
    }


def test_dry_run_expands_unassigned_slots_without_settings_or_mutation(tmp_path):
    manifest = tmp_path / "unassigned.json"
    manifest.write_text(
        json.dumps(
            {
                "request_id": "spain-four-001",
                "server": "Spain-Madrid",
                "items": [
                    {
                        "mode": "recipient_unassigned",
                        "recipient_label": "Иван",
                        "quantity": 4,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    plan = json.loads(
        build_admin_config_issuance_plan(
            manifest_path=manifest,
            server_name="Spain-Madrid",
        )
    )

    assert plan["expanded_slot_count"] == 4
    assert [slot["filename"] for slot in plan["slots"]] == [
        "NEOBYATNAYA.NET-Ivan-01.conf",
        "NEOBYATNAYA.NET-Ivan-02.conf",
        "NEOBYATNAYA.NET-Ivan-03.conf",
        "NEOBYATNAYA.NET-Ivan-04.conf",
    ]
    assert all(slot["expiry_policy"] == "indefinite" for slot in plan["slots"])
    assert all(slot["quota_delta"] == 1 for slot in plan["slots"])


def test_admin_config_apply_requires_explicit_admin_id(tmp_path):
    manifest = _manifest_file(tmp_path)
    args = build_parser().parse_args(
        [
            "admin-config",
            "issue-manifest",
            "--manifest",
            str(manifest),
            "--server",
            "Spain-Madrid",
            "--apply",
        ]
    )

    assert args.apply is True
    assert args.admin_telegram_id is None


def test_dry_run_rejects_server_mismatch_without_mutation(tmp_path):
    manifest = _manifest_file(tmp_path)

    with pytest.raises(ValueError, match="server does not match"):
        build_admin_config_issuance_plan(
            manifest_path=manifest,
            server_name="Other-Server",
        )


def test_apply_requires_configured_admin_before_injected_peer_client_runs(tmp_path):
    config_path = tmp_path / "servers.yml"
    config_path.write_text(DOCKER_YAML, encoding="utf-8")
    server = select_server(load_server_config(config_path), "debian-vps-1")
    manifest = tmp_path / "issuance.json"
    manifest.write_text(
        json.dumps(
            {
                "request_id": "example-apply-001",
                "server": "debian-vps-1",
                "items": [
                    {
                        "recipient_label": "Example Recipient",
                        "device_label": "Example Device",
                        "platform": "android",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    command_client = FakeDockerCommandClient()

    with pytest.raises(PermissionError, match="configured admin"):
        run_admin_config_issue_manifest(
            db_path=tmp_path / "issuance.sqlite3",
            manifest_path=manifest,
            server=server,
            admin_telegram_id=7001,
            authorized_admin_telegram_ids=set(),
            app_secret_key="test-secret-for-admin-issuance-1234567890",
            max_devices_per_user=5,
            duration_days=30,
            command_client=command_client,
            attachment_builder=lambda filename, content: None,
        )

    assert command_client.calls == []


def test_apply_uses_injected_peer_client_and_returns_only_safe_receipts(tmp_path):
    config_path = tmp_path / "servers.yml"
    config_path.write_text(DOCKER_YAML, encoding="utf-8")
    server = select_server(load_server_config(config_path), "debian-vps-1")
    manifest = tmp_path / "issuance.json"
    manifest.write_text(
        json.dumps(
            {
                "request_id": "example-apply-002",
                "server": "debian-vps-1",
                "items": [
                    {
                        "recipient_label": "Example Recipient",
                        "device_label": "Example Device",
                        "platform": "android",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    db_path = tmp_path / "issuance.sqlite3"
    command_client = FakeDockerCommandClient()
    attachments = []

    output = run_admin_config_issue_manifest(
        db_path=db_path,
        manifest_path=manifest,
        server=server,
        admin_telegram_id=7001,
        authorized_admin_telegram_ids={7001},
        app_secret_key="test-secret-for-admin-issuance-1234567890",
        max_devices_per_user=5,
        duration_days=30,
        command_client=command_client,
        attachment_builder=lambda filename, content: attachments.append(
            (filename, content)
        ),
    )

    payload = json.loads(output)
    assert payload["status"] == "completed"
    assert payload["config_payload_output"] is False
    assert payload["receipts"][0]["config_filename"].endswith(".conf")
    assert len(command_client.calls) == 4
    assert len(attachments) == 1
    assert "PrivateKey =" in attachments[0][1]
    assert "PrivateKey =" not in output
    assert "PresharedKey =" not in output
    assert "debian.example" not in output
    conn = connect(db_path)
    assert conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 1
    assert conn.execute(
        "SELECT COUNT(*) FROM admin_config_issuance_receipts"
    ).fetchone()[0] == 1
    conn.close()


def test_main_apply_branch_checks_live_gate_before_settings_or_mutation(
    tmp_path, monkeypatch
):
    manifest = _manifest_file(tmp_path)
    gate_calls = []

    def stop_at_gate():
        gate_calls.append(True)
        raise SystemExit("test live gate closed")

    monkeypatch.setattr(cli, "require_vps_apply_enabled_for_cli_apply", stop_at_gate)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "amneziya",
            "admin-config",
            "issue-manifest",
            "--manifest",
            str(manifest),
            "--server",
            "Spain-Madrid",
            "--admin-telegram-id",
            "7001",
            "--apply",
        ],
    )

    with pytest.raises(SystemExit, match="test live gate closed"):
        cli.main()

    assert gate_calls == [True]


class FakeDockerCommandClient:
    def __init__(self):
        self.calls = []

    def run(self, command: str, stdin: str | None = None) -> CommandResult:
        self.calls.append((command, stdin))
        if " cat " in command:
            return CommandResult(
                exit_code=0,
                stdout=(
                    "[Interface]\n"
                    "PrivateKey = server-private\n"
                    "Address = 10.8.0.1/24\n"
                    "ListenPort = 30001\n"
                ),
                stderr="",
            )
        return CommandResult(exit_code=0, stdout="ok", stderr="")
