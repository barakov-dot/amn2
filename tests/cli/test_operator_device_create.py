import json
import os
import stat

import pytest

from app.cli import (
    build_operator_device_create_plan,
    build_parser,
    run_operator_device_create,
)
from app.db.connection import connect
from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.server.ssh import CommandResult
from app.server_config.loader import load_server_config, select_server
from app.services.private_config_artifact import write_private_config_artifact
from tests.server_config.test_loader import DOCKER_YAML


def test_cli_requires_explicit_operator_device_owner_and_output():
    parser = build_parser()

    args = parser.parse_args(
        [
            "device",
            "create-operator",
            "--owner-user-id",
            "42",
            "--server",
            "local",
            "--name",
            "Neobyatnaya-AMNZ-N-android-tv-02",
            "--duration-days",
            "365",
            "--config-version",
            "amneziawg_v2",
            "--output",
            "private/device.conf",
            "--admin-telegram-id",
            "999",
            "--execution-target",
            "local",
            "--dry-run",
        ]
    )

    assert args.device_command == "create-operator"
    assert args.owner_user_id == 42
    assert args.output == "private/device.conf"
    assert args.execution_target == "local"
    assert args.dry_run is True
    assert args.apply is False


def test_cli_operator_device_create_rejects_missing_owner():
    parser = build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args(
            [
                "device",
                "create-operator",
                "--server",
                "local",
                "--name",
                "Android TV",
                "--duration-days",
                "30",
                "--output",
                "private/device.conf",
                "--admin-telegram-id",
                "999",
                "--execution-target",
                "local",
                "--dry-run",
            ]
        )


def test_operator_device_dry_run_plan_is_secret_safe(tmp_path):
    output_path = tmp_path / "device.conf"

    payload = json.loads(
        build_operator_device_create_plan(
            owner_user_id=42,
            server_name="local",
            device_name="Android TV",
            duration_days=30,
            config_version="amneziawg_v2",
            output_path=output_path,
            admin_telegram_id=999,
            execution_target="local",
            pretty=True,
        )
    )

    assert payload["mode"] == "dry-run"
    assert payload["owner_user_id"] == 42
    assert payload["output"] == str(output_path)
    assert payload["execution_target"] == "local"
    assert payload["remote_mutation"] is False
    assert payload["config_payload_output"] is False
    assert not output_path.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission assertion")
def test_private_config_artifact_is_atomic_private_and_refuses_overwrite(tmp_path):
    output_path = tmp_path / "device.conf"

    written = write_private_config_artifact(output_path, "secret-config\n")

    assert written == output_path
    assert output_path.read_text(encoding="utf-8") == "secret-config\n"
    assert stat.S_IMODE(output_path.stat().st_mode) == 0o600
    assert not list(tmp_path.glob(".*.tmp"))
    with pytest.raises(FileExistsError):
        write_private_config_artifact(output_path, "replacement\n")
    assert output_path.read_text(encoding="utf-8") == "secret-config\n"


@pytest.mark.skipif(os.name == "posix", reason="non-POSIX safety assertion")
def test_private_config_artifact_rejects_non_posix_target(tmp_path):
    with pytest.raises(OSError, match="POSIX"):
        write_private_config_artifact(tmp_path / "device.conf", "secret-config\n")


def test_run_operator_device_create_returns_safe_output_and_records_owner(
    tmp_path, monkeypatch
):
    config_path = tmp_path / "servers.yml"
    config_path.write_text(DOCKER_YAML, encoding="utf-8")
    server = select_server(load_server_config(config_path), "debian-vps-1")
    db_path = tmp_path / "amneziya.sqlite3"
    conn = connect(db_path)
    initialize_schema(conn)
    repo = Repository(conn)
    owner_user_id = repo.upsert_user(
        telegram_id=1001,
        username="alice",
        first_name="Alice",
        last_name=None,
    )
    conn.close()
    output_path = tmp_path / "device.conf"
    command_client = DockerCommandClient()

    def fake_writer(path, config_text):
        path.write_text(config_text, encoding="utf-8")
        return path

    output = run_operator_device_create(
        db_path=db_path,
        server=server,
        owner_user_id=owner_user_id,
        device_name="Android TV",
        duration_days=30,
        config_version="amneziawg_v2",
        output_path=output_path,
        admin_telegram_id=999,
        app_secret_key="test-secret-for-access-service-1234567890",
        authorized_admin_telegram_ids={999},
        max_devices_per_user=5,
        execution_target="local",
        command_client=command_client,
        config_artifact_writer=fake_writer,
        pretty=True,
    )

    payload = json.loads(output)
    assert payload["status"] == "passed"
    assert payload["owner_user_id"] == owner_user_id
    assert payload["execution_target"] == "local"
    assert payload["config_payload_output"] is False
    assert "PrivateKey =" not in output
    assert "PresharedKey =" not in output
    assert output_path.exists()
    conn = connect(db_path)
    assert conn.execute(
        "SELECT COUNT(*) FROM admin_actions WHERE action = ?",
        ("access.create_operator_device",),
    ).fetchone()[0] == 1
    conn.close()


def test_run_operator_device_create_rejects_unauthorized_admin_before_apply(
    tmp_path,
):
    config_path = tmp_path / "servers.yml"
    config_path.write_text(DOCKER_YAML, encoding="utf-8")
    server = select_server(load_server_config(config_path), "debian-vps-1")
    db_path = tmp_path / "amneziya.sqlite3"
    conn = connect(db_path)
    initialize_schema(conn)
    repo = Repository(conn)
    owner_user_id = repo.upsert_user(
        telegram_id=1001,
        username="alice",
        first_name="Alice",
        last_name=None,
    )
    conn.close()
    command_client = DockerCommandClient()

    with pytest.raises(PermissionError, match="authorized operator admin"):
        run_operator_device_create(
            db_path=db_path,
            server=server,
            owner_user_id=owner_user_id,
            device_name="Android TV",
            duration_days=30,
            config_version="amneziawg_v2",
            output_path=tmp_path / "device.conf",
            admin_telegram_id=999,
            app_secret_key="test-secret-for-access-service-1234567890",
            authorized_admin_telegram_ids=set(),
            max_devices_per_user=5,
            execution_target="local",
            command_client=command_client,
            config_artifact_writer=lambda path, text: path,
        )

    assert command_client.calls == []
    conn = connect(db_path)
    assert conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 0
    conn.close()


class DockerCommandClient:
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
