import re
from pathlib import Path

from fastapi.testclient import TestClient

from app.config.settings import Settings
from app.db.connection import connect
from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.server.ssh import CommandResult
from app.server.operations import RemoteMutationResult
from app.services.access import RemoteOperationPartialFailure
from app.web.app import create_web_app
from app.web.auth import create_password_hash


APP_SECRET = "test-secret-for-web-operator-device-1234567890"


def test_operator_device_form_is_private_and_apply_is_closed_by_default(tmp_path: Path):
    settings = _settings(tmp_path)
    user_id = _seed_user(Path(settings.database_path))

    anonymous = TestClient(create_web_app(settings), base_url="https://testserver")
    response = anonymous.post(
        f"/users/{user_id}/devices/create-operator",
        data={"mode": "dry-run"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/login"

    client = _authenticated_client(settings)
    page = client.get(f"/users/{user_id}")
    assert page.status_code == 200
    assert "Create operator device" in page.text
    assert 'value="dry-run"' in page.text
    assert 'value="apply"' in page.text
    assert "Apply is closed" in page.text


def test_operator_device_dry_run_is_secret_safe_and_has_no_side_effects(tmp_path: Path):
    config_path = _write_server_config(tmp_path)
    settings = _settings(
        tmp_path,
        admin_telegram_ids="9001",
        server_config_path=config_path,
    )
    user_id = _seed_user(Path(settings.database_path))
    command_client = DockerCommandClient()
    client = _authenticated_client(settings, command_client=command_client)
    page = client.get(f"/users/{user_id}")

    response = client.post(
        f"/users/{user_id}/devices/create-operator",
        data={
            "server_name": "local",
            "device_name": "Living room TV",
            "duration_days": "365",
            "config_version": "amneziawg_v2",
            "execution_target": "local",
            "mode": "dry-run",
            "csrf_token": _csrf_token(page.text),
        },
    )

    assert response.status_code == 200
    assert "Dry-run ready" in response.text
    assert "Living room TV" in response.text
    assert "No database, peer or artifact changes were made" in response.text
    assert "PrivateKey =" not in response.text
    assert "PresharedKey =" not in response.text
    assert command_client.calls == []
    with _repo(Path(settings.database_path)) as repo:
        assert repo.list_user_devices_for_admin(user_id) == []


def test_operator_device_apply_requires_runtime_gate_and_confirmation(tmp_path: Path):
    config_path = _write_server_config(tmp_path)
    settings = _settings(
        tmp_path,
        admin_telegram_ids="9001",
        server_config_path=config_path,
    )
    user_id = _seed_user(Path(settings.database_path))
    command_client = DockerCommandClient()
    client = _authenticated_client(settings, command_client=command_client)
    page = client.get(f"/users/{user_id}")
    payload = {
        "server_name": "local",
        "device_name": "Living room TV",
        "duration_days": "365",
        "config_version": "amneziawg_v2",
        "execution_target": "local",
        "mode": "apply",
        "confirm_one_device_gate": "on",
        "csrf_token": _csrf_token(page.text),
    }

    response = client.post(
        f"/users/{user_id}/devices/create-operator",
        data=payload,
    )

    assert response.status_code == 400
    assert "VPS_APPLY_ENABLED must be true" in response.text
    assert command_client.calls == []
    with _repo(Path(settings.database_path)) as repo:
        assert repo.list_user_devices_for_admin(user_id) == []

    enabled_settings = _settings(
        tmp_path / "enabled",
        admin_telegram_ids="9001",
        server_config_path=_write_server_config(tmp_path / "enabled"),
        vps_apply_enabled=True,
    )
    enabled_user_id = _seed_user(Path(enabled_settings.database_path))
    enabled_client = _authenticated_client(
        enabled_settings,
        command_client=DockerCommandClient(),
    )
    enabled_page = enabled_client.get(f"/users/{enabled_user_id}")
    payload["csrf_token"] = _csrf_token(enabled_page.text)

    gate_closed = enabled_client.post(
        f"/users/{enabled_user_id}/devices/create-operator",
        data=payload,
    )
    assert gate_closed.status_code == 400
    assert "OPERATOR_DEVICE_CREATE_ENABLED must be true" in gate_closed.text

    enabled_settings.operator_device_create_enabled = True
    payload.pop("confirm_one_device_gate")

    response = enabled_client.post(
        f"/users/{enabled_user_id}/devices/create-operator",
        data=payload,
    )
    assert response.status_code == 400
    assert "one-device gate confirmation is required" in response.text


def test_operator_device_apply_uses_common_service_and_returns_safe_result(tmp_path: Path):
    config_path = _write_server_config(tmp_path)
    settings = _settings(
        tmp_path,
        admin_telegram_ids="9001",
        server_config_path=config_path,
        vps_apply_enabled=True,
        operator_device_create_enabled=True,
    )
    user_id = _seed_user(Path(settings.database_path))
    command_client = DockerCommandClient()
    written_artifacts: list[Path] = []

    def fake_writer(path: Path, config_text: str) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(config_text, encoding="utf-8")
        written_artifacts.append(path)
        return path

    client = _authenticated_client(
        settings,
        command_client=command_client,
        artifact_writer=fake_writer,
    )
    page = client.get(f"/users/{user_id}")

    response = client.post(
        f"/users/{user_id}/devices/create-operator",
        data={
            "server_name": "local",
            "device_name": "Living room TV",
            "duration_days": "365",
            "config_version": "amneziawg_v2",
            "execution_target": "local",
            "mode": "apply",
            "confirm_one_device_gate": "on",
            "csrf_token": _csrf_token(page.text),
        },
    )

    assert response.status_code == 200
    assert "Operator device created" in response.text
    assert "Living room TV" in response.text
    assert "PrivateKey =" not in response.text
    assert "PresharedKey =" not in response.text
    assert len(written_artifacts) == 1
    assert written_artifacts[0].is_file()
    assert written_artifacts[0].parent.name == str(user_id)
    assert command_client.calls
    with _repo(Path(settings.database_path)) as repo:
        devices = repo.list_user_devices_for_admin(user_id)
        assert len(devices) == 1
        assert devices[0]["name"] == "Living room TV"
        actions = repo.list_admin_actions_for_target_user(user_id)
        assert actions[0]["action"] == "access.create_operator_device"
        assert actions[0]["admin_telegram_id"] == 9001


def test_operator_device_partial_failure_is_redacted_and_audited(
    tmp_path: Path,
    monkeypatch,
):
    import app.cli as cli

    settings = _settings(
        tmp_path,
        admin_telegram_ids="9001",
        server_config_path=_write_server_config(tmp_path),
        vps_apply_enabled=True,
        operator_device_create_enabled=True,
    )
    user_id = _seed_user(Path(settings.database_path))

    def fail_after_remote_apply(**_kwargs):
        raise RemoteOperationPartialFailure(
            RemoteMutationResult(
                operation_id="access.create_operator_device",
                consistency_status="remote-changed-local-failed",
                remote_applied=True,
                local_applied=False,
                recovery_note="Reconcile device without printing PrivateKey material",
            ),
            OSError("artifact write failed"),
        )

    monkeypatch.setattr(cli, "run_operator_device_create", fail_after_remote_apply)
    client = _authenticated_client(settings)
    page = client.get(f"/users/{user_id}")
    response = client.post(
        f"/users/{user_id}/devices/create-operator",
        data={
            "server_name": "local",
            "device_name": "Living room TV",
            "duration_days": "365",
            "config_version": "amneziawg_v2",
            "execution_target": "local",
            "mode": "apply",
            "confirm_one_device_gate": "on",
            "csrf_token": _csrf_token(page.text),
        },
    )

    assert response.status_code == 409
    assert "remote-changed-local-failed" not in response.text
    assert "PrivateKey" not in response.text
    with _repo(Path(settings.database_path)) as repo:
        actions = repo.list_admin_actions_for_target_user(user_id)
        assert actions[0]["action"] == "web_operator_device_create_failed"
        assert "PrivateKey" not in actions[0]["metadata_json"]


def test_operator_device_create_rejects_bad_csrf_and_inactive_owner(tmp_path: Path):
    config_path = _write_server_config(tmp_path)
    settings = _settings(
        tmp_path,
        admin_telegram_ids="9001",
        server_config_path=config_path,
    )
    user_id = _seed_user(Path(settings.database_path), status="blocked")
    client = _authenticated_client(settings)
    payload = {
        "server_name": "local",
        "device_name": "Living room TV",
        "duration_days": "365",
        "config_version": "amneziawg_v2",
        "execution_target": "local",
        "mode": "dry-run",
    }

    bad_csrf = client.post(
        f"/users/{user_id}/devices/create-operator",
        data={**payload, "csrf_token": "invalid"},
    )
    assert bad_csrf.status_code == 403

    page = client.get(f"/users/{user_id}")
    inactive = client.post(
        f"/users/{user_id}/devices/create-operator",
        data={**payload, "csrf_token": _csrf_token(page.text)},
    )
    assert inactive.status_code == 400
    assert "active owner" in inactive.text


class DockerCommandClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str | None]] = []

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


def _settings(
    tmp_path: Path,
    *,
    admin_telegram_ids: str = "",
    server_config_path: Path | None = None,
    vps_apply_enabled: bool = False,
    operator_device_create_enabled: bool = False,
) -> Settings:
    tmp_path.mkdir(parents=True, exist_ok=True)
    return Settings(
        _env_file=None,
        telegram_bot_token="TEST_TOKEN",
        app_secret_key=APP_SECRET,
        database_path=str(tmp_path / "amneziya.sqlite3"),
        admin_telegram_ids=admin_telegram_ids,
        web_admin_username="root",
        web_admin_password_hash=create_password_hash(
            "correct-password",
            salt="test-salt",
        ),
        web_admin_session_secret="s" * 32,
        web_admin_session_cookie_secure=True,
        vps_apply_enabled=vps_apply_enabled,
        operator_device_create_enabled=operator_device_create_enabled,
        server_config_path=str(server_config_path or (tmp_path / "servers.yml")),
        server_name="local",
    )


def _authenticated_client(
    settings: Settings,
    *,
    command_client: DockerCommandClient | None = None,
    artifact_writer=None,
) -> TestClient:
    client = TestClient(
        create_web_app(
            settings,
            operator_command_client=command_client,
            operator_config_artifact_writer=artifact_writer,
        ),
        base_url="https://testserver",
    )
    login_page = client.get("/login")
    response = client.post(
        "/login",
        data={
            "username": "root",
            "password": "correct-password",
            "csrf_token": _csrf_token(login_page.text),
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    return client


def _csrf_token(html: str) -> str:
    match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html)
    assert match is not None
    return match.group(1)


def _seed_user(database_path: Path, *, status: str = "active") -> int:
    conn = connect(database_path)
    try:
        initialize_schema(conn)
        repo = Repository(conn)
        user_id = repo.upsert_user(
            telegram_id=1001,
            username="alice",
            first_name="Alice",
            last_name=None,
        )
        conn.execute("UPDATE users SET status = ? WHERE id = ?", (status, user_id))
        conn.commit()
        return user_id
    finally:
        conn.close()


def _write_server_config(tmp_path: Path) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / "servers.yml"
    path.write_text(
        """
servers:
  - name: local
    enabled: true
    location: test
    ssh:
      host: 127.0.0.1
      port: 22
      user: root
      auth:
        type: password
    vpn:
      endpoint_host: vpn.example.test
      port: 37661
      interface: awg0
      network_cidr: 10.8.0.0/24
      server_address: 10.8.0.1/24
      dns: 1.1.1.1
      allowed_ips: 0.0.0.0/0
      max_devices: 254
      server_public_key: server-public-key
    firewall:
      provider: ufw
      open_vpn_port: true
    runtime:
      type: docker
      container_name: amnezia-awg2
      config_path: /opt/amnezia/awg/awg0.conf
""".lstrip(),
        encoding="utf-8",
    )
    return path


class _repo:
    def __init__(self, database_path: Path) -> None:
        self._database_path = database_path
        self._conn = None

    def __enter__(self) -> Repository:
        self._conn = connect(self._database_path)
        initialize_schema(self._conn)
        return Repository(self._conn)

    def __exit__(self, *args) -> None:
        assert self._conn is not None
        self._conn.close()
