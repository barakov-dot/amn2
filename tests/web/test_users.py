import json
import re
from pathlib import Path

from fastapi.testclient import TestClient

import app.web.app as web_app
from app.config.settings import Settings
from app.db.connection import connect
from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.security.crypto import SecretBox
from app.server.peer_apply import PeerApplyError
from app.web.app import create_web_app
from app.web.auth import create_password_hash

TEST_APP_SECRET = "test-secret-for-web-users-1234567890"


def test_users_redirects_when_unauthenticated(tmp_path: Path):
    client = _client(tmp_path)

    response = client.get("/users", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_disabled_devices_redirects_when_unauthenticated(tmp_path: Path):
    client = _client(tmp_path)

    response = client.get("/devices/disabled", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_users_lists_existing_telegram_users_and_device_counts(tmp_path: Path):
    settings = _settings(tmp_path)
    user_id = _seed_user(
        Path(settings.database_path),
        telegram_id=1001,
        username="alice",
        first_name="Alice",
        last_name="Admin",
        email="alice@example.com",
        status="active",
        is_admin=True,
    )
    _seed_devices(Path(settings.database_path), user_id=user_id)
    client = _authenticated_client(settings)

    response = client.get("/users")

    assert response.status_code == 200
    assert "1001" in response.text
    assert "alice" in response.text
    assert "Alice Admin" in response.text
    assert "alice@example.com" in response.text
    assert "active" in response.text
    assert "admin" in response.text.lower()
    assert "1 / 2" in response.text
    assert 'href="/devices/disabled"' in response.text


def test_disabled_devices_page_lists_only_disabled_devices(tmp_path: Path):
    settings = _settings(tmp_path)
    disabled_user_id = _seed_user(
        Path(settings.database_path),
        telegram_id=1010,
        username="disabled-owner",
        first_name="Disabled",
        last_name="Owner",
    )
    active_user_id = _seed_user(
        Path(settings.database_path),
        telegram_id=2020,
        username="active-owner",
        first_name="Active",
        last_name="Owner",
    )
    _seed_encrypted_device(
        Path(settings.database_path),
        user_id=disabled_user_id,
        private_key="client-private-key",
        preshared_key="stored-psk",
        status="disabled",
    )
    _seed_devices(Path(settings.database_path), user_id=active_user_id)
    client = _authenticated_client(settings)

    response = client.get("/devices/disabled")

    assert response.status_code == 200
    assert "Отключенные устройства" in response.text
    assert "encrypted-device" in response.text
    assert "disabled-owner" in response.text
    assert "10.8.0.44" in response.text
    assert "local" in response.text
    assert f'href="/users/{disabled_user_id}"' in response.text
    assert "active-device" not in response.text
    assert "active-owner" not in response.text


def test_create_user_from_web_stores_email_admin_and_records_action(tmp_path: Path):
    settings = _settings(tmp_path, admin_telegram_ids="9001")
    client = _authenticated_client(settings)
    form = client.get("/users/new")
    assert form.status_code == 200

    response = client.post(
        "/users/new",
        data={
            "telegram_id": "3003",
            "username": "carol",
            "first_name": "Carol",
            "last_name": "Creator",
            "email": "carol@example.com",
            "status": "active",
            "is_admin": "on",
            "csrf_token": _csrf_token(form.text),
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert re.fullmatch(r"/users/\d+", response.headers["location"])
    with _repo(Path(settings.database_path)) as repo:
        user = repo.get_user_by_telegram_id(3003)
        assert user is not None
        assert user["username"] == "carol"
        assert user["first_name"] == "Carol"
        assert user["last_name"] == "Creator"
        assert user["email"] == "carol@example.com"
        assert user["email_verified_at"] is None
        assert user["status"] == "active"
        assert user["is_admin"] == 1
        actions = repo.list_admin_actions_for_target_user(int(user["id"]))
        assert actions[0]["admin_telegram_id"] == 9001
        assert actions[0]["action"] == "web_user_create"


def test_create_user_rejects_duplicate_telegram_id_without_mutating_existing_user(
    tmp_path: Path,
):
    settings = _settings(tmp_path)
    user_id = _seed_user(
        Path(settings.database_path),
        telegram_id=3003,
        username="existing",
        first_name="Existing",
        last_name="User",
        email="existing@example.com",
        email_verified_at="2026-05-29T10:00:00Z",
        status="active",
        is_admin=False,
    )
    client = _authenticated_client(settings)
    form = client.get("/users/new")

    response = client.post(
        "/users/new",
        data={
            "telegram_id": "3003",
            "username": "mutated",
            "first_name": "Mutated",
            "last_name": "Admin",
            "email": "mutated@example.com",
            "status": "blocked",
            "is_admin": "on",
            "csrf_token": _csrf_token(form.text),
        },
        follow_redirects=False,
    )

    assert response.status_code == 400
    with _repo(Path(settings.database_path)) as repo:
        user = repo.get_user(user_id)
        assert user["username"] == "existing"
        assert user["first_name"] == "Existing"
        assert user["last_name"] == "User"
        assert user["email"] == "existing@example.com"
        assert user["email_verified_at"] == "2026-05-29T10:00:00Z"
        assert user["status"] == "active"
        assert user["is_admin"] == 0
        assert repo.list_admin_actions_for_target_user(user_id) == []


def test_user_detail_shows_profile_summaries_and_actions(tmp_path: Path):
    settings = _settings(tmp_path)
    user_id = _seed_user(
        Path(settings.database_path),
        telegram_id=4004,
        username="dana",
        first_name="Dana",
        last_name="Detail",
        email="dana@example.com",
        email_verified_at="2026-05-29T10:00:00Z",
    )
    _seed_devices(Path(settings.database_path), user_id=user_id)
    _seed_order_and_action(Path(settings.database_path), user_id=user_id)
    client = _authenticated_client(settings)

    response = client.get(f"/users/{user_id}")

    assert response.status_code == 200
    assert "dana" in response.text
    assert "dana@example.com" in response.text
    assert ">verified<" in response.text
    assert "active-device" in response.text
    assert "Disable VPN" in response.text
    assert "Enable VPN" in response.text
    assert "Show secrets" in response.text
    assert "Delete permanently" in response.text
    assert "v1:active-private" not in response.text
    assert "v1:active-psk" not in response.text
    assert "manual_review" in response.text
    assert "seed_action" in response.text


def test_user_detail_shows_device_expiration_contract(tmp_path: Path):
    settings = _settings(tmp_path)
    user_id = _seed_user(
        Path(settings.database_path),
        telegram_id=4014,
        username="lifecycle-user",
        first_name="Life",
        last_name="Contract",
    )
    _seed_devices(Path(settings.database_path), user_id=user_id)
    with _repo(Path(settings.database_path)) as repo:
        repo._conn.execute(
            "UPDATE devices SET expires_at = ? WHERE user_id = ? AND name = ?",
            ("2026-06-27 12:00:00", user_id, "active-device"),
        )
        repo._conn.commit()
    client = _authenticated_client(settings)

    response = client.get(f"/users/{user_id}")

    assert response.status_code == 200
    assert "<th>Expires</th>" in response.text
    assert "2026-06-27 12:00:00" in response.text
    assert "active-device" in response.text


def test_user_detail_marks_external_only_device_without_config_actions(tmp_path: Path):
    settings = _settings(tmp_path)
    user_id = _seed_user(
        Path(settings.database_path),
        telegram_id=4024,
        username="external-user",
        first_name="External",
        last_name="Import",
        email="external@example.com",
    )
    with _repo(Path(settings.database_path)) as repo:
        server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
        repo.create_external_device(
            user_id=user_id,
            server_id=server_id,
            name="Neobyatnaya-AMNZ-4",
            duration_days=30,
            vpn_ip="10.8.0.44",
            peer_public_key="external-peer-4",
            config_version="amneziawg_v2",
            status="revoked",
            revoked_at="2026-06-09T10:00:00Z",
            revoke_reason="phase3_test_revoked",
        )
    client = _authenticated_client(settings)

    response = client.get(f"/users/{user_id}")

    assert response.status_code == 200
    assert "Neobyatnaya-AMNZ-4" in response.text
    assert "external-only импорт" in response.text
    assert "Импортировано только для видимости; исходный конфиг недоступен." in response.text
    assert (
        "Повторная отправка конфига, секреты и email-доставка недоступны для этой external-only записи."
        in response.text
    )
    assert "Show secrets" not in response.text
    assert "Email config" not in response.text


def test_user_detail_admin_actions_show_metadata(tmp_path: Path):
    settings = _settings(tmp_path, admin_telegram_ids="9001")
    user_id = _seed_user(
        Path(settings.database_path),
        telegram_id=4054,
        username="audit-user",
        first_name="Audit",
        last_name=None,
    )
    device_id = _seed_encrypted_device(
        Path(settings.database_path),
        user_id=user_id,
        private_key="client-private-key",
        preshared_key="stored-psk",
        status="disabled",
    )
    with _repo(Path(settings.database_path)) as repo:
        repo.record_admin_action(
            admin_telegram_id=9001,
            action="web_user_enable_vpn_failed",
            target_user_id=user_id,
            target_device_id=device_id,
            metadata={
                "operation": "enable_user_vpn",
                "error_type": "PeerApplyError",
                "redacted_error": "Docker apply failed",
            },
        )
    client = _authenticated_client(settings)

    response = client.get(f"/users/{user_id}")

    assert response.status_code == 200
    assert "Admin actions" in response.text
    assert "Metadata" in response.text
    assert "Target device" in response.text
    assert f"#{device_id}" in response.text
    assert "enable_user_vpn" in response.text
    assert "PeerApplyError" in response.text
    assert "Docker apply failed" in response.text


def test_user_detail_marks_dangerous_actions_with_confirmation(tmp_path: Path):
    settings = _settings(tmp_path)
    user_id = _seed_user(
        Path(settings.database_path),
        telegram_id=4104,
        username="danger-user",
        first_name="Danger",
        last_name=None,
    )
    _seed_devices(Path(settings.database_path), user_id=user_id)
    client = _authenticated_client(settings)

    response = client.get(f"/users/{user_id}")

    assert response.status_code == 200
    assert "window.confirm(message)" in response.text
    assert (
        "Disable VPN for this user? This changes local device status and may remove "
        "active peers from AmneziaWG when VPS_APPLY_ENABLED=true."
    ) in response.text
    assert (
        "Enable VPN for this user? This changes local device status and may add "
        "disabled peers back to AmneziaWG when VPS_APPLY_ENABLED=true."
    ) in response.text
    assert "Soft delete this user in the admin database?" in response.text
    assert "Permanently delete this user and all related data? This cannot be undone." in response.text
    assert (
        "Delete this device? This deletes local data and may revoke its peer from "
        "AmneziaWG when VPS_APPLY_ENABLED=true. This cannot be undone."
    ) in response.text


def test_user_detail_shows_vpn_action_availability_for_active_devices(tmp_path: Path):
    settings = _settings(tmp_path)
    user_id = _seed_user(
        Path(settings.database_path),
        telegram_id=4204,
        username="active-vpn-actions",
        first_name="Active",
        last_name=None,
    )
    _seed_devices(Path(settings.database_path), user_id=user_id)
    client = _authenticated_client(settings)

    response = client.get(f"/users/{user_id}")

    assert response.status_code == 200
    assert "1 active/pending device can be disabled" in response.text
    assert "No disabled devices to enable" in response.text
    assert 'name="enable_vpn_unavailable"' in response.text


def test_user_detail_shows_vpn_action_availability_for_disabled_devices(tmp_path: Path):
    settings = _settings(tmp_path)
    user_id = _seed_user(
        Path(settings.database_path),
        telegram_id=4304,
        username="disabled-vpn-actions",
        first_name="Disabled",
        last_name=None,
        status="blocked",
    )
    _seed_encrypted_device(
        Path(settings.database_path),
        user_id=user_id,
        private_key="client-private-key",
        preshared_key="stored-psk",
        status="disabled",
    )
    client = _authenticated_client(settings)

    response = client.get(f"/users/{user_id}")

    assert response.status_code == 200
    assert "No active or pending devices to disable" in response.text
    assert "1 disabled device can be enabled" in response.text
    assert 'name="disable_vpn_unavailable"' in response.text


def test_edit_user_preserves_and_clears_email_verification(tmp_path: Path):
    settings = _settings(tmp_path, admin_telegram_ids="9001")
    user_id = _seed_user(
        Path(settings.database_path),
        telegram_id=5005,
        username="erin",
        first_name="Erin",
        last_name="Editor",
        email="erin@example.com",
        email_verified_at="2026-05-29T10:00:00Z",
    )
    client = _authenticated_client(settings)

    form = client.get(f"/users/{user_id}/edit")
    assert form.status_code == 200
    same_email_response = client.post(
        f"/users/{user_id}/edit",
        data={
            "telegram_id": "5005",
            "username": "erin-updated",
            "first_name": "Erin",
            "last_name": "Editor",
            "email": "erin@example.com",
            "status": "active",
            "csrf_token": _csrf_token(form.text),
        },
        follow_redirects=False,
    )

    assert same_email_response.status_code == 303
    with _repo(Path(settings.database_path)) as repo:
        user = repo.get_user(user_id)
        assert user["username"] == "erin-updated"
        assert user["email_verified_at"] == "2026-05-29T10:00:00Z"
        assert user["is_admin"] == 0
        assert repo.list_admin_actions_for_target_user(user_id)[0]["action"] == "web_user_update"

    form = client.get(f"/users/{user_id}/edit")
    assert form.status_code == 200
    changed_email_response = client.post(
        f"/users/{user_id}/edit",
        data={
            "telegram_id": "5005",
            "username": "erin-updated",
            "first_name": "Erin",
            "last_name": "Editor",
            "email": "new-erin@example.com",
            "status": "active",
            "is_admin": "on",
            "csrf_token": _csrf_token(form.text),
        },
        follow_redirects=False,
    )

    assert changed_email_response.status_code == 303
    with _repo(Path(settings.database_path)) as repo:
        user = repo.get_user(user_id)
        assert user["email"] == "new-erin@example.com"
        assert user["email_verified_at"] is None
        assert user["is_admin"] == 1


def test_block_and_delete_mutate_status_but_keep_user_row(tmp_path: Path):
    settings = _settings(tmp_path, admin_telegram_ids="9001")
    user_id = _seed_user(
        Path(settings.database_path),
        telegram_id=6006,
        username="frank",
        first_name="Frank",
        last_name=None,
    )
    client = _authenticated_client(settings)

    detail = client.get(f"/users/{user_id}")
    assert detail.status_code == 200
    block_response = client.post(
        f"/users/{user_id}/block",
        data={"csrf_token": _csrf_token(detail.text)},
        follow_redirects=False,
    )

    assert block_response.status_code == 303
    with _repo(Path(settings.database_path)) as repo:
        user = repo.get_user(user_id)
        assert user["status"] == "blocked"
        assert user["telegram_id"] == 6006
        assert repo.list_admin_actions_for_target_user(user_id)[0]["action"] == "web_user_block"

    detail = client.get(f"/users/{user_id}")
    assert detail.status_code == 200
    delete_response = client.post(
        f"/users/{user_id}/delete",
        data={"csrf_token": _csrf_token(detail.text)},
        follow_redirects=False,
    )

    assert delete_response.status_code == 303
    with _repo(Path(settings.database_path)) as repo:
        user = repo.get_user(user_id)
        assert user["status"] == "deleted"
        assert user["telegram_id"] == 6006
        assert repo.list_admin_actions_for_target_user(user_id)[0]["action"] == "web_user_delete"


def test_disable_user_vpn_revokes_remote_peers_and_keeps_user_row(
    tmp_path: Path,
    monkeypatch,
):
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(
        web_app,
        "ServerConfigPeerApplier",
        _fake_peer_applier(calls),
    )
    server_config_path = _write_server_config(tmp_path, server_name="local")
    settings = _settings(
        tmp_path,
        admin_telegram_ids="9001",
        vps_apply_enabled=True,
        server_config_path=server_config_path,
    )
    user_id = _seed_user(
        Path(settings.database_path),
        telegram_id=6106,
        username="frank-vpn",
        first_name="Frank",
        last_name=None,
    )
    _seed_devices(Path(settings.database_path), user_id=user_id)
    client = _authenticated_client(settings)

    detail = client.get(f"/users/{user_id}")
    response = client.post(
        f"/users/{user_id}/disable-vpn",
        data={"csrf_token": _csrf_token(detail.text)},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == f"/users/{user_id}"
    assert calls == [("local", f"active-public-{user_id}")]
    with _repo(Path(settings.database_path)) as repo:
        user = repo.get_user(user_id)
        devices = repo.list_user_devices_for_admin(user_id)
        assert user["status"] == "blocked"
        assert [device["status"] for device in devices] == ["revoked", "disabled"]
        latest_action = repo.list_admin_actions_for_target_user(user_id)[0]
        assert latest_action["action"] == "web_user_disable_vpn"
        assert '"disabled_device_count": 1' in latest_action["metadata_json"]


def test_disable_user_vpn_with_apply_disabled_marks_local_devices_only(tmp_path: Path):
    settings = _settings(tmp_path, vps_apply_enabled=False)
    user_id = _seed_user(
        Path(settings.database_path),
        telegram_id=6206,
        username="gina",
        first_name="Gina",
        last_name=None,
    )
    _seed_devices(Path(settings.database_path), user_id=user_id)
    client = _authenticated_client(settings)

    detail = client.get(f"/users/{user_id}")
    response = client.post(
        f"/users/{user_id}/disable-vpn",
        data={"csrf_token": _csrf_token(detail.text)},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == f"/users/{user_id}"
    with _repo(Path(settings.database_path)) as repo:
        user = repo.get_user(user_id)
        devices = repo.list_user_devices_for_admin(user_id)
        assert user["status"] == "blocked"
        assert [device["status"] for device in devices] == ["revoked", "disabled"]
        latest_action = repo.list_admin_actions_for_target_user(user_id)[0]
        assert latest_action["action"] == "web_user_disable_vpn"
        assert '"vps_apply": "skipped"' in latest_action["metadata_json"]


def test_disable_user_vpn_returns_redacted_peer_apply_error(
    tmp_path: Path,
    monkeypatch,
):
    class FailingPeerApplier:
        def __init__(self, server, *, password=None):
            self._server = server

        def remove_peer(self, *, server, peer_public_key: str) -> None:
            raise PeerApplyError(
                "Docker revoke failed: PresharedKey = secret-psk"
            )

    monkeypatch.setattr(web_app, "ServerConfigPeerApplier", FailingPeerApplier)
    server_config_path = _write_server_config(tmp_path, server_name="local")
    settings = _settings(
        tmp_path,
        vps_apply_enabled=True,
        server_config_path=server_config_path,
    )
    user_id = _seed_user(
        Path(settings.database_path),
        telegram_id=6236,
        username="redacted-error",
        first_name="Redacted",
        last_name=None,
    )
    _seed_devices(Path(settings.database_path), user_id=user_id)
    client = _authenticated_client(settings)

    detail = client.get(f"/users/{user_id}")
    response = client.post(
        f"/users/{user_id}/disable-vpn",
        data={"csrf_token": _csrf_token(detail.text)},
        follow_redirects=False,
    )

    assert response.status_code == 400
    assert "PeerApplyError: Docker revoke failed" in response.text
    assert "secret-psk" not in response.text
    with _repo(Path(settings.database_path)) as repo:
        user = repo.get_user(user_id)
        devices = repo.list_user_devices_for_admin(user_id)
        actions = repo.list_admin_actions_for_target_user(user_id)
        metadata = json.loads(actions[0]["metadata_json"])
        assert user["status"] == "active"
        assert sorted(device["status"] for device in devices) == ["active", "revoked"]
        assert actions[0]["action"] == "web_user_disable_vpn_failed"
        assert metadata["operation"] == "disable_user_vpn"
        assert metadata["error_type"] == "PeerApplyError"
        assert "Docker revoke failed" in metadata["redacted_error"]
        assert "secret-psk" not in metadata["redacted_error"]


def test_enable_user_vpn_reapplies_disabled_device_with_stored_key_and_ip(
    tmp_path: Path,
    monkeypatch,
):
    calls: list[tuple[str, str, str, str]] = []
    monkeypatch.setattr(
        web_app,
        "ServerConfigPeerApplier",
        _fake_peer_applier_with_apply(calls),
    )
    server_config_path = _write_server_config(tmp_path, server_name="local")
    settings = _settings(
        tmp_path,
        admin_telegram_ids="9001",
        vps_apply_enabled=True,
        server_config_path=server_config_path,
    )
    user_id = _seed_user(
        Path(settings.database_path),
        telegram_id=6256,
        username="gina-vpn",
        first_name="Gina",
        last_name=None,
        status="blocked",
    )
    device_id = _seed_encrypted_device(
        Path(settings.database_path),
        user_id=user_id,
        private_key="client-private-key",
        preshared_key="stored-psk",
        status="disabled",
    )
    client = _authenticated_client(settings)

    detail = client.get(f"/users/{user_id}")
    response = client.post(
        f"/users/{user_id}/enable-vpn",
        data={"csrf_token": _csrf_token(detail.text)},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == f"/users/{user_id}"
    assert calls == [("local", "encrypted-public", "stored-psk", "10.8.0.44")]
    with _repo(Path(settings.database_path)) as repo:
        user = repo.get_user(user_id)
        device = repo.get_device(device_id)
        assert user["status"] == "active"
        assert device["status"] == "active"
        assert device["vpn_ip"] == "10.8.0.44"
        latest_action = repo.list_admin_actions_for_target_user(user_id)[0]
        assert latest_action["action"] == "web_user_enable_vpn"
        assert '"enabled_device_count": 1' in latest_action["metadata_json"]


def test_delete_single_user_device_revokes_only_selected_peer_and_cleans_links(
    tmp_path: Path,
    monkeypatch,
):
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(
        web_app,
        "ServerConfigPeerApplier",
        _fake_peer_applier(calls),
    )
    server_config_path = _write_server_config(tmp_path, server_name="local")
    settings = _settings(
        tmp_path,
        admin_telegram_ids="9001",
        vps_apply_enabled=True,
        server_config_path=server_config_path,
    )
    user_id = _seed_user(
        Path(settings.database_path),
        telegram_id=6260,
        username="device-owner",
        first_name="Device",
        last_name=None,
    )
    target_device_id = _seed_encrypted_device(
        Path(settings.database_path),
        user_id=user_id,
        private_key="client-private-key",
        preshared_key="stored-psk",
        status="active",
    )
    _seed_devices(Path(settings.database_path), user_id=user_id)
    with _repo(Path(settings.database_path)) as repo:
        order_id = repo.create_order(
            user_id=user_id,
            plan_id=None,
            payment_mode="free_test",
        )
        repo.mark_order_fulfilled(order_id, target_device_id)
        repo.record_admin_action(
            admin_telegram_id=9001,
            action="seed_device_action",
            target_user_id=user_id,
            target_device_id=target_device_id,
            metadata={"source": "test"},
        )
    client = _authenticated_client(settings)
    detail = client.get(f"/users/{user_id}")
    assert "Удалить устройство" in detail.text

    response = client.post(
        f"/users/{user_id}/devices/{target_device_id}/delete",
        data={"csrf_token": _csrf_token(detail.text)},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == f"/users/{user_id}"
    assert calls == [("local", "encrypted-public")]
    with _repo(Path(settings.database_path)) as repo:
        remaining_devices = repo.list_user_devices_for_admin(user_id)
        assert target_device_id in {int(device["id"]) for device in remaining_devices}
        assert len(remaining_devices) == 3
        assert repo.get_device(target_device_id)["status"] == "revoked"
        assert repo.get_order(order_id)["device_id"] is None
        seeded_action = repo._conn.execute(
            "SELECT * FROM admin_actions WHERE action = ?",
            ("seed_device_action",),
        ).fetchone()
        assert seeded_action["target_device_id"] == target_device_id
        latest_action = repo.list_admin_actions_for_target_user(user_id)[0]
        assert latest_action["action"] == "web_device_revoke_cascade"
        assert f'"device_id": {target_device_id}' in latest_action["metadata_json"]
        assert '"remote_peer_removed": true' in latest_action["metadata_json"]


def test_delete_single_user_device_with_apply_disabled_refuses_local_only_revoke(
    tmp_path: Path,
    monkeypatch,
):
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(
        web_app,
        "ServerConfigPeerApplier",
        _fake_peer_applier(calls),
    )
    settings = _settings(tmp_path, admin_telegram_ids="9001", vps_apply_enabled=False)
    user_id = _seed_user(
        Path(settings.database_path),
        telegram_id=6261,
        username="local-delete-owner",
        first_name="Local",
        last_name=None,
    )
    target_device_id = _seed_encrypted_device(
        Path(settings.database_path),
        user_id=user_id,
        private_key="client-private-key",
        preshared_key="stored-psk",
        status="active",
    )
    client = _authenticated_client(settings)
    detail = client.get(f"/users/{user_id}")

    response = client.post(
        f"/users/{user_id}/devices/{target_device_id}/delete",
        data={"csrf_token": _csrf_token(detail.text)},
        follow_redirects=False,
    )

    assert response.status_code == 400
    assert "local-only revoke is refused" in response.text
    assert calls == []
    with _repo(Path(settings.database_path)) as repo:
        assert repo.get_device(target_device_id)["status"] == "active"
        assert repo.list_admin_actions_for_target_user(user_id) == []


def test_user_detail_reveals_device_secrets_only_after_explicit_post(tmp_path: Path):
    settings = _settings(tmp_path)
    user_id = _seed_user(
        Path(settings.database_path),
        telegram_id=6266,
        username="secret-user",
        first_name="Secret",
        last_name=None,
    )
    device_id = _seed_encrypted_device(
        Path(settings.database_path),
        user_id=user_id,
        private_key="client-private-key",
        preshared_key="stored-psk",
        status="active",
    )
    client = _authenticated_client(settings)

    detail = client.get(f"/users/{user_id}")
    assert detail.status_code == 200
    assert "client-private-key" not in detail.text
    assert "stored-psk" not in detail.text

    revealed = client.post(
        f"/users/{user_id}/devices/{device_id}/secrets",
        data={"csrf_token": _csrf_token(detail.text)},
    )

    assert revealed.status_code == 200
    assert "client-private-key" in revealed.text
    assert "stored-psk" in revealed.text


def test_destroy_user_revokes_vpn_and_deletes_user_data(
    tmp_path: Path,
    monkeypatch,
):
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(
        web_app,
        "ServerConfigPeerApplier",
        _fake_peer_applier(calls),
    )
    server_config_path = _write_server_config(tmp_path, server_name="local")
    settings = _settings(
        tmp_path,
        admin_telegram_ids="9001",
        vps_apply_enabled=True,
        server_config_path=server_config_path,
    )
    user_id = _seed_user(
        Path(settings.database_path),
        telegram_id=6306,
        username="harry",
        first_name="Harry",
        last_name=None,
    )
    _seed_devices(Path(settings.database_path), user_id=user_id)
    _seed_order_and_action(Path(settings.database_path), user_id=user_id)
    client = _authenticated_client(settings)

    detail = client.get(f"/users/{user_id}")
    response = client.post(
        f"/users/{user_id}/destroy",
        data={"csrf_token": _csrf_token(detail.text)},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/users"
    assert calls == [("local", f"active-public-{user_id}")]
    conn = connect(Path(settings.database_path))
    try:
        initialize_schema(conn)
        assert conn.execute("SELECT COUNT(*) FROM users WHERE id = ?", (user_id,)).fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM devices WHERE user_id = ?", (user_id,)).fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM orders WHERE user_id = ?", (user_id,)).fetchone()[0] == 0
        assert conn.execute(
            "SELECT COUNT(*) FROM admin_actions WHERE target_user_id = ?",
            (user_id,),
        ).fetchone()[0] == 0
        destroy_action = conn.execute(
            "SELECT * FROM admin_actions WHERE action = 'web_user_destroy'"
        ).fetchone()
        assert destroy_action is not None
        assert destroy_action["target_user_id"] is None
        assert '"deleted_user_id": ' + str(user_id) in destroy_action["metadata_json"]
    finally:
        conn.close()


def test_invalid_csrf_does_not_create_edit_block_or_delete(tmp_path: Path):
    settings = _settings(tmp_path)
    user_id = _seed_user(
        Path(settings.database_path),
        telegram_id=7007,
        username="grace",
        first_name="Grace",
        last_name=None,
        email="grace@example.com",
    )
    client = _authenticated_client(settings)

    create_response = client.post(
        "/users/new",
        data={
            "telegram_id": "8008",
            "username": "hank",
            "first_name": "Hank",
            "last_name": "",
            "email": "hank@example.com",
            "status": "active",
        },
        follow_redirects=False,
    )
    edit_response = client.post(
        f"/users/{user_id}/edit",
        data={
            "telegram_id": "7007",
            "username": "mutated",
            "first_name": "Grace",
            "last_name": "",
            "email": "mutated@example.com",
            "status": "blocked",
            "csrf_token": "bad-token",
        },
        follow_redirects=False,
    )
    block_response = client.post(
        f"/users/{user_id}/block",
        data={"csrf_token": "bad-token"},
        follow_redirects=False,
    )
    delete_response = client.post(
        f"/users/{user_id}/delete",
        data={"csrf_token": "bad-token"},
        follow_redirects=False,
    )
    disable_vpn_response = client.post(
        f"/users/{user_id}/disable-vpn",
        data={"csrf_token": "bad-token"},
        follow_redirects=False,
    )
    enable_vpn_response = client.post(
        f"/users/{user_id}/enable-vpn",
        data={"csrf_token": "bad-token"},
        follow_redirects=False,
    )
    reveal_secrets_response = client.post(
        f"/users/{user_id}/devices/1/secrets",
        data={"csrf_token": "bad-token"},
        follow_redirects=False,
    )
    destroy_response = client.post(
        f"/users/{user_id}/destroy",
        data={"csrf_token": "bad-token"},
        follow_redirects=False,
    )

    assert create_response.status_code == 403
    assert edit_response.status_code == 403
    assert block_response.status_code == 403
    assert delete_response.status_code == 403
    assert disable_vpn_response.status_code == 403
    assert enable_vpn_response.status_code == 403
    assert reveal_secrets_response.status_code == 403
    assert destroy_response.status_code == 403
    with _repo(Path(settings.database_path)) as repo:
        assert repo.get_user_by_telegram_id(8008) is None
        user = repo.get_user(user_id)
        assert user["username"] == "grace"
        assert user["email"] == "grace@example.com"
        assert user["status"] == "active"
        assert repo.list_admin_actions_for_target_user(user_id) == []


def _settings(
    tmp_path: Path,
    *,
    admin_telegram_ids: str = "",
    session_cookie_secure: bool = True,
    vps_apply_enabled: bool = False,
    server_config_path: str | Path | None = None,
) -> Settings:
    return Settings(
        _env_file=None,
        telegram_bot_token="TEST_TOKEN",
        app_secret_key=TEST_APP_SECRET,
        database_path=str(tmp_path / "amneziya.sqlite3"),
        admin_telegram_ids=admin_telegram_ids,
        web_admin_username="root",
        web_admin_password_hash=create_password_hash(
            "correct-password",
            salt="test-salt",
        ),
        web_admin_session_secret="s" * 32,
        web_admin_session_cookie_secure=session_cookie_secure,
        vps_apply_enabled=vps_apply_enabled,
        server_config_path=str(server_config_path or (tmp_path / "servers.yml")),
    )


def _client(
    tmp_path: Path | None = None,
    *,
    settings: Settings | None = None,
    base_url: str = "https://testserver",
) -> TestClient:
    actual_settings = settings or _settings(tmp_path or Path("."))
    return TestClient(create_web_app(actual_settings), base_url=base_url)


def _authenticated_client(settings: Settings) -> TestClient:
    client = _client(settings=settings)
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


def _seed_user(
    database_path: Path,
    *,
    telegram_id: int,
    username: str,
    first_name: str,
    last_name: str | None,
    email: str | None = None,
    email_verified_at: str | None = None,
    status: str = "active",
    is_admin: bool = False,
) -> int:
    conn = connect(database_path)
    try:
        initialize_schema(conn)
        repo = Repository(conn)
        user_id = repo.upsert_user(
            telegram_id=telegram_id,
            username=username,
            first_name=first_name,
            last_name=last_name,
        )
        conn.execute(
            """
            UPDATE users
            SET email = ?,
                email_verified_at = ?,
                status = ?,
                is_admin = ?
            WHERE id = ?
            """,
            (email, email_verified_at, status, int(is_admin), user_id),
        )
        conn.commit()
        return user_id
    finally:
        conn.close()


def _seed_devices(database_path: Path, *, user_id: int) -> None:
    conn = connect(database_path)
    try:
        initialize_schema(conn)
        repo = Repository(conn)
        server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
        repo.create_device(
            user_id=user_id,
            server_id=server_id,
            name="active-device",
            duration_days=7,
            vpn_ip=f"10.8.0.{user_id + 2}",
            peer_public_key=f"active-public-{user_id}",
            peer_private_key_encrypted="v1:active-private",
            preshared_key_encrypted="v1:active-psk",
            config_version="amneziawg_v2",
        )
        revoked_id = repo.create_device(
            user_id=user_id,
            server_id=server_id,
            name="revoked-device",
            duration_days=7,
            vpn_ip=f"10.8.0.{user_id + 3}",
            peer_public_key=f"revoked-public-{user_id}",
            peer_private_key_encrypted="v1:revoked-private",
            preshared_key_encrypted="v1:revoked-psk",
            config_version="amneziawg_v2",
        )
        repo.revoke_device(
            revoked_id,
            reason="test",
            revoked_at="2026-05-29T10:00:00Z",
        )
    finally:
        conn.close()


def _seed_encrypted_device(
    database_path: Path,
    *,
    user_id: int,
    private_key: str,
    preshared_key: str,
    status: str,
) -> int:
    conn = connect(database_path)
    try:
        initialize_schema(conn)
        repo = Repository(conn)
        server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
        secret_box = SecretBox.from_app_secret(TEST_APP_SECRET)
        device_id = repo.create_device(
            user_id=user_id,
            server_id=server_id,
            name="encrypted-device",
            duration_days=7,
            vpn_ip="10.8.0.44",
            peer_public_key="encrypted-public",
            peer_private_key_encrypted=secret_box.encrypt_text(private_key),
            preshared_key_encrypted=secret_box.encrypt_text(preshared_key),
            config_version="amneziawg_v2",
        )
        if status == "disabled":
            repo.disable_user_devices(
                user_id,
                reason="test",
                disabled_at="2026-05-30T10:00:00Z",
            )
        elif status != "active":
            conn.execute("UPDATE devices SET status = ? WHERE id = ?", (status, device_id))
            conn.commit()
        return device_id
    finally:
        conn.close()


def _seed_order_and_action(database_path: Path, *, user_id: int) -> None:
    conn = connect(database_path)
    try:
        initialize_schema(conn)
        repo = Repository(conn)
        repo.create_order(user_id=user_id, plan_id=None, payment_mode="free_test")
        repo.record_admin_action(
            admin_telegram_id=9001,
            action="seed_action",
            target_user_id=user_id,
            metadata={"source": "test"},
        )
    finally:
        conn.close()


def _write_server_config(tmp_path: Path, *, server_name: str) -> Path:
    path = tmp_path / "servers.yml"
    path.write_text(
        f"""
servers:
  - name: {server_name}
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


def _fake_peer_applier(calls: list[tuple[str, str]]):
    class FakePeerApplier:
        def __init__(self, server, *, password=None):
            self._server = server

        def remove_peer(self, *, server, peer_public_key: str) -> None:
            calls.append((server.name, peer_public_key))

    return FakePeerApplier


def _fake_peer_applier_with_apply(calls: list[tuple[str, str, str, str]]):
    class FakePeerApplier:
        def __init__(self, server, *, password=None):
            self._server = server

        def apply_peer(self, *, server, peer_public_key: str, preshared_key: str, vpn_ip: str) -> None:
            calls.append((server.name, peer_public_key, preshared_key, vpn_ip))

    return FakePeerApplier
