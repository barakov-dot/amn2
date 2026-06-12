from __future__ import annotations

import re
from pathlib import Path

from fastapi.testclient import TestClient

from app.config.settings import Settings
from app.db.connection import connect
from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.web.app import create_web_app
from app.web.auth import create_password_hash


def test_api_readiness_requires_login(tmp_path: Path):
    client = TestClient(create_web_app(_settings(tmp_path)))

    response = client.get("/api-readiness", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_api_readiness_shows_read_only_status_without_secrets(tmp_path: Path):
    settings = _settings(tmp_path)
    _seed_api_readiness_data(Path(settings.database_path))
    client = _authenticated_client(settings)

    response = client.get("/api-readiness")

    assert response.status_code == 200
    assert "Готовность API" in response.text
    assert "server:read" in response.text
    assert "metrics:read" in response.text
    assert "Серверы" in response.text
    assert "Пользователи" in response.text
    assert "Устройства" in response.text
    assert "1" in response.text
    forbidden = [
        "PrivateKey",
        "PresharedKey",
        "vpn://",
        "token_hash",
        "Authorization",
        "client.conf",
        "wg0.conf",
    ]
    assert all(marker not in response.text for marker in forbidden)


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        _env_file=None,
        telegram_bot_token="TEST_TOKEN",
        app_secret_key="test-secret",
        database_path=str(tmp_path / "amneziya.sqlite3"),
        web_admin_username="root",
        web_admin_password_hash=create_password_hash(
            "correct-password",
            salt="test-salt",
        ),
        web_admin_session_secret="s" * 32,
        web_admin_session_cookie_secure=True,
    )


def _authenticated_client(settings: Settings) -> TestClient:
    client = TestClient(create_web_app(settings), base_url="https://testserver")
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


def _seed_api_readiness_data(database_path: Path) -> None:
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
        server_id = repo.upsert_server_config(
            name="local",
            host="127.0.0.1",
            ssh_port=22,
            endpoint_host="127.0.0.1",
            vpn_port=51820,
            vpn_network_cidr="10.8.1.0/24",
            server_address="10.8.1.1/24",
            server_public_key="public-key",
            runtime="docker",
            firewall="none",
            max_devices=100,
        )
        repo.create_device(
            user_id=user_id,
            server_id=server_id,
            name="phone",
            duration_days=7,
            peer_public_key="peer-public-key",
            peer_private_key_encrypted="v1:peer-private-key",
            preshared_key_encrypted="v1:peer-preshared-key",
            vpn_ip="10.8.1.2",
            config_version="amneziawg_v2",
        )
    finally:
        conn.close()
