from __future__ import annotations

import re
from importlib import metadata
from pathlib import Path

from fastapi.testclient import TestClient

from app.config.settings import Settings
from app.web.app import create_web_app
from app.web.auth import create_password_hash


def test_about_requires_login(tmp_path: Path):
    client = TestClient(create_web_app(_settings(tmp_path)))

    response = client.get("/about", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_about_shows_read_only_build_status_without_secrets(tmp_path: Path):
    settings = _settings(tmp_path)
    client = _authenticated_client(settings)

    dashboard_response = client.get("/")
    response = client.get("/about")

    assert dashboard_response.status_code == 200
    assert 'href="/about"' in dashboard_response.text
    assert response.status_code == 200
    assert "О системе" in response.text
    assert "Версия приложения" in response.text
    assert _expected_package_version() in response.text
    assert "Python runtime" in response.text
    assert "Статус сборки" in response.text
    assert "read-only" in response.text
    assert "No auto-update" in response.text
    assert "Write-действия" in response.text
    assert "not available" in response.text

    forbidden = [
        "PrivateKey",
        "PresharedKey",
        "vpn://",
        "token_hash",
        "Authorization",
        "client.conf",
        "wg0.conf",
        "APP_SECRET_KEY",
        "WEB_ADMIN_PASSWORD_HASH",
        "WEB_ADMIN_SESSION_SECRET",
        "VPS_SSH_PASSWORD",
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


def _expected_package_version() -> str:
    try:
        return metadata.version("amneziya")
    except metadata.PackageNotFoundError:
        return "unknown"
