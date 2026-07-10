from __future__ import annotations

import re
from pathlib import Path

from fastapi.testclient import TestClient

from app.config.settings import Settings
from app.db.connection import connect
from app.db.schema import initialize_schema
from app.services.api_tokens import hash_api_token
from app.web.app import create_web_app
from app.web.auth import create_password_hash


def test_api_tokens_requires_login(tmp_path: Path):
    client = TestClient(create_web_app(_settings(tmp_path)))

    response = client.get("/api-tokens", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_api_token_issue_displays_raw_token_once_without_hash_leak(tmp_path: Path):
    settings = _settings(tmp_path)
    client = _authenticated_client(settings)
    form = client.get("/api-tokens")

    response = client.post(
        "/api-tokens/issue",
        data={
            "csrf_token": _csrf_token(form.text),
            "name": "VPS smoke",
            "owner_label": "ops",
            "integration_kind": "monitoring",
            "purpose": "VPS health polling",
            "scope": ["server:read", "metrics:read"],
            "expires_days": "7",
        },
    )

    assert response.status_code == 200
    assert "Raw API token" in response.text
    raw_token = _raw_token(response.text)
    assert raw_token
    assert "token_hash" not in response.text
    assert hash_api_token(raw_token) not in response.text

    refresh = client.get("/api-tokens")

    assert refresh.status_code == 200
    assert "VPS smoke" in refresh.text
    assert "ops" in refresh.text
    assert "monitoring" in refresh.text
    assert "VPS health polling" in refresh.text
    assert "server:read" in refresh.text
    assert "metrics:read" in refresh.text
    assert raw_token not in refresh.text
    assert hash_api_token(raw_token) not in refresh.text
    assert "token_hash" not in refresh.text


def test_api_token_revoke_marks_token_revoked_without_secret_output(tmp_path: Path):
    settings = _settings(tmp_path)
    client = _authenticated_client(settings)
    raw_token = _issue_token(client, name="Token to revoke")
    token_id = _single_token_id(Path(settings.database_path))
    page = client.get("/api-tokens")

    response = client.post(
        f"/api-tokens/{token_id}/revoke",
        data={"csrf_token": _csrf_token(page.text)},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/api-tokens"
    assert raw_token not in client.get("/api-tokens").text
    assert hash_api_token(raw_token) not in client.get("/api-tokens").text

    row = _single_token_row(Path(settings.database_path))
    assert row["revoked_at"]
    assert row["revoke_reason"] == "web-admin-revoke"


def test_api_token_rotate_preserves_integration_identity_and_shows_new_secret_once(
    tmp_path: Path,
):
    settings = _settings(tmp_path)
    client = _authenticated_client(settings)
    old_raw_token = _issue_token(client, name="Bot observer")
    old_token_id = _single_token_id(Path(settings.database_path))
    page = client.get("/api-tokens")

    response = client.post(
        f"/api-tokens/{old_token_id}/rotate",
        data={"csrf_token": _csrf_token(page.text), "expires_days": "14"},
    )

    assert response.status_code == 200
    new_raw_token = _raw_token(response.text)
    assert new_raw_token != old_raw_token
    assert old_raw_token not in response.text
    assert hash_api_token(new_raw_token) not in response.text
    rows = _token_rows(Path(settings.database_path))
    assert len(rows) == 2
    old_row = next(row for row in rows if row["id"] == old_token_id)
    new_row = next(row for row in rows if row["id"] != old_token_id)
    assert old_row["revoke_reason"] == "rotated"
    assert new_row["rotated_from_token_id"] == old_token_id
    assert new_row["integration_kind"] == "telegram_bot"
    assert new_row["purpose"] == "Operator notifications"
    refresh = client.get("/api-tokens")
    assert new_raw_token not in refresh.text
    assert hash_api_token(new_raw_token) not in refresh.text


def test_api_token_issue_rejects_unsupported_scope_without_mutating(tmp_path: Path):
    settings = _settings(tmp_path)
    client = _authenticated_client(settings)
    form = client.get("/api-tokens")

    response = client.post(
        "/api-tokens/issue",
        data={
            "csrf_token": _csrf_token(form.text),
            "name": "Bad token",
            "owner_label": "ops",
            "integration_kind": "web_panel",
            "purpose": "Unsafe config export",
            "scope": ["config:read"],
            "expires_days": "7",
        },
        follow_redirects=False,
    )

    assert response.status_code == 400
    assert "unsupported API token scopes" in response.text
    assert _token_count(Path(settings.database_path)) == 0


def test_api_token_issue_rejects_expiry_beyond_production_ttl_without_mutating(
    tmp_path: Path,
):
    settings = _settings(tmp_path)
    client = _authenticated_client(settings)
    form = client.get("/api-tokens")

    response = client.post(
        "/api-tokens/issue",
        data={
            "csrf_token": _csrf_token(form.text),
            "name": "Long token",
            "owner_label": "ops",
            "integration_kind": "monitoring",
            "purpose": "Long polling credential",
            "scope": ["server:read"],
            "expires_days": "31",
        },
        follow_redirects=False,
    )

    assert response.status_code == 400
    assert "expires_days must be in 1..30" in response.text
    assert _token_count(Path(settings.database_path)) == 0


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


def _issue_token(client: TestClient, *, name: str) -> str:
    form = client.get("/api-tokens")
    response = client.post(
        "/api-tokens/issue",
        data={
            "csrf_token": _csrf_token(form.text),
            "name": name,
            "owner_label": "ops",
            "integration_kind": "telegram_bot",
            "purpose": "Operator notifications",
            "scope": ["server:read"],
            "expires_days": "7",
        },
    )
    assert response.status_code == 200
    return _raw_token(response.text)


def _csrf_token(html: str) -> str:
    match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html)
    assert match is not None
    return match.group(1)


def _raw_token(html: str) -> str:
    match = re.search(r'<code class="raw-token">([^<]+)</code>', html)
    assert match is not None
    return match.group(1)


def _single_token_id(database_path: Path) -> str:
    return str(_single_token_row(database_path)["id"])


def _single_token_row(database_path: Path):
    conn = connect(database_path)
    try:
        initialize_schema(conn)
        row = conn.execute("SELECT * FROM api_tokens").fetchone()
        assert row is not None
        return row
    finally:
        conn.close()


def _token_count(database_path: Path) -> int:
    conn = connect(database_path)
    try:
        initialize_schema(conn)
        row = conn.execute("SELECT COUNT(*) AS count FROM api_tokens").fetchone()
        return int(row["count"])
    finally:
        conn.close()


def _token_rows(database_path: Path):
    conn = connect(database_path)
    try:
        initialize_schema(conn)
        return conn.execute("SELECT * FROM api_tokens ORDER BY created_at, id").fetchall()
    finally:
        conn.close()
