from __future__ import annotations

import re
import subprocess
from pathlib import Path

from fastapi.testclient import TestClient

from app.config.settings import Settings
from app.db.connection import connect
from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.web.app import create_web_app
from app.web.auth import create_password_hash


def test_integration_status_page_requires_login(tmp_path: Path):
    client = TestClient(create_web_app(_settings(tmp_path)), base_url="https://testserver")

    response = client.get("/integration-status", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_integration_status_page_renders_gate_without_secret_markers(tmp_path: Path):
    settings = _settings(tmp_path)
    _seed_server(Path(settings.database_path))
    client = _authenticated_client(settings)

    response = client.get("/integration-status")

    assert response.status_code == 200
    assert "Integration status" in response.text
    assert (
        "Операторский пилот: web/admin остается на 127.0.0.1:3030 через SSH-туннель; "
        "API 3040 только loopback/read-only."
    ) in response.text
    assert (
        "Публичный доступ, выдача конфигов и write routes требуют отдельных named gates."
        in response.text
    )
    assert "phase-6-productization-planning" in response.text
    assert "operator-only-pilot-accepted" in response.text
    assert _expected_git_head() in response.text
    assert "2215761" in response.text
    assert "not-package-rebuilt-not-vps-smoked" in response.text
    assert "20260613T045107Z" in response.text
    assert "ssh-tunnel-loopback" in response.text
    assert "active-on-disposable-test-vps" in response.text
    assert "absent-or-loopback-only" in response.text
    assert "local-only-not-vps-smoked" in response.text
    assert "policy-registry-ready" in response.text
    assert "single-server-operator-control" in response.text
    assert "amneziawg" in response.text
    assert "wireguard" in response.text
    assert "xray" in response.text
    assert "manual-approval-boundary-ready" in response.text
    assert "separate-bot-boundary-ready" in response.text
    assert "payment processor enabled" in response.text
    assert "False" in response.text
    assert "support bot" in response.text
    assert "news bot" in response.text
    assert "blocked-future" in response.text
    assert "identity-mutation-gate-ready" in response.text
    assert "telegram api enabled" in response.text
    assert "P6-I005 Telegram identity mutation gate" in response.text
    assert "aggregate-privacy-boundary-ready" in response.text
    assert "scheduler-contract-ready" in response.text
    assert "aggregate-only-analytics-ready" in response.text
    assert "per peer breakdown enabled" in response.text
    assert "reconciliation-release-boundary-ready" in response.text
    assert "report-only-plan-ready" in response.text
    assert "release-checklist-ready" in response.text
    assert "live reconciliation enabled" in response.text
    assert "telemetry-retention-policy-ready" in response.text
    assert "bounded-aggregate-retention-ready" in response.text
    assert "watcher-candidate-incorporation-ready" in response.text
    assert "candidate-rows-only" in response.text
    assert "dry-run-only-pass" in response.text
    assert "Phase 2 live write gate" in response.text
    assert "verified-live" in response.text
    assert "new live peer apply/revoke without separate operator confirmation" in response.text
    assert "payment processor integration without named gate" in response.text
    assert "support/news bot runtime without separate token gate" in response.text
    assert "Telegram profile icon mutation without P6-I005 gate" in response.text
    assert "live health/status polling without P6-M002 gate" in response.text
    assert "attach-existing-server reconciliation apply without P6-M003 gate" in response.text
    assert "raw telemetry export without P6-N004 retention/redaction gate" in response.text
    assert "P6-N001 public docs/API taxonomy if approved" in response.text
    assert "server:read" in response.text
    forbidden = [
        "PrivateKey",
        "PresharedKey",
        "Authorization",
        "token_hash",
        "vpn://",
        "client.conf",
        "wg0.conf",
        "docker exec",
        "awg show",
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


def _seed_server(db_path: Path) -> None:
    conn = connect(db_path)
    try:
        initialize_schema(conn)
        repo = Repository(conn)
        repo.upsert_server_config(
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
    finally:
        conn.close()


def _expected_git_head() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()
