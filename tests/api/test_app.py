from pathlib import Path
import json

from fastapi.testclient import TestClient

from app.api.app import create_api_app
from app.config.settings import Settings
from app.db.connection import connect
from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.services.api_tokens import hash_api_token


AGENT_TOKEN_HASH = (
    "sha256:"
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)


def test_api_servers_requires_server_read_scope_and_returns_safe_summary(tmp_path: Path):
    settings, repo = _seed_api_data(tmp_path)
    _store_token(repo, raw_token="server-token", scopes=["server:read"])
    client = TestClient(create_api_app(settings))

    missing = client.get("/api/servers")
    response = client.get(
        "/api/servers",
        headers={"Authorization": "Bearer server-token"},
    )

    assert missing.status_code == 401
    assert response.status_code == 200
    payload = response.json()
    assert payload["servers"] == [
        {
            "name": "local",
            "status": "active",
            "enabled": True,
            "configured": True,
            "runtime": "host_systemd",
            "device_counts": {"active": 1, "total": 2},
            "health": {
                "status": "online",
                "latency_ms": 20,
                "checked_at": payload["servers"][0]["health"]["checked_at"],
                "readiness": {"ssh": True, "awg": True, "udp_port": True},
            },
        }
    ]
    assert payload["servers"][0]["health"]["checked_at"]
    assert _forbidden_markers_absent(payload)


def test_api_server_summary_returns_one_server_without_secret_fields(tmp_path: Path):
    settings, repo = _seed_api_data(tmp_path)
    _store_token(repo, raw_token="server-token", scopes=["server:read"])
    client = TestClient(create_api_app(settings))

    found = client.get(
        "/api/servers/local/summary",
        headers={"Authorization": "Bearer server-token"},
    )
    missing = client.get(
        "/api/servers/missing/summary",
        headers={"Authorization": "Bearer server-token"},
    )

    assert found.status_code == 200
    assert found.json()["server"]["name"] == "local"
    assert found.json()["server"]["device_counts"] == {"active": 1, "total": 2}
    assert missing.status_code == 404
    assert _forbidden_markers_absent(found.json())


def test_api_metrics_requires_metrics_read_scope(tmp_path: Path):
    settings, repo = _seed_api_data(tmp_path)
    _store_token(repo, raw_token="server-token", scopes=["server:read"])
    _store_token(repo, raw_token="metrics-token", scopes=["metrics:read"])
    client = TestClient(create_api_app(settings))

    denied = client.get(
        "/api/metrics/summary",
        headers={"Authorization": "Bearer server-token"},
    )
    allowed = client.get(
        "/api/metrics/summary",
        headers={"Authorization": "Bearer metrics-token"},
    )

    assert denied.status_code == 403
    assert allowed.status_code == 200
    assert allowed.json() == {
        "users": {"total": 1, "active": 1, "blocked": 0, "deleted": 0},
        "servers": {"total": 1, "active": 1, "degraded": 0, "disabled": 0},
        "devices": {"total": 2, "active": 1, "disabled": 0, "revoked": 1},
        "traffic": {
            "rx_bytes": 150,
            "tx_bytes": 250,
            "source": "latest_device_snapshots",
        },
    }
    assert _forbidden_markers_absent(allowed.json())


def test_api_users_summary_requires_metrics_scope_and_omits_personal_fields(tmp_path: Path):
    settings, repo = _seed_api_data(tmp_path)
    blocked_user_id = repo.create_user_for_admin(
        telegram_id=3002,
        username="secret-user",
        first_name="Secret",
        last_name="Person",
        email="secret@example.com",
        status="blocked",
        is_admin=False,
    )
    repo.create_order(user_id=blocked_user_id, plan_id=None, payment_mode="manual")
    _store_token(repo, raw_token="server-token", scopes=["server:read"])
    _store_token(repo, raw_token="metrics-token", scopes=["metrics:read"])
    client = TestClient(create_api_app(settings))

    denied = client.get(
        "/api/users/summary",
        headers={"Authorization": "Bearer server-token"},
    )
    allowed = client.get(
        "/api/users/summary",
        headers={"Authorization": "Bearer metrics-token"},
    )

    assert denied.status_code == 403
    assert allowed.status_code == 200
    assert allowed.json() == {
        "users": {
            "total": 2,
            "active": 1,
            "blocked": 1,
            "deleted": 0,
            "admins": 0,
        },
        "devices": {
            "users_with_devices": 1,
            "users_without_devices": 1,
        },
        "orders": {
            "total": 1,
            "manual_review": 1,
            "approved": 0,
            "fulfilled": 0,
            "payment_pending": 0,
            "rejected": 0,
        },
    }
    serialized = json.dumps(allowed.json())
    assert "secret-user" not in serialized
    assert "secret@example.com" not in serialized
    assert "3002" not in serialized
    assert _forbidden_markers_absent(allowed.json())


def test_api_read_routes_record_safe_audit_metadata(tmp_path: Path):
    settings, repo = _seed_api_data(tmp_path)
    _store_token(
        repo,
        raw_token="metrics-token",
        scopes=["metrics:read"],
        token_id="api_metrics_read",
    )
    client = TestClient(create_api_app(settings))

    response = client.get(
        "/api/metrics/summary",
        headers={"Authorization": "Bearer metrics-token"},
    )

    assert response.status_code == 200
    row = repo._conn.execute(
        "SELECT admin_telegram_id, action, metadata_json FROM admin_actions ORDER BY id DESC LIMIT 1"
    ).fetchone()
    assert row is not None
    assert row["admin_telegram_id"] == 0
    assert row["action"] == "api_read"
    metadata = json.loads(row["metadata_json"])
    assert metadata == {
        "aggregate_only": True,
        "method": "GET",
        "owner_label": "ops",
        "path": "/api/metrics/summary",
        "scope": "metrics:read",
        "status": "allowed",
        "token_id": "api_metrics_read",
        "token_name": "API token",
    }
    serialized = row["metadata_json"]
    assert "metrics-token" not in serialized
    assert "Authorization" not in serialized
    assert "token_hash" not in serialized


def test_api_auth_rejects_invalid_token_without_echoing_secret(tmp_path: Path):
    settings, _repo = _seed_api_data(tmp_path)
    client = TestClient(create_api_app(settings))

    response = client.get(
        "/api/servers",
        headers={"Authorization": "Bearer raw-invalid-token"},
    )

    assert response.status_code == 401
    assert "raw-invalid-token" not in response.text
    assert "token_hash" not in response.text


def test_api_local_agent_runtime_summary_is_controller_safe(tmp_path: Path):
    settings, repo = _seed_api_data(
        tmp_path,
        local_agent_enabled=True,
        local_agent_host="10.9.0.10",
        local_agent_port=3041,
        local_agent_token_hash=AGENT_TOKEN_HASH,
        local_agent_token_id="agent-secret-token-id",
        local_agent_token_owner="agent-secret-owner",
    )
    _store_token(repo, raw_token="server-token", scopes=["server:read"])
    _store_token(repo, raw_token="metrics-token", scopes=["metrics:read"])
    client = TestClient(create_api_app(settings))

    denied = client.get(
        "/api/local-agent/runtime/summary",
        headers={"Authorization": "Bearer metrics-token"},
    )
    allowed = client.get(
        "/api/local-agent/runtime/summary",
        headers={"Authorization": "Bearer server-token"},
    )

    assert denied.status_code == 403
    assert allowed.status_code == 200
    payload = allowed.json()
    assert payload == {
        "local_agent": {
            "configured": True,
            "connectivity": "not_checked",
            "read_only": True,
            "source": "controller_settings",
            "write_routes_enabled": False,
            "runtime_summary": {
                "agent_status": "configured_not_checked",
                "agent_version": None,
                "runtime_contract_version": 1,
                "write_enabled": False,
                "controller_display_status": "safe",
                "runtime_type": "unknown",
                "runtime_status": "unknown",
                "protocols": [],
            },
        }
    }
    assert _forbidden_markers_absent(payload)
    serialized = json.dumps(payload)
    for forbidden in (
        AGENT_TOKEN_HASH,
        "agent-secret-token-id",
        "agent-secret-owner",
        "10.9.0.10",
        "3041",
        "server-token",
        "Authorization",
        "token_hash",
        "sha256",
        "container_name",
        "interface",
        "config_path",
        "docker exec",
        "awg show",
    ):
        assert forbidden not in serialized

    row = repo._conn.execute(
        "SELECT action, metadata_json FROM admin_actions ORDER BY id DESC LIMIT 1"
    ).fetchone()
    assert row is not None
    assert row["action"] == "api_read"
    metadata = json.loads(row["metadata_json"])
    assert metadata == {
        "aggregate_only": True,
        "method": "GET",
        "owner_label": "ops",
        "path": "/api/local-agent/runtime/summary",
        "scope": "server:read",
        "status": "allowed",
        "token_id": "token-server-token",
        "token_name": "API token",
    }


def test_install_mutation_request_requires_install_write_scope_and_never_applies_when_disabled(
    tmp_path: Path,
):
    settings, repo = _seed_api_data(tmp_path, vps_apply_enabled=False)
    _store_token(repo, raw_token="server-token", scopes=["server:read"])
    _store_token(
        repo,
        raw_token="install-token",
        scopes=["install:write"],
        token_id="api_install_write",
    )
    client = TestClient(create_api_app(settings))

    denied = client.post(
        "/api/install/mutation-requests",
        json={"requested_action": "clean_install_prepare", "target": "local"},
        headers={"Authorization": "Bearer server-token"},
    )
    allowed = client.post(
        "/api/install/mutation-requests",
        json={
            "requested_action": "clean_install_prepare",
            "target": "local",
            "operator_note": "must-not-appear-in-audit",
        },
        headers={"Authorization": "Bearer install-token"},
    )

    assert denied.status_code == 403
    assert allowed.status_code == 202
    payload = allowed.json()
    assert payload == {
        "install_mutation_request": {
            "status": "recorded_blocked_by_vps_apply_disabled",
            "request_recorded": True,
            "requested_action": "clean_install_prepare",
            "target": "local",
            "execution": {
                "vps_apply_enabled": False,
                "executor_invoked": False,
                "package_apply_performed": False,
                "service_restart_performed": False,
                "public_exposure_performed": False,
                "config_delivery_performed": False,
                "telegram_action_performed": False,
            },
            "safe_evidence": True,
        }
    }
    assert _forbidden_markers_absent(payload)

    row = repo._conn.execute(
        "SELECT action, metadata_json FROM admin_actions ORDER BY id DESC LIMIT 1"
    ).fetchone()
    assert row is not None
    assert row["action"] == "api_write"
    metadata = json.loads(row["metadata_json"])
    assert metadata == {
        "aggregate_only": False,
        "method": "POST",
        "owner_label": "ops",
        "path": "/api/install/mutation-requests",
        "requested_action": "clean_install_prepare",
        "scope": "install:write",
        "status": "recorded_blocked_by_vps_apply_disabled",
        "target": "local",
        "token_id": "api_install_write",
        "token_name": "API token",
        "vps_apply_enabled": False,
    }
    serialized = row["metadata_json"]
    assert "install-token" not in serialized
    assert "server-token" not in serialized
    assert "Authorization" not in serialized
    assert "token_hash" not in serialized
    assert "must-not-appear-in-audit" not in serialized


def _seed_api_data(tmp_path: Path, **settings_overrides: object) -> tuple[Settings, Repository]:
    db_path = tmp_path / "api.sqlite3"
    settings_values = {
        "_env_file": None,
        "telegram_bot_token": "CHANGE_ME",
        "app_secret_key": "test-secret",
        "database_path": str(db_path),
    }
    settings_values.update(settings_overrides)
    settings = Settings(**settings_values)
    conn = connect(db_path)
    initialize_schema(conn)
    repo = Repository(conn)
    user_id = repo.upsert_user(
        telegram_id=2001,
        username="bob",
        first_name="Bob",
        last_name=None,
    )
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    active_device_id = _insert_device(
        repo,
        user_id=user_id,
        server_id=server_id,
        vpn_ip="10.8.0.2",
        peer_public_key="active-public",
        status="active",
    )
    _insert_device(
        repo,
        user_id=user_id,
        server_id=server_id,
        vpn_ip="10.8.0.3",
        peer_public_key="revoked-public",
        status="revoked",
    )
    repo.record_server_health(
        server_id=server_id,
        status="online",
        latency_ms=20,
        ssh_ok=True,
        awg_ok=True,
        udp_port_ok=True,
        error="must not appear in API",
    )
    repo.record_device_traffic_snapshot(
        device_id=active_device_id,
        server_id=server_id,
        peer_public_key="active-public",
        rx_bytes=100,
        tx_bytes=200,
        source="test",
        collected_at="2026-06-01T10:00:00Z",
    )
    repo.record_device_traffic_snapshot(
        device_id=active_device_id,
        server_id=server_id,
        peer_public_key="active-public",
        rx_bytes=150,
        tx_bytes=250,
        source="test",
        collected_at="2026-06-01T10:05:00Z",
    )
    return settings, repo


def _store_token(
    repo: Repository,
    *,
    raw_token: str,
    scopes: list[str],
    token_id: str | None = None,
) -> None:
    repo.create_api_token(
        token_id=token_id or f"token-{raw_token}",
        name="API token",
        owner_user_id=None,
        owner_label="ops",
        token_hash=hash_api_token(raw_token),
        scopes=scopes,
        expires_at="2099-01-01T00:00:00+00:00",
    )


def _insert_device(
    repo: Repository,
    *,
    user_id: int,
    server_id: int,
    vpn_ip: str,
    peer_public_key: str,
    status: str,
) -> int:
    cursor = repo._conn.execute(
        """
        INSERT INTO devices (
            user_id,
            server_id,
                name,
                duration_days,
                expires_at,
                status,
            vpn_ip,
            peer_public_key,
            peer_private_key_encrypted,
            preshared_key_encrypted,
            config_version
        )
            VALUES (?, ?, ?, ?, datetime('now', '+7 days'), ?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            server_id,
            f"{status}-device",
            7,
            status,
            vpn_ip,
            peer_public_key,
            f"v1:{status}-private",
            f"v1:{status}-psk",
            "amneziawg_v2",
        ),
    )
    repo._conn.commit()
    return int(cursor.lastrowid)


def _forbidden_markers_absent(payload: object) -> bool:
    text = str(payload).lower()
    forbidden = (
        "private",
        "preshared",
        "psk",
        "vpn://",
        "token_hash",
        "raw-token",
        "raw token",
        "peer_public_key",
        "server_public_key",
        "ssh_port",
        "endpoint_host",
        "must not appear",
    )
    return all(marker not in text for marker in forbidden)
