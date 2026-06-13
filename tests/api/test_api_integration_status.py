from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from app.api.app import create_api_app
from app.config.settings import Settings
from app.db.connection import connect
from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.services.api_tokens import hash_api_token


def test_integration_status_requires_bearer_token(tmp_path: Path):
    client = TestClient(create_api_app(_settings(tmp_path)))

    response = client.get("/api/integration/status")

    assert response.status_code == 401


def test_integration_status_rejects_missing_server_read_scope(tmp_path: Path):
    settings = _settings(tmp_path)
    _store_token(settings, raw_token="metrics-token", scopes=["metrics:read"])
    client = TestClient(create_api_app(settings))

    response = client.get(
        "/api/integration/status",
        headers={"Authorization": "Bearer metrics-token"},
    )

    assert response.status_code == 403


def test_integration_status_returns_safe_read_only_report_and_audit(tmp_path: Path):
    settings = _settings(tmp_path)
    _seed_server(Path(settings.database_path))
    _store_token(
        settings,
        raw_token="server-token",
        scopes=["server:read"],
        token_id="api_integration_status",
    )
    client = TestClient(create_api_app(settings))

    response = client.get(
        "/api/integration/status",
        headers={"Authorization": "Bearer server-token"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "phase_6_productization_planning"
    assert payload["source_checkpoint"]["current_branch_head"] == "b676e1b"
    assert payload["source_checkpoint"]["latest_vps_smoked_package_head"] == "2215761"
    assert (
        payload["source_checkpoint"]["package_status_for_branch_head"]
        == "not_package_rebuilt_not_vps_smoked"
    )
    assert payload["api_baseline"]["stable_head"] == "b676e1b"
    assert payload["api_baseline"]["previous_stable_head"] == "2215761"
    assert payload["api_baseline"]["api_web_baseline_head"] == "b676e1b"
    assert payload["api_baseline"]["integration_status_head"] == "b676e1b"
    assert payload["api_baseline"]["write_routes_enabled"] is False
    assert payload["api_baseline"]["public_api_exposed"] is False
    assert payload["remote_operation_gate"]["candidate_head"] == "7281254"
    assert payload["remote_operation_gate"]["stable_merge_head"] == "708c98e"
    assert payload["remote_operation_gate"]["write_operations_enabled"] is False
    assert payload["remote_operation_gate"]["phase_2"] == "verified_live"
    assert payload["controlled_prod_readiness"]["decision"] == "operator-only-pilot-accepted"
    assert payload["controlled_prod_readiness"]["source_overlay_head"] == "2215761"
    assert payload["controlled_prod_readiness"]["vps_smoke_run_id"] == "20260613T045107Z"
    assert payload["controlled_prod_readiness"]["source_update_run_id"] == "20260613T045004Z"
    assert payload["controlled_prod_readiness"]["web_admin_access"] == "ssh_tunnel_loopback"
    assert payload["controlled_prod_readiness"]["manual_web_check"] == "passed"
    assert payload["controlled_prod_readiness"]["service_deployment"] == "active_on_disposable_test_vps"
    assert payload["controlled_prod_readiness"]["api_listener"] == "absent_or_loopback_only"
    assert payload["controlled_prod_readiness"]["vps_apply_enabled_default"] is False
    assert payload["local_read_only_extension"]["head"] == "b676e1b"
    assert payload["local_read_only_extension"]["status"] == "local_only_not_vps_smoked"
    assert payload["local_read_only_extension"]["vps_smoke_status"] == "not_run_for_branch_head"
    assert payload["local_read_only_extension"]["checked_routes"] == 6
    assert payload["local_read_only_extension"]["workspace"] == "local_branch"
    assert payload["local_read_only_extension"]["token_lifecycle"] == "revoked"
    assert payload["capability_registry"]["status"] == "policy_registry_ready"
    assert payload["capability_registry"]["server_capabilities"][0]["protocol"] == "amneziawg"
    assert payload["capability_registry"]["server_capabilities"][0]["runtime"] == "docker"
    assert payload["capability_registry"]["future_protocols"][0]["protocol"] == "wireguard"
    assert payload["capability_registry"]["future_protocols"][1]["protocol"] == "xray"
    assert payload["next_gate"] == "P6-I003 commercial/manual approval boundary"
    assert payload["aggregate_state"]["servers"] == 1
    assert "new live peer apply/revoke without separate operator confirmation" in payload["blocked_lanes"]
    assert _forbidden_markers_absent(payload)

    conn = connect(Path(settings.database_path))
    try:
        row = conn.execute(
            "SELECT admin_telegram_id, action, metadata_json FROM admin_actions ORDER BY id DESC LIMIT 1"
        ).fetchone()
    finally:
        conn.close()
    assert row is not None
    assert row["admin_telegram_id"] == 0
    assert row["action"] == "api_read"
    metadata = json.loads(row["metadata_json"])
    assert metadata == {
        "aggregate_only": True,
        "method": "GET",
        "owner_label": "tests",
        "path": "/api/integration/status",
        "scope": "server:read",
        "status": "allowed",
        "token_id": "api_integration_status",
        "token_name": "Integration status test",
    }
    assert "server-token" not in row["metadata_json"]
    assert "Authorization" not in row["metadata_json"]
    assert "token_hash" not in row["metadata_json"]


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        _env_file=None,
        telegram_bot_token="CHANGE_ME",
        app_secret_key="test-secret",
        database_path=str(tmp_path / "amneziya.sqlite3"),
    )


def _store_token(
    settings: Settings,
    *,
    raw_token: str,
    scopes: list[str],
    token_id: str = "api_test_token",
) -> None:
    conn = connect(Path(settings.database_path))
    try:
        initialize_schema(conn)
        repo = Repository(conn)
        repo.create_api_token(
            token_id=token_id,
            name="Integration status test",
            owner_user_id=None,
            owner_label="tests",
            token_hash=hash_api_token(raw_token),
            scopes=scopes,
            expires_at="2099-01-01T00:00:00+00:00",
        )
    finally:
        conn.close()


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


def _forbidden_markers_absent(payload: object) -> bool:
    text = str(payload).lower()
    forbidden = (
        "private",
        "preshared",
        "psk",
        "vpn://",
        "token_hash",
        "server-token",
        "authorization",
        "peer_public_key",
        "server_public_key",
        "ssh_port",
        "endpoint_host",
        "docker exec",
        "awg show",
    )
    return all(marker not in text for marker in forbidden)
