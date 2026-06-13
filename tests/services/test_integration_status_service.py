from __future__ import annotations

from pathlib import Path

from app.db.connection import connect
from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.services.integration_status import build_integration_status


FORBIDDEN_MARKERS = [
    "PrivateKey",
    "PresharedKey",
    "Authorization",
    "token_hash",
    "vpn://",
    ".conf",
    "root@",
    "docker exec",
    "awg show",
]


def test_build_integration_status_reports_controlled_prod_without_write_enablement(tmp_path: Path):
    db_path = tmp_path / "amneziya.sqlite3"
    conn = connect(db_path)
    try:
        initialize_schema(conn)
        repo = Repository(conn)
        _seed_server(repo)

        report = build_integration_status(repo)
    finally:
        conn.close()

    assert report["status"] == "phase_6_productization_planning"
    assert report["source_checkpoint"] == {
        "current_branch_head": "b676e1b",
        "latest_vps_smoked_package_head": "2215761",
        "latest_vps_smoke_status": "live_update_smoke_pass",
        "package_status_for_branch_head": "not_package_rebuilt_not_vps_smoked",
        "public_self_service_open": False,
        "vps_apply_enabled_default": False,
    }
    assert report["api_baseline"]["status"] == "phase_6_planning_ready"
    assert report["api_baseline"]["stable_head"] == "b676e1b"
    assert report["api_baseline"]["previous_stable_head"] == "2215761"
    assert report["api_baseline"]["api_web_baseline_head"] == "b676e1b"
    assert report["api_baseline"]["integration_status_head"] == "b676e1b"
    assert report["api_baseline"]["write_routes_enabled"] is False
    assert report["api_baseline"]["public_api_exposed"] is False
    assert report["remote_operation_gate"]["candidate_head"] == "7281254"
    assert report["remote_operation_gate"]["stable_merge_head"] == "708c98e"
    assert report["remote_operation_gate"]["phase_1"] == "dry_run_only_pass"
    assert report["remote_operation_gate"]["phase_2"] == "verified_live"
    assert report["remote_operation_gate"]["write_operations_enabled"] is False
    assert report["controlled_prod_readiness"]["status"] == "operator_only_pilot_accepted"
    assert report["controlled_prod_readiness"]["decision"] == "operator-only-pilot-accepted"
    assert report["controlled_prod_readiness"]["runbook"] == "docs/ROUTE_AUTH_OPERATION_POLICY.ru.md"
    assert report["controlled_prod_readiness"]["source_overlay_head"] == "2215761"
    assert report["controlled_prod_readiness"]["vps_smoke_run_id"] == "20260613T045107Z"
    assert report["controlled_prod_readiness"]["source_update_run_id"] == "20260613T045004Z"
    assert report["controlled_prod_readiness"]["web_admin_access"] == "ssh_tunnel_loopback"
    assert report["controlled_prod_readiness"]["manual_web_check"] == "passed"
    assert report["controlled_prod_readiness"]["service_deployment"] == "active_on_disposable_test_vps"
    assert report["controlled_prod_readiness"]["api_listener"] == "absent_or_loopback_only"
    assert report["controlled_prod_readiness"]["vps_apply_enabled_default"] is False
    assert report["local_read_only_extension"]["head"] == "b676e1b"
    assert report["local_read_only_extension"]["status"] == "local_only_not_vps_smoked"
    assert report["local_read_only_extension"]["vps_smoke_status"] == "not_run_for_branch_head"
    assert report["local_read_only_extension"]["checked_routes"] == 6
    assert report["local_read_only_extension"]["workspace"] == "local_branch"
    assert report["local_read_only_extension"]["token_lifecycle"] == "revoked"
    assert report["aggregate_state"]["servers"] == 1
    assert report["capability_registry"]["status"] == "policy_registry_ready"
    assert report["capability_registry"]["current_branch_head"] == "b676e1b"
    assert report["capability_registry"]["latest_vps_smoked_package_head"] == "2215761"
    assert report["capability_registry"]["server_capabilities"] == [
        {
            "capability": "single_server_operator_control",
            "status": "implemented_operator_only",
            "runtime": "docker",
            "protocol": "amneziawg",
            "safe_surfaces": [
                "web_admin_operator_only",
                "read_only_api_aggregate",
                "bot_access_flow",
            ],
        }
    ]
    assert report["capability_registry"]["future_protocols"] == [
        {
            "protocol": "wireguard",
            "status": "blocked_future",
            "gate": "P6-M001 implementation gate",
            "license_boundary": "no upstream code copy",
        },
        {
            "protocol": "xray",
            "status": "blocked_future",
            "gate": "P6-M001 implementation gate",
            "license_boundary": "no upstream code copy",
        },
    ]
    assert "new live peer apply/revoke without separate operator confirmation" in report["blocked_lanes"]
    assert "/api/clients write CRUD" in report["blocked_lanes"]
    assert "additional protocol managers without capability registry" in report["blocked_lanes"]
    assert report["next_gate"] == "P6-I003 commercial/manual approval boundary"


def test_build_integration_status_contains_no_secret_or_command_markers(tmp_path: Path):
    db_path = tmp_path / "amneziya.sqlite3"
    conn = connect(db_path)
    try:
        initialize_schema(conn)
        repo = Repository(conn)
        _seed_server(repo)

        report_text = repr(build_integration_status(repo))
    finally:
        conn.close()

    for marker in FORBIDDEN_MARKERS:
        assert marker not in report_text


def test_controlled_prod_runbook_reference_exists(tmp_path: Path):
    db_path = tmp_path / "amneziya.sqlite3"
    conn = connect(db_path)
    try:
        initialize_schema(conn)
        repo = Repository(conn)
        _seed_server(repo)

        report = build_integration_status(repo)
    finally:
        conn.close()

    runbook_path = Path(report["controlled_prod_readiness"]["runbook"])
    assert runbook_path.exists()


def _seed_server(repo: Repository) -> None:
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
