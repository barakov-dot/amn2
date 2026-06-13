from pathlib import Path

from app.services.privacy_status_boundary import build_privacy_status_boundary


def test_privacy_status_boundary_keeps_health_polling_aggregate_only():
    boundary = build_privacy_status_boundary()

    scheduler = boundary["health_status_scheduler"]
    assert boundary["status"] == "aggregate_privacy_boundary_ready"
    assert scheduler["status"] == "scheduler_contract_ready"
    assert scheduler["enabled_by_default"] is False
    assert scheduler["live_probes_enabled"] is False
    assert scheduler["source"] == "stored_server_health_snapshots"
    assert scheduler["minimum_interval_seconds"] == 300
    assert scheduler["allowed_aggregate_fields"] == [
        "servers_total",
        "servers_online",
        "servers_degraded",
        "servers_disabled",
        "latest_check_age_bucket",
        "scheduler_last_run_status",
    ]
    assert scheduler["blocked_without_gate"] == [
        "live_probe_execution",
        "raw_check_output",
        "per_peer_health_fields",
        "endpoint_host_export",
        "ssh_or_awg_command_output",
    ]


def test_privacy_status_boundary_keeps_admin_analytics_without_identity_leakage():
    analytics = build_privacy_status_boundary()["admin_analytics"]

    assert analytics["status"] == "aggregate_only_analytics_ready"
    assert analytics["per_user_breakdown_enabled"] is False
    assert analytics["per_peer_breakdown_enabled"] is False
    assert analytics["allowed_widgets"] == [
        "users_by_status",
        "orders_by_status",
        "devices_by_status",
        "servers_by_status",
        "aggregate_traffic_totals",
    ]
    assert analytics["forbidden_fields"] == [
        "telegram_id",
        "username",
        "email",
        "device_name",
        "peer_public_key",
        "endpoint_host",
        "client_config",
        "vpn_import_uri",
    ]


def test_privacy_status_boundary_doc_exists():
    boundary = build_privacy_status_boundary()

    doc_path = Path(boundary["docs"]["policy_doc"])
    text = doc_path.read_text(encoding="utf-8")
    assert "aggregate-only" in text
    assert "per-peer" in text
    assert "per-user" in text
    assert "live probes" in text
