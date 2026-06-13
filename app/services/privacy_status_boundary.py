from __future__ import annotations

from typing import Any


def build_privacy_status_boundary() -> dict[str, Any]:
    return {
        "status": "aggregate_privacy_boundary_ready",
        "health_status_scheduler": {
            "status": "scheduler_contract_ready",
            "enabled_by_default": False,
            "live_probes_enabled": False,
            "source": "stored_server_health_snapshots",
            "minimum_interval_seconds": 300,
            "allowed_aggregate_fields": [
                "servers_total",
                "servers_online",
                "servers_degraded",
                "servers_disabled",
                "latest_check_age_bucket",
                "scheduler_last_run_status",
            ],
            "blocked_without_gate": [
                "live_probe_execution",
                "raw_check_output",
                "per_peer_health_fields",
                "endpoint_host_export",
                "ssh_or_awg_command_output",
            ],
        },
        "admin_analytics": {
            "status": "aggregate_only_analytics_ready",
            "per_user_breakdown_enabled": False,
            "per_peer_breakdown_enabled": False,
            "allowed_widgets": [
                "users_by_status",
                "orders_by_status",
                "devices_by_status",
                "servers_by_status",
                "aggregate_traffic_totals",
            ],
            "forbidden_fields": [
                "telegram_id",
                "username",
                "email",
                "device_name",
                "peer_public_key",
                "endpoint_host",
                "client_config",
                "vpn_import_uri",
            ],
        },
        "docs": {
            "policy_doc": "docs/PRIVACY_STATUS_ANALYTICS_BOUNDARY.ru.md",
        },
    }
