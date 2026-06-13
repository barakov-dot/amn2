from __future__ import annotations

from typing import Any


def build_telemetry_retention_policy() -> dict[str, Any]:
    return {
        "status": "telemetry_retention_policy_ready",
        "aggregate_retention": {
            "status": "bounded_aggregate_retention_ready",
            "raw_snapshot_retention_days": 7,
            "aggregate_retention_days": 180,
            "raw_export_enabled": False,
            "allowed_aggregate_keys": [
                "servers_by_status",
                "users_by_status",
                "devices_by_status",
                "orders_by_status",
                "traffic_totals_by_day",
                "health_age_buckets",
            ],
        },
        "redaction": {
            "status": "redaction_contract_ready",
            "identity_fields_allowed": False,
            "secret_material_allowed": False,
            "forbidden_raw_categories": [
                "identity_fields",
                "peer_key_material",
                "endpoint_values",
                "client_config_artifacts",
                "command_output",
                "raw_tokens",
            ],
        },
        "upstream_refresh_incorporation": {
            "status": "watcher_candidate_incorporation_ready",
            "default_action": "candidate_rows_only",
            "live_actions_enabled": False,
            "code_copy_enabled": False,
            "automation_ids": [
                "amnezia-weekly-upstream-refresh",
                "prvtpro-weekly-upstream-refresh",
                "weekly-kyoresuas-upstream-refresh",
            ],
            "required_review_before_incorporation": [
                "license_boundary",
                "security_delta",
                "local_tests",
                "evidence_update",
            ],
        },
        "docs": {
            "policy_doc": "docs/TELEMETRY_RETENTION_POLICY.ru.md",
        },
    }
