from pathlib import Path

from app.services.telemetry_retention_policy import build_telemetry_retention_policy


def test_telemetry_retention_policy_keeps_aggregates_bounded_and_redacted():
    policy = build_telemetry_retention_policy()
    retention = policy["aggregate_retention"]
    redaction = policy["redaction"]

    assert policy["status"] == "telemetry_retention_policy_ready"
    assert retention["status"] == "bounded_aggregate_retention_ready"
    assert retention["raw_snapshot_retention_days"] == 7
    assert retention["aggregate_retention_days"] == 180
    assert retention["raw_export_enabled"] is False
    assert retention["allowed_aggregate_keys"] == [
        "servers_by_status",
        "users_by_status",
        "devices_by_status",
        "orders_by_status",
        "traffic_totals_by_day",
        "health_age_buckets",
    ]
    assert redaction["status"] == "redaction_contract_ready"
    assert redaction["identity_fields_allowed"] is False
    assert redaction["secret_material_allowed"] is False
    assert redaction["forbidden_raw_categories"] == [
        "identity_fields",
        "peer_key_material",
        "endpoint_values",
        "client_config_artifacts",
        "command_output",
        "raw_tokens",
    ]


def test_upstream_refresh_incorporation_stays_candidate_only():
    incorporation = build_telemetry_retention_policy()["upstream_refresh_incorporation"]

    assert incorporation["status"] == "watcher_candidate_incorporation_ready"
    assert incorporation["default_action"] == "candidate_rows_only"
    assert incorporation["live_actions_enabled"] is False
    assert incorporation["code_copy_enabled"] is False
    assert incorporation["automation_ids"] == [
        "amnezia-weekly-upstream-refresh",
        "prvtpro-weekly-upstream-refresh",
        "weekly-kyoresuas-upstream-refresh",
    ]
    assert incorporation["required_review_before_incorporation"] == [
        "license_boundary",
        "security_delta",
        "local_tests",
        "evidence_update",
    ]


def test_telemetry_retention_policy_doc_exists():
    policy = build_telemetry_retention_policy()

    doc_path = Path(policy["docs"]["policy_doc"])
    text = doc_path.read_text(encoding="utf-8")
    assert "retention" in text
    assert "redaction" in text
    assert "upstream refresh" in text
    assert "candidate rows" in text
