from pathlib import Path

from app.services.reconciliation_release_boundary import (
    build_reconciliation_release_boundary,
)


def test_attach_existing_server_reconciliation_stays_report_only():
    boundary = build_reconciliation_release_boundary()
    reconciliation = boundary["attach_existing_server_reconciliation"]

    assert boundary["status"] == "reconciliation_release_boundary_ready"
    assert reconciliation["status"] == "report_only_plan_ready"
    assert reconciliation["enabled_by_default"] is False
    assert reconciliation["live_reconciliation_enabled"] is False
    assert reconciliation["allowed_inputs"] == [
        "stored_server_config",
        "redacted_peer_inventory",
        "operator_supplied_mapping",
        "aggregate_health_status",
    ]
    assert reconciliation["allowed_outputs"] == [
        "safe_diff_counts",
        "adoption_plan_summary",
        "blocked_action_list",
        "manual_gate_checklist",
    ]
    assert reconciliation["blocked_without_gate"] == [
        "live_peer_import",
        "local_device_creation",
        "peer_removal",
        "server_config_overwrite",
        "config_delivery",
        "local_agent_mutation",
    ]
    assert reconciliation["requires_gates"] == [
        "P6-M003 reconciliation apply gate",
        "P6-C003 write API production gate",
        "production peer/user mutation gate",
    ]


def test_release_checklist_blocks_public_or_package_progression_by_default():
    checklist = build_reconciliation_release_boundary()["release_checklist"]

    assert checklist["status"] == "release_checklist_ready"
    assert checklist["default_release_action"] == "planning_only"
    assert checklist["latest_vps_smoked_package_head"] == "2215761"
    assert checklist["branch_head_package_status"] == "not_package_rebuilt_not_vps_smoked"
    assert checklist["allowed_without_gate"] == [
        "local_tests",
        "docs_evidence_update",
        "changelog_draft",
        "operator_only_release_notes",
    ]
    assert checklist["blocked_without_gate"] == [
        "package_apply_or_rebuild_on_vps",
        "public_exposure",
        "config_delivery",
        "write_api_enablement",
        "local_agent_mutation",
        "production_peer_user_mutation",
    ]
    assert checklist["required_named_gates_before_public_release"] == [
        "P6-C001",
        "P6-C002",
        "P6-C003",
        "P6-C004",
        "P6-M003 apply gate",
    ]


def test_reconciliation_release_boundary_doc_exists():
    boundary = build_reconciliation_release_boundary()

    doc_path = Path(boundary["docs"]["policy_doc"])
    text = doc_path.read_text(encoding="utf-8")
    assert "attach-existing-server" in text
    assert "release checklist" in text
    assert "write API" in text
    assert "live reconciliation" in text
