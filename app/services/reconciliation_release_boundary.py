from __future__ import annotations

from typing import Any


LATEST_VPS_SMOKED_PACKAGE_HEAD = "2215761"
BRANCH_HEAD_PACKAGE_STATUS = "not_package_rebuilt_not_vps_smoked"


def build_reconciliation_release_boundary() -> dict[str, Any]:
    return {
        "status": "reconciliation_release_boundary_ready",
        "attach_existing_server_reconciliation": {
            "status": "report_only_plan_ready",
            "enabled_by_default": False,
            "live_reconciliation_enabled": False,
            "allowed_inputs": [
                "stored_server_config",
                "redacted_peer_inventory",
                "operator_supplied_mapping",
                "aggregate_health_status",
            ],
            "allowed_outputs": [
                "safe_diff_counts",
                "adoption_plan_summary",
                "blocked_action_list",
                "manual_gate_checklist",
            ],
            "blocked_without_gate": [
                "live_peer_import",
                "local_device_creation",
                "peer_removal",
                "server_config_overwrite",
                "config_delivery",
                "local_agent_mutation",
            ],
            "requires_gates": [
                "P6-M003 reconciliation apply gate",
                "P6-C003 write API production gate",
                "production peer/user mutation gate",
            ],
        },
        "release_checklist": {
            "status": "release_checklist_ready",
            "default_release_action": "planning_only",
            "latest_vps_smoked_package_head": LATEST_VPS_SMOKED_PACKAGE_HEAD,
            "branch_head_package_status": BRANCH_HEAD_PACKAGE_STATUS,
            "allowed_without_gate": [
                "local_tests",
                "docs_evidence_update",
                "changelog_draft",
                "operator_only_release_notes",
            ],
            "blocked_without_gate": [
                "package_apply_or_rebuild_on_vps",
                "public_exposure",
                "config_delivery",
                "write_api_enablement",
                "local_agent_mutation",
                "production_peer_user_mutation",
            ],
            "required_named_gates_before_public_release": [
                "P6-C001",
                "P6-C002",
                "P6-C003",
                "P6-C004",
                "P6-M003 apply gate",
            ],
        },
        "docs": {
            "policy_doc": "docs/RECONCILIATION_RELEASE_CHECKLIST.ru.md",
        },
    }
