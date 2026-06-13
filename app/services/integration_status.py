from __future__ import annotations

from typing import Any

from app.db.repositories import Repository


ALLOWED_API_SCOPES = ("metrics:read", "server:read")
ALLOWED_LANES = (
    "read-only API status",
    "aggregate metrics",
    "web evidence UX",
    "API token lifecycle administration",
    "controlled prod status visibility",
    "Local Agent runtime summary visibility",
    "capability registry visibility",
    "manual validation VPS evidence",
)
BLOCKED_LANES = (
    "new live peer apply/revoke without separate operator confirmation",
    "/api/clients write CRUD",
    "API config:read",
    "public/self-service config delivery",
    "Local Agent configs or mutations",
    "backup/import/reboot routes",
    "public API 3040 exposure",
    "self-service runtime routes",
    "additional protocol managers without capability registry",
    "systemd/reverse proxy deployment on validation VPS",
)
CURRENT_STABLE_HEAD = "b676e1b"
PREVIOUS_STABLE_HEAD = "2215761"
POST_DRY_RUN_READ_ONLY_HEAD = "b676e1b"
API_WEB_BASELINE_HEAD = "b676e1b"
REMOTE_OPERATION_GATE_MERGE_HEAD = "708c98e"
REMOTE_OPERATION_GATE_CANDIDATE_HEAD = "7281254"
LATEST_VPS_SMOKED_PACKAGE_HEAD = "2215761"
LATEST_VPS_SMOKE_STATUS = "live_update_smoke_pass"
PACKAGE_STATUS_FOR_BRANCH_HEAD = "not_package_rebuilt_not_vps_smoked"
CONTROLLED_PROD_SMOKE_RUN_ID = "20260613T045107Z"
CONTROLLED_PROD_SOURCE_UPDATE_RUN_ID = "20260613T045004Z"
CURRENT_LOCAL_READ_ONLY_HEAD = CURRENT_STABLE_HEAD
CURRENT_LOCAL_READ_ONLY_SMOKE_STATUS = "not_run_for_branch_head"
CURRENT_LOCAL_READ_ONLY_SMOKE_CHECKED_ROUTES = 6


def build_integration_status(repo: Repository) -> dict[str, Any]:
    return {
        "status": "phase_6_productization_planning",
        "summary": (
            "Phase 6 local branch is ahead of the latest VPS-smoked package. "
            "Public, self-service, config delivery and write gates remain closed."
        ),
        "source_checkpoint": {
            "current_branch_head": CURRENT_STABLE_HEAD,
            "latest_vps_smoked_package_head": LATEST_VPS_SMOKED_PACKAGE_HEAD,
            "latest_vps_smoke_status": LATEST_VPS_SMOKE_STATUS,
            "package_status_for_branch_head": PACKAGE_STATUS_FOR_BRANCH_HEAD,
            "public_self_service_open": False,
            "vps_apply_enabled_default": False,
        },
        "api_baseline": {
            "status": "phase_6_planning_ready",
            "stable_head": CURRENT_STABLE_HEAD,
            "previous_stable_head": PREVIOUS_STABLE_HEAD,
            "api_web_baseline_head": API_WEB_BASELINE_HEAD,
            "integration_status_head": POST_DRY_RUN_READ_ONLY_HEAD,
            "allowed_scopes": list(ALLOWED_API_SCOPES),
            "write_routes_enabled": False,
            "public_api_exposed": False,
        },
        "remote_operation_gate": {
            "candidate_head": REMOTE_OPERATION_GATE_CANDIDATE_HEAD,
            "stable_merge_head": REMOTE_OPERATION_GATE_MERGE_HEAD,
            "phase_1": "dry_run_only_pass",
            "phase_2": "verified_live",
            "write_operations_enabled": False,
        },
        "controlled_prod_readiness": {
            "status": "operator_only_pilot_accepted",
            "decision": "operator-only-pilot-accepted",
            "runbook": "docs/ROUTE_AUTH_OPERATION_POLICY.ru.md",
            "source_overlay_head": LATEST_VPS_SMOKED_PACKAGE_HEAD,
            "vps_smoke_run_id": CONTROLLED_PROD_SMOKE_RUN_ID,
            "source_update_run_id": CONTROLLED_PROD_SOURCE_UPDATE_RUN_ID,
            "web_admin_access": "ssh_tunnel_loopback",
            "manual_web_check": "passed",
            "service_deployment": "active_on_disposable_test_vps",
            "api_listener": "absent_or_loopback_only",
            "vps_apply_enabled_default": False,
            "recovery_path": "known",
        },
        "local_read_only_extension": {
            "head": CURRENT_LOCAL_READ_ONLY_HEAD,
            "status": "local_only_not_vps_smoked",
            "vps_smoke_status": CURRENT_LOCAL_READ_ONLY_SMOKE_STATUS,
            "checked_routes": CURRENT_LOCAL_READ_ONLY_SMOKE_CHECKED_ROUTES,
            "workspace": "local_branch",
            "token_lifecycle": "revoked",
            "safe_routes": [
                "/api/local-agent/runtime/summary",
            ],
        },
        "capability_registry": build_capability_registry(),
        "aggregate_state": _load_aggregate_state(repo),
        "allowed_lanes": list(ALLOWED_LANES),
        "blocked_lanes": list(BLOCKED_LANES),
        "next_gate": "P6-I003 commercial/manual approval boundary",
    }


def build_capability_registry() -> dict[str, Any]:
    return {
        "status": "policy_registry_ready",
        "current_branch_head": CURRENT_STABLE_HEAD,
        "latest_vps_smoked_package_head": LATEST_VPS_SMOKED_PACKAGE_HEAD,
        "server_capabilities": [
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
        ],
        "future_protocols": [
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
        ],
    }


def _load_aggregate_state(repo: Repository) -> dict[str, int]:
    summary = repo.get_api_metrics_summary()
    return {
        "servers": summary["servers_total"],
        "users": summary["users_total"],
        "devices": summary["devices_total"],
    }
