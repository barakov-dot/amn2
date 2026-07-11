from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from app.db.repositories import Repository
from app.services.fresh_install_wizard import (
    build_fresh_install_manifest,
    build_fresh_install_wizard_boundary,
)
from app.services.privacy_status_boundary import build_privacy_status_boundary
from app.services.productization_boundary import build_productization_boundary
from app.services.public_productization_boundaries import (
    build_destructive_cleanup_gate_checklist,
    build_public_docs_api_taxonomy_boundary,
)
from app.services.reconciliation_release_boundary import (
    build_reconciliation_release_boundary,
)
from app.services.telemetry_retention_policy import build_telemetry_retention_policy
from app.security.surface_policy import SURFACE_POLICIES
from app.vpn.client_compatibility import (
    CLIENT_COMPATIBILITY_MATRIX,
    CLIENT_COMPATIBILITY_WATCH,
    recommended_delivery_order,
)


ALLOWED_API_SCOPES = ("install:write", "metrics:read", "server:read")
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
    "payment processor integration without named gate",
    "automatic entitlement/config delivery on payment",
    "support/news bot runtime without separate token gate",
    "Telegram profile icon mutation without P6-I005 gate",
    "live health/status polling without P6-M002 gate",
    "per-peer or per-user analytics without P6-N002 gate",
    "attach-existing-server reconciliation apply without P6-M003 gate",
    "release/package/public launch without P6-S001 checklist gates",
    "raw telemetry export without P6-N004 retention/redaction gate",
    "upstream refresh live actions without P6-S002 incorporation gate",
    "short tokenized config links require P6-C002 live/config delivery gate",
    "automatic commercial entitlement activation without P6-I006/P6-C003 gates",
    "public docs/API publication without P6-C001 public exposure gate",
    "destructive cleanup/reinstall without P6-C007 named destructive gate",
    "systemd/reverse proxy deployment on validation VPS",
)


def _current_source_head() -> str:
    repo_root = Path(__file__).resolve().parents[2]
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "--short", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return result.stdout.strip() or "unknown"


CURRENT_STABLE_HEAD = _current_source_head()
PREVIOUS_STABLE_HEAD = "b3102db"
POST_DRY_RUN_READ_ONLY_HEAD = CURRENT_STABLE_HEAD
API_WEB_BASELINE_HEAD = CURRENT_STABLE_HEAD
REMOTE_OPERATION_GATE_MERGE_HEAD = "708c98e"
REMOTE_OPERATION_GATE_CANDIDATE_HEAD = "7281254"
LATEST_VPS_SMOKED_PACKAGE_HEAD = "b3102db"
LATEST_VPS_SMOKE_STATUS = "live_update_smoke_pass"
PACKAGE_STATUS_FOR_BRANCH_HEAD = "not_package_rebuilt_not_vps_smoked"
CONTROLLED_PROD_SMOKE_RUN_ID = "20260613T154826Z"
CONTROLLED_PROD_SOURCE_UPDATE_RUN_ID = "20260613T154511Z"
CURRENT_LOCAL_READ_ONLY_HEAD = CURRENT_STABLE_HEAD
CURRENT_LOCAL_READ_ONLY_SMOKE_STATUS = "not_run_for_branch_head"
CURRENT_LOCAL_READ_ONLY_SMOKE_CHECKED_ROUTES = 6


def build_integration_status(repo: Repository) -> dict[str, Any]:
    return {
        "status": "phase_6_productization_planning",
        "summary": (
            "Phase 6 local branch is ahead of the latest VPS-smoked package. "
            "Public, self-service, config delivery, payment and write gates remain closed."
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
            "status": "p7_scoped_write_contour_ready",
            "stable_head": CURRENT_STABLE_HEAD,
            "previous_stable_head": PREVIOUS_STABLE_HEAD,
            "api_web_baseline_head": API_WEB_BASELINE_HEAD,
            "integration_status_head": POST_DRY_RUN_READ_ONLY_HEAD,
            "allowed_scopes": list(ALLOWED_API_SCOPES),
            "write_routes_enabled": True,
            "write_route_count": 1,
            "write_route_boundary": "install-mutation-request-audit-only",
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
        "productization_boundary": build_productization_boundary(),
        "privacy_status_boundary": build_privacy_status_boundary(),
        "reconciliation_release_boundary": build_reconciliation_release_boundary(),
        "telemetry_retention_policy": build_telemetry_retention_policy(),
        "client_compatibility_boundary": build_client_compatibility_boundary(),
        "fresh_install_wizard_boundary": build_fresh_install_wizard_boundary(),
        "public_config_write_prerequisite_split": build_fresh_install_manifest()[
            "public_config_write_prerequisite_split"
        ],
        "public_exposure_readiness_design": build_fresh_install_manifest()[
            "public_exposure_readiness_design"
        ],
        "config_delivery_channel_readiness": (
            build_config_delivery_channel_readiness_api_boundary()
        ),
        "write_api_scope_decision": build_fresh_install_manifest()[
            "write_api_scope_decision"
        ],
        "backup_restore_import_readiness": build_fresh_install_manifest()[
            "backup_restore_import_readiness"
        ],
        "telegram_identity_readiness": build_fresh_install_manifest()[
            "telegram_identity_readiness"
        ],
        "api_docs_taxonomy_rc_drift_check": build_api_docs_taxonomy_rc_drift_check(),
        "public_docs_api_taxonomy_boundary": build_public_docs_api_taxonomy_boundary(),
        "destructive_cleanup_gate_checklist": build_destructive_cleanup_gate_checklist(),
        "aggregate_state": _load_aggregate_state(repo),
        "allowed_lanes": list(ALLOWED_LANES),
        "blocked_lanes": list(BLOCKED_LANES),
        "next_gate": (
            "Phase 6 default local-only queue empty; named gate required "
            "for live/public/destructive work"
        ),
    }


def build_client_compatibility_boundary() -> dict[str, Any]:
    return {
        "status": "client-compatibility-matrix-ready",
        "ios": {
            "primary_rf_path": CLIENT_COMPATIBILITY_MATRIX["defaultvpn_ios_ru"].label,
            "installed_legacy_path": CLIENT_COMPATIBILITY_MATRIX[
                "amneziawg_apple"
            ].label,
        },
        "android": {
            "supported_path": CLIENT_COMPATIBILITY_MATRIX["amneziawg_android"].label,
        },
        "fallback_order": recommended_delivery_order("defaultvpn_ios_ru"),
        "watch_refresh": dict(CLIENT_COMPATIBILITY_WATCH),
        "one_tap_copy": {
            "telegram_copy_text_limit": 256,
            "full_import_link_copy_when_too_long": False,
            "short_delivery_link_requires_gate": "P6-C002 Config delivery gate",
        },
        "live_client_import_verified": bool(
            CLIENT_COMPATIBILITY_WATCH["live_client_import_verified"]
        ),
    }


def build_config_delivery_channel_readiness_api_boundary() -> dict[str, Any]:
    readiness = dict(build_fresh_install_manifest()["config_delivery_channel_readiness"])
    safe_checklists: list[dict[str, Any]] = []
    for checklist in readiness["checklists"]:
        safe_checklist = dict(checklist)
        forbidden_evidence = safe_checklist.pop("forbidden_evidence", None)
        if forbidden_evidence is not None:
            safe_checklist["forbidden_evidence_count"] = len(forbidden_evidence)
            safe_checklist["evidence_policy"] = "names_redacted_from_api_status"
        safe_checklists.append(safe_checklist)
    readiness["checklists"] = safe_checklists
    return readiness


def build_api_docs_taxonomy_rc_drift_check() -> dict[str, Any]:
    implemented_api_routes = [
        policy
        for policy in SURFACE_POLICIES
        if policy.surface == "api" and policy.implementation_mode == "implemented"
    ]
    blocked_api_routes = [
        policy
        for policy in SURFACE_POLICIES
        if policy.surface == "api" and policy.implementation_mode == "blocked-future"
    ]
    return {
        "status": "taxonomy_rc_drift_check_ready",
        "mode": "local_only",
        "public_openapi_publication_allowed": False,
        "new_route_exposure_allowed": False,
        "write_route_enablement_allowed": False,
        "required_checks": [
            "surface_policy_route_order",
            "integration_status_safe_payload",
            "public_docs_publication_flags_disabled",
            "safe_metadata_marker_vocabulary",
        ],
        "surface_policy_counts": {
            "implemented_api_routes": len(implemented_api_routes),
            "blocked_future_api_routes": len(blocked_api_routes),
        },
        "safe_metadata_marker_guard": {
            "forbidden_marker_words_allowed": False,
            "error_mode": "field_or_category_only",
        },
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
        "multi_instance_conflict_model": {
            "status": "local_conflict_model_ready",
            "gate": "local-only/docs/tests",
            "live_multi_instance_apply_allowed": False,
            "write_api_required_before_apply": "P6-C003",
            "config_delivery_required_before_user_output": "P6-C002",
            "required_checks": [
                "unique_runtime_instance_id",
                "unique_listen_port_per_instance",
                "non_overlapping_vpn_cidr",
                "unique_interface_name",
                "endpoint_pair_review",
                "dns_ipv6_policy_review",
            ],
            "safe_outputs": [
                "conflict_report",
                "operator_notes",
                "blocked_gate_summary",
            ],
            "blocked_outputs": [
                "runtime_config_write",
                "firewall_change",
                "peer_migration",
                "config_delivery",
                "service_restart",
            ],
        },
    }


def _load_aggregate_state(repo: Repository) -> dict[str, int]:
    summary = repo.get_api_metrics_summary()
    return {
        "servers": summary["servers_total"],
        "users": summary["users_total"],
        "devices": summary["devices_total"],
    }
