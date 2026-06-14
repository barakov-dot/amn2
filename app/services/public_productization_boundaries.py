from __future__ import annotations

from typing import Any


def build_public_docs_api_taxonomy_boundary() -> dict[str, Any]:
    return {
        "status": "public_docs_api_taxonomy_ready",
        "publication_enabled": False,
        "public_docs_enabled": False,
        "public_openapi_enabled": False,
        "public_api_exposed": False,
        "requires_public_exposure_gate": "P6-C001 Public exposure gate",
        "taxonomy": {
            "public_safe": [
                "product_overview",
                "client_compatibility_guidance",
                "operator_only_status_summary",
                "support_intake_copy",
            ],
            "operator_only": [
                "web_admin",
                "api_integration_status",
                "api_metrics_summary",
                "api_users_summary",
                "local_agent_runtime_summary",
            ],
            "blocked_secret_bearing": [
                "config_delivery",
                "tokenized_config_links",
                "client_config_artifacts",
                "device_secret_recovery",
            ],
            "blocked_write": [
                "client_write_crud",
                "peer_apply_revoke",
                "backup_restore_import",
                "destructive_cleanup",
            ],
        },
        "allowed_public_fields": [
            "product_name",
            "client_platform_guidance",
            "aggregate_status_category",
            "support_contact_copy",
        ],
        "blocked_public_fields": [
            "per_user_state",
            "per_peer_state",
            "raw_runtime_output",
            "token_material",
            "operator_identity",
            "server_endpoint_detail",
        ],
        "docs": {
            "taxonomy_doc": "docs/PUBLIC_DOCS_API_TAXONOMY.ru.md",
        },
        "route_order_drift_guard": {
            "status": "route_order_guard_ready",
            "gate": "local-only/docs/tests",
            "public_openapi_publication_allowed": False,
            "deterministic_order_source": "surface_policy_registration_order",
            "required_checks": [
                "route_groups_match_taxonomy",
                "route_order_is_deterministic",
                "blocked_routes_stay_out_of_public_docs",
                "publication_flags_remain_false",
            ],
        },
    }


def build_public_config_gate_checklist() -> dict[str, Any]:
    return {
        "status": "public_config_gate_checklist_ready",
        "mode": "docs_only_checklist",
        "public_exposure_enabled": False,
        "config_delivery_enabled": False,
        "requires_public_gate": "P6-C001 Public exposure gate",
        "requires_config_gate": "P6-C002 Config delivery gate",
        "safe_default_work": [
            "checklist drafting",
            "threat model review",
            "client compatibility notes",
            "operator decision evidence",
        ],
        "public_exposure_preconditions": [
            "operator opens P6-C001 by name",
            "domain and listener plan reviewed",
            "TLS and firewall plan reviewed",
            "auth/session/rate-limit plan reviewed",
            "rollback and incident plan recorded",
            "external probe scope approved",
        ],
        "config_delivery_preconditions": [
            "operator opens P6-C002 by name",
            "token hash-at-rest model reviewed",
            "raw token return-once policy reviewed",
            "TTL and one-time-use policy reviewed",
            "audit redaction reviewed",
            "client import matrix reviewed",
        ],
        "blocked_without_gate": [
            "public listener exposure",
            "public OpenAPI publication",
            "short config-link issue",
            "public config-link redeem",
            "QR code output",
            "vpn_import_link output",
            "client .conf output",
            "Telegram live config send",
            "Local Agent config mutation",
        ],
        "safe_evidence_fields": [
            "gate_id",
            "decision",
            "operator",
            "timestamp",
            "approved_scope",
            "stop_conditions",
        ],
        "docs": {
            "checklist_doc": "docs/PUBLIC_CONFIG_GATE_CHECKLIST.ru.md",
        },
    }


def build_destructive_cleanup_gate_checklist() -> dict[str, Any]:
    return {
        "status": "destructive_cleanup_checklist_ready",
        "mode": "checklist_only",
        "target_reference": "operator_named_validation_vps",
        "destructive_execution_enabled": False,
        "cleanup_commands_enabled": False,
        "requires_named_gate": "P6-C007 Destructive cleanup/reinstall gate",
        "required_preconditions": [
            "operator opens P6-C007 by name",
            "retention and data-loss decision recorded",
            "latest AMN2 head and package choice recorded",
            "rollback or rebuild stop criteria recorded",
            "operator-local secret handoff ready",
            "second confirmation before any destructive action",
        ],
        "blocked_actions_without_gate": [
            "provider rebuild",
            "disk wipe",
            "service stop",
            "database deletion",
            "firewall/public listener change",
            "live cleanup command execution",
        ],
        "safe_default_work": [
            "checklist drafting",
            "dry-run package selection notes",
            "retention decision template",
            "stop criteria template",
            "secret handoff checklist",
        ],
        "docs": {
            "checklist_doc": "docs/DESTRUCTIVE_CLEANUP_GATE_CHECKLIST.ru.md",
        },
    }
