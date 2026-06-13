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
