from __future__ import annotations

from collections.abc import Callable
from typing import Any


QUESTION_SCHEMA_VERSION = "fresh-install-questions.v1"
ANSWER_SCHEMA_VERSION = "fresh-install-answers.v1"
PLAN_SCHEMA_VERSION = "fresh-install-plan.v1"
READINESS_SCHEMA_VERSION = "fresh-install-readiness.v1"
EVIDENCE_SCHEMA_VERSION = "fresh-install-evidence.v1"
PACKAGE_PREFLIGHT_SCHEMA_VERSION = "fresh-install-package-preflight.v1"
RC_ACCEPTANCE_SCHEMA_VERSION = "clean-installer-rc-acceptance.v1"
PUBLIC_CONFIG_WRITE_SPLIT_SCHEMA_VERSION = "public-config-write-prerequisite-split.v1"
PUBLIC_EXPOSURE_READINESS_SCHEMA_VERSION = "public-exposure-readiness-design.v1"
CONFIG_DELIVERY_CHANNEL_READINESS_SCHEMA_VERSION = (
    "config-delivery-channel-readiness.v1"
)
WRITE_API_SCOPE_DECISION_SCHEMA_VERSION = "write-api-scope-decision.v1"
BACKUP_RESTORE_IMPORT_READINESS_SCHEMA_VERSION = (
    "backup-restore-import-prerequisite-checklist.v1"
)
TELEGRAM_IDENTITY_READINESS_SCHEMA_VERSION = (
    "telegram-identity-profile-media-prerequisite-checklist.v1"
)
SECRET_HANDOFF_POLICY_DOC = "docs/AMN2_SECRET_HANDOFF_PROTOCOL.ru.md"
FRESH_INSTALLER_OPERATOR_INDEX_DOC = "docs/FRESH_INSTALLER_OPERATOR_INDEX.ru.md"
MULTI_INSTANCE_IPAM_MODEL_DOC = "docs/MULTI_INSTANCE_IPAM_CONFLICT_MODEL.ru.md"
CURRENT_PACKAGE_PREFLIGHT_HEAD = "b121865"
LATEST_VPS_SMOKED_PACKAGE_HEAD = "b121865"
CURRENT_SOURCE_ZIP_SHA256 = "D0FB561D5A12C3B2C095521C3B44923B001F49C8E94CA5C13DB1E811ABB17647"

DEFAULT_FRESH_INSTALL_ANSWERS: dict[str, str] = {
    "project_name": "AMN2",
    "server_name": "local",
    "runtime": "docker",
    "vpn_protocol": "amneziawg",
    "public_exposure": "no",
    "config_delivery": "no",
    "write_api": "no",
    "destructive_cleanup": "no",
    "telegram_bot": "operator_local",
    "secret_handoff": "operator_local",
}

_QUESTION_FIELDS: tuple[dict[str, Any], ...] = (
    {
        "key": "project_name",
        "prompt": "Название проекта",
        "required": True,
        "allowed_values": None,
        "gate": None,
    },
    {
        "key": "server_name",
        "prompt": "Имя сервера",
        "required": True,
        "allowed_values": None,
        "gate": None,
    },
    {
        "key": "runtime",
        "prompt": "Режим запуска: docker или host_systemd",
        "required": True,
        "allowed_values": ["docker", "host_systemd"],
        "gate": None,
    },
    {
        "key": "vpn_protocol",
        "prompt": "VPN-протокол",
        "required": True,
        "allowed_values": ["amneziawg", "wireguard", "xray"],
        "gate": None,
    },
    {
        "key": "public_exposure",
        "prompt": "Открывать публичный доступ сейчас (yes/no)",
        "required": True,
        "allowed_values": ["no", "yes"],
        "gate": "P7-C002",
    },
    {
        "key": "config_delivery",
        "prompt": "Включать выдачу реальных конфигов сейчас (yes/no)",
        "required": True,
        "allowed_values": ["no", "yes"],
        "gate": "P7-C003",
    },
    {
        "key": "write_api",
        "prompt": "Включать write API для установки сейчас (yes/no)",
        "required": True,
        "allowed_values": ["no", "yes"],
        "gate": "P7-C005",
    },
    {
        "key": "destructive_cleanup",
        "prompt": "Запускать очистку или переустановку сейчас (yes/no)",
        "required": True,
        "allowed_values": ["no", "yes"],
        "gate": "P7-C004",
    },
    {
        "key": "telegram_bot",
        "prompt": "Режим Telegram-бота",
        "required": True,
        "allowed_values": ["not_configured", "operator_local"],
        "gate": None,
    },
    {
        "key": "secret_handoff",
        "prompt": "Режим передачи секретов",
        "required": True,
        "allowed_values": ["not_configured", "operator_local"],
        "gate": None,
    },
)

QUESTION_PROMPTS: tuple[tuple[str, str], ...] = tuple(
    (str(field["key"]), str(field["prompt"])) for field in _QUESTION_FIELDS
)

_ALLOWED_VALUES: dict[str, set[str]] = {
    "runtime": {"docker", "host_systemd"},
    "vpn_protocol": {"amneziawg", "wireguard", "xray"},
    "public_exposure": {"yes", "no"},
    "config_delivery": {"yes", "no"},
    "write_api": {"yes", "no"},
    "destructive_cleanup": {"yes", "no"},
    "telegram_bot": {"operator_local", "not_configured"},
    "secret_handoff": {"operator_local", "not_configured"},
}

_STOP_LINES: tuple[tuple[str, str, str], ...] = (
    ("public_exposure", "P7-C002", "P7-C002 required before public exposure"),
    ("config_delivery", "P7-C003", "P7-C003 required before config delivery"),
    ("write_api", "P7-C005", "P7-C005 required before write API"),
    (
        "destructive_cleanup",
        "P7-C004",
        "P7-C004 required before destructive cleanup/reinstall",
    ),
)

_FORBIDDEN_IN_PLAN: list[str] = [
    ".env",
    "servers.yml",
    "telegram_bot_token",
    "web_admin_password",
    "session_secret",
    "client_config",
    "qr_payload",
    "vpn://",
]

_SECRET_INPUT_MARKERS = (
    ".env",
    ".conf",
    "servers.yml",
    "telegram_bot_token",
    "web_admin_password",
    "session_secret",
    "client_config",
    "qr_payload",
    "vpn://",
    "PrivateKey",
    "PresharedKey",
    "Authorization",
    "token_hash",
)

_LOCAL_DRY_RUN_STEPS = [
    "python -m app.toolchain check",
    "python -m app.cli install plan --answers fresh-install-answers.json --pretty",
    "python -m app.cli server retest-plan --config servers.yml --server local --db data/amneziya.sqlite3",
]

_BLOCKED_WITHOUT_NAMED_GATE = [
    "live VPS commands",
    "SSH commands",
    "package apply/rebuild on VPS",
    "service restart/deploy",
    "public listener/domain/reverse proxy",
    "real config delivery",
    "write API",
    "Local Agent mutation",
    "backup/restore/import apply",
    "production peer/user mutation",
    "destructive cleanup/reinstall",
    "Telegram identity mutation",
]

_SAFETY_BOUNDARY = {
    "live_vps_commands_enabled": False,
    "ssh_commands_enabled": False,
    "package_apply_enabled": False,
    "service_restart_enabled": False,
    "public_exposure_enabled": False,
    "config_delivery_enabled": False,
    "write_api_enabled": False,
    "local_agent_mutation_enabled": False,
    "backup_restore_import_enabled": False,
    "production_peer_user_mutation_enabled": False,
    "destructive_cleanup_enabled": False,
    "telegram_identity_mutation_enabled": False,
    "vps_apply_enabled_default": False,
}

_TARGET_PREFLIGHT_CHECKS: list[dict[str, Any]] = [
    {
        "id": "os-release",
        "label": "Target OS release",
        "read_only": True,
        "expected": ["Ubuntu LTS", "Debian stable"],
    },
    {
        "id": "python-runtime",
        "label": "CPython runtime",
        "read_only": True,
        "expected": ["CPython 3.12.x"],
    },
    {
        "id": "docker-runtime",
        "label": "Docker runtime availability",
        "read_only": True,
        "expected": ["docker present when runtime=docker"],
    },
    {
        "id": "network-ports",
        "label": "Required listener and VPN ports",
        "read_only": True,
        "expected": ["operator-selected ports only"],
    },
    {
        "id": "disk-space",
        "label": "Disk capacity for source, data and logs",
        "read_only": True,
        "expected": ["enough free space before package apply"],
    },
    {
        "id": "time-sync",
        "label": "System clock synchronization",
        "read_only": True,
        "expected": ["time sync active"],
    },
    {
        "id": "package-tools",
        "label": "Package and archive tools",
        "read_only": True,
        "expected": ["shell, unzip, sha256 tooling available"],
    },
]

_PACKAGE_HYGIENE_REQUIRED_CHECKS = [
    "toolchain_check",
    "full_pytest",
    "git_diff_check",
    "source_zip_checksum",
    "forbidden_source_entries",
    "shell_lf_no_bom",
    "markdown_hygiene",
    "commit_binding",
]

_CURRENT_HEAD_PACKAGE_PREFLIGHT_REQUIRED_CHECKS = [
    "toolchain_check",
    "full_pytest",
    "git_diff_check",
    "source_zip_checksum_plan",
    "forbidden_source_entries_plan",
    "shell_lf_no_bom_plan",
    "markdown_hygiene",
    "commit_binding",
    "named_live_gate_checklist",
    "asset_path_preflight",
]

_ASSET_PATH_PREFLIGHT_REQUIRED_CHECKS = [
    "operator_kit_required_files_exist",
    "operator_runbook_paths_resolve",
    "package_manifest_paths_match_archive",
    "source_zip_paths_match_manifest",
    "no_secret_material_in_asset_manifest",
    "package_local_helper_defaults_match_commit",
]

_RC_ACCEPTANCE_SECTIONS = [
    "answers",
    "target_preflight",
    "package_preflight",
    "smoke_evidence",
    "secret_handoff",
    "rollback",
    "stop_lines",
]

_RC_REQUIRED_EVIDENCE = [
    "rendered_plan_secret_free",
    "package_sha256_recorded",
    "source_sha256_recorded",
    "operator_runbook_paths_verified",
    "helper_default_bindings_verified",
    "known_good_baseline_preserved",
    "multi_instance_ipam_conflict_model_reviewed",
]

_MULTI_INSTANCE_IPAM_REQUIRED_CHECKS = [
    "unique_runtime_instance_id",
    "unique_listen_port_per_instance",
    "non_overlapping_vpn_cidr",
    "unique_interface_name",
    "endpoint_pair_review",
    "dns_ipv6_policy_review",
]

_MULTI_INSTANCE_IPAM_SAFE_OUTPUTS = [
    "conflict_report",
    "operator_notes",
    "blocked_gate_summary",
]

_MULTI_INSTANCE_IPAM_BLOCKED_OUTPUTS = [
    "runtime_config_write",
    "firewall_change",
    "peer_migration",
    "config_delivery",
    "service_restart",
]

_SMOKE_EVIDENCE_REQUIRED_SECTIONS = [
    "selected_commit",
    "loopback_http_codes",
    "auth_scope_status",
    "listener_summary",
    "audit_summary",
    "external_closed_probe_status",
    "forbidden_marker_result",
    "final_verdict",
]

_RECONCILIATION_ALLOWED_INPUTS = [
    "server_inventory_summary",
    "read_only_peer_counts",
    "runtime_mode_observation",
    "operator_notes",
]

_RECONCILIATION_BLOCKED_OUTPUTS = [
    "auto_fix",
    "peer_import",
    "config_overwrite",
    "peer_creation",
    "peer_removal",
]

_PUBLIC_CONFIG_WRITE_OBSERVED_BLOCKERS = [
    "web_loopback_only",
    "external_public_probes_closed",
    "web_admin_username_missing",
    "smtp_config_missing",
    "vps_apply_enabled_false",
    "local_agent_disabled",
    "write_api_route_count_zero",
]

_PUBLIC_CONFIG_WRITE_BLOCKED_ACTIONS = [
    "public_listener_change",
    "domain_tls_reverse_proxy_apply",
    "config_artifact_output",
    "write_api_route_enablement",
    "vps_apply_enabled_true",
    "local_agent_mutation",
    "live_peer_user_mutation",
]

_PUBLIC_CONFIG_WRITE_READINESS_TRACKS: list[dict[str, Any]] = [
    {
        "id": "public-exposure-readiness",
        "gate": "P7-C002",
        "status": "blocked",
        "required_decisions": [
            "admin_credential_contract",
            "domain_tls_reverse_proxy_plan",
            "firewall_listener_plan",
            "public_probe_matrix",
            "rollback_to_loopback",
        ],
        "live_enable_allowed": False,
    },
    {
        "id": "config-delivery-channel-readiness",
        "gate": "P7-C003",
        "status": "blocked",
        "required_decisions": [
            "smtp_or_operator_local_channel",
            "secret_safe_evidence_protocol",
            "client_import_matrix",
            "one_time_delivery_policy",
            "delivery_revocation_story",
        ],
        "live_enable_allowed": False,
    },
    {
        "id": "write-api-scope-decision",
        "gate": "P7-C005",
        "status": "blocked",
        "decision_options": [
            "keep_public_api_read_only_for_rc",
            "add_separate_write_api_implementation_slice",
            "operator_only_web_write_window",
        ],
        "required_decisions": [
            "route_scope_inventory",
            "mutation_idempotency_policy",
            "audit_redaction_contract",
            "vps_apply_enabled_window",
            "rollback_or_reconcile_plan",
        ],
        "live_enable_allowed": False,
    },
]

_PUBLIC_EXPOSURE_READINESS_CHECKLISTS: list[dict[str, Any]] = [
    {
        "id": "admin-credential-contract",
        "status": "required_before_apply",
        "required": [
            "WEB_ADMIN_USERNAME present",
            "WEB_ADMIN_PASSWORD_HASH present",
            "APP_SECRET_KEY present",
            "no raw credential value in evidence",
        ],
        "safe_evidence": [
            "presence_only",
            "boolean_flags_only",
            "no_hash_or_secret_value",
        ],
    },
    {
        "id": "domain-tls-reverse-proxy-plan",
        "status": "required_before_apply",
        "requires_operator_inputs": [
            "domain_name",
            "tls_mode",
            "reverse_proxy_kind",
        ],
        "allowed_proxy_targets": [
            "127.0.0.1:3030",
        ],
        "blocked_proxy_targets": [
            "127.0.0.1:3040",
            "0.0.0.0:3040",
        ],
    },
    {
        "id": "firewall-listener-plan",
        "status": "required_before_apply",
        "backend_listener": "127.0.0.1:3030",
        "blocked_direct_listeners": [
            "0.0.0.0:3030",
            "0.0.0.0:3040",
        ],
        "allowed_public_ports_after_apply": [
            "80",
            "443",
        ],
    },
    {
        "id": "external-probe-matrix",
        "status": "required_before_apply",
        "expected_before_apply": {
            "3030": "closed",
            "3040": "closed",
            "80": "closed_or_proxy_planned",
            "443": "closed_or_proxy_planned",
        },
        "expected_after_apply": {
            "3030": "closed",
            "3040": "closed",
            "80": "redirect_or_challenge",
            "443": "login_or_auth_challenge",
        },
    },
    {
        "id": "rollback-to-loopback",
        "status": "required_before_apply",
        "rollback_goal": "web_loopback_only",
        "required_checks": [
            "disable_public_proxy",
            "restore_firewall_closed_3030_3040",
            "verify_loopback_login_200",
            "verify_external_3030_3040_closed",
        ],
    },
]

_PUBLIC_EXPOSURE_BLOCKED_ACTIONS = [
    "public_listener_change",
    "firewall_apply",
    "reverse_proxy_apply",
    "tls_certificate_issue",
    "public_openapi_publication",
    "direct_public_api_3040",
]

_CONFIG_DELIVERY_CHANNEL_CHECKLISTS: list[dict[str, Any]] = [
    {
        "id": "delivery-channel-decision",
        "status": "required_before_apply",
        "allowed_channels": ["smtp_email", "operator_local"],
        "requires_operator_inputs": [
            "selected_channel",
            "recipient_identity_policy",
            "fallback_channel",
        ],
    },
    {
        "id": "secret-safe-evidence-protocol",
        "status": "required_before_apply",
        "forbidden_evidence": [
            "client_config_body",
            "qr_payload",
            "vpn_import_uri",
            "private_key",
            "preshared_key",
            "smtp_secret",
        ],
        "safe_evidence": [
            "delivery_status_code",
            "artifact_type_counts",
            "redacted_audit_summary",
        ],
    },
    {
        "id": "client-import-matrix",
        "status": "required_before_apply",
        "required_artifacts": [
            "conf_file",
            "vpn_import_link",
            "qr_vpn_import_link",
        ],
        "compatibility_notes": [
            "conf_file_primary",
            "vpn_import_link_copyable",
            "qr_not_universal",
        ],
    },
    {
        "id": "one-time-delivery-policy",
        "status": "required_before_apply",
        "required_properties": [
            "single_use",
            "short_ttl",
            "purpose_bound",
            "audit_redacted",
        ],
        "blocked_defaults": [
            "long_lived_public_link",
            "reusable_token",
            "secret_in_logs",
        ],
    },
    {
        "id": "delivery-revocation-story",
        "status": "required_before_apply",
        "required_steps": [
            "disable_delivery_channel",
            "revoke_or_expire_delivery_token",
            "record_safe_revocation_summary",
        ],
        "rollback_goal": "no_active_public_config_delivery",
    },
]

_CONFIG_DELIVERY_BLOCKED_ACTIONS = [
    "config_artifact_output",
    "smtp_send",
    "telegram_config_send",
    "public_config_link_issue",
    "public_config_link_redeem",
    "qr_generation_for_delivery",
]

_WRITE_API_DECISION_OPTIONS: list[dict[str, Any]] = [
    {
        "id": "keep-public-api-read-only-for-rc",
        "selected": True,
        "status": "selected_for_rc",
        "write_routes_enabled": False,
        "requires_new_named_gate": None,
        "notes": [
            "preserve existing read-only API scope model",
            "use loopback/operator web surfaces for manual RC validation",
        ],
    },
    {
        "id": "separate-write-api-implementation-slice",
        "selected": False,
        "status": "deferred",
        "write_routes_enabled": False,
        "requires_new_named_gate": "P7-C005",
        "required_scope_decisions": [
            "route_allowlist",
            "write_auth_scopes",
            "idempotency_model",
            "audit_redaction_model",
            "rollback_or_compensating_action",
        ],
    },
    {
        "id": "operator-only-web-write-window",
        "selected": False,
        "status": "deferred",
        "write_routes_enabled": False,
        "requires_new_named_gate": "P7-C005",
        "required_scope_decisions": [
            "loopback_access_window",
            "operator_confirmation_copy",
            "post_window_relock_check",
        ],
    },
]

_WRITE_API_REQUIRED_BEFORE_ANY_WRITE = [
    "route_inventory_still_zero_or_explicitly_scoped",
    "auth_scope_model_for_write",
    "idempotency_and_audit_contract",
    "rollback_or_compensating_action_story",
    "operator_confirmation_boundary",
    "safe_evidence_no_secret_or_peer_material",
]

_WRITE_API_BLOCKED_ACTIONS = [
    "write_api_route_enablement",
    "api_clients_crud",
    "install_mutation_route",
    "local_agent_mutation",
    "vps_apply_enabled_true",
    "production_peer_user_mutation",
    "server_config_rewrite",
]

_BACKUP_RESTORE_IMPORT_CHECKLISTS: list[dict[str, Any]] = [
    {
        "id": "backup-scope-decision",
        "status": "required_before_apply",
        "required_decisions": [
            "source_state_scope",
            "artifact_inventory",
            "operator_retention_choice",
        ],
        "safe_outputs": [
            "aggregate_state_scope",
            "artifact_type_counts",
            "retention_label",
        ],
    },
    {
        "id": "encryption-and-retention-policy",
        "status": "required_before_apply",
        "required_properties": [
            "encrypted_at_rest",
            "operator_local_secret_handoff",
            "retention_window_declared",
            "safe_evidence_only",
        ],
        "blocked_defaults": [
            "plain_archive",
            "unbounded_retention",
            "secret_value_in_evidence",
        ],
    },
    {
        "id": "restore-preview-safety",
        "status": "required_before_apply",
        "required_steps": [
            "restore_preview_only",
            "target_isolation_confirmed",
            "no_overwrite_without_named_gate",
        ],
        "apply_allowed": False,
    },
    {
        "id": "import-source-validation",
        "status": "required_before_apply",
        "required_checks": [
            "source_integrity_check",
            "schema_version_check",
            "operator_ownership_check",
            "safe_manifest_only",
        ],
        "import_apply_allowed": False,
    },
    {
        "id": "disaster-recovery-drill-plan",
        "status": "required_before_apply",
        "required_steps": [
            "drill_scope_declared",
            "rollback_stop_line_declared",
            "post_drill_relock_check",
        ],
        "reboot_allowed": False,
    },
]

_BACKUP_RESTORE_IMPORT_BLOCKED_ACTIONS = [
    "backup_archive_create",
    "restore_apply",
    "archive_import_apply",
    "reboot",
    "destructive_migration",
    "remote_backup_download",
]

_TELEGRAM_IDENTITY_CHECKLISTS: list[dict[str, Any]] = [
    {
        "id": "telegram-identity-scope-decision",
        "status": "required_before_apply",
        "required_decisions": [
            "bot_identity_target",
            "allowed_profile_fields",
            "operator_approval_window",
        ],
        "safe_outputs": [
            "target_label",
            "field_allowlist",
            "approval_window_label",
        ],
    },
    {
        "id": "credential-handoff-and-storage-policy",
        "status": "required_before_apply",
        "required_properties": [
            "operator_local_secret_handoff",
            "no_token_in_evidence",
            "no_token_in_rendered_plan",
            "credential_rotation_story",
        ],
        "blocked_defaults": [
            "token_in_file",
            "token_in_log",
            "token_in_status_payload",
        ],
    },
    {
        "id": "profile-media-asset-plan",
        "status": "required_before_apply",
        "required_artifacts": [
            "profile_display_name_plan",
            "profile_description_plan",
            "profile_media_asset_reference",
        ],
        "live_upload_allowed": False,
    },
    {
        "id": "operator-preview-and-rollback",
        "status": "required_before_apply",
        "required_steps": [
            "operator_preview_only",
            "before_after_summary_plan",
            "rollback_or_revert_story",
        ],
        "profile_apply_allowed": False,
    },
    {
        "id": "post-mutation-relock-audit",
        "status": "required_before_apply",
        "required_steps": [
            "disable_token_access_after_window",
            "record_safe_audit_summary",
            "verify_no_live_send_needed",
        ],
        "live_bot_send_allowed": False,
    },
]

_TELEGRAM_IDENTITY_BLOCKED_ACTIONS = [
    "telegram_token_use",
    "live_bot_send",
    "profile_name_mutation",
    "profile_description_mutation",
    "profile_photo_mutation",
    "media_upload",
]


def build_fresh_install_manifest() -> dict[str, Any]:
    return {
        "status": "fresh_install_manifest_ready",
        "mode": "local_only_dry_run",
        "question_schema": _build_question_schema(),
        "installer_readiness": _build_installer_readiness(
            DEFAULT_FRESH_INSTALL_ANSWERS
        ),
        "installer_evidence": _build_installer_evidence(),
        "current_head_package_preflight": _build_current_head_package_preflight(),
        "clean_installer_rc_acceptance": _build_rc_acceptance_checklist(),
        "multi_instance_ipam_rc_decision": _build_multi_instance_ipam_rc_decision(),
        "public_config_write_prerequisite_split": (
            _build_public_config_write_prerequisite_split()
        ),
        "public_exposure_readiness_design": _build_public_exposure_readiness_design(),
        "config_delivery_channel_readiness": (
            _build_config_delivery_channel_readiness()
        ),
        "write_api_scope_decision": _build_write_api_scope_decision(),
        "backup_restore_import_readiness": (
            _build_backup_restore_import_readiness()
        ),
        "telegram_identity_readiness": _build_telegram_identity_readiness(),
        "secret_input_contract": _build_secret_input_contract(),
        "secret_handoff_policy": {
            "policy_doc": SECRET_HANDOFF_POLICY_DOC,
            "mode": DEFAULT_FRESH_INSTALL_ANSWERS["secret_handoff"],
            "raw_secret_allowed_in_plan": False,
            "operator_local_channel_required": True,
            "forbidden_in_plan": _FORBIDDEN_IN_PLAN,
        },
        "docs": {
            "runbook": "docs/FRESH_INSTALL_WIZARD.ru.md",
            "secret_handoff": SECRET_HANDOFF_POLICY_DOC,
        },
    }


def collect_fresh_install_answers(
    *,
    input_fn: Callable[[str], str] = input,
) -> dict[str, str]:
    answers: dict[str, str] = {}
    for key, label in QUESTION_PROMPTS:
        default = DEFAULT_FRESH_INSTALL_ANSWERS[key]
        raw = input_fn(f"{label} [{default}]: ").strip()
        answers[key] = raw or default
    return answers


def build_fresh_install_plan(answers: dict[str, str]) -> dict[str, Any]:
    normalized = _normalize_answers(answers)
    stop_lines = [
        message
        for key, _gate, message in _STOP_LINES
        if normalized.get(key) == "yes"
    ]
    required_gates = [
        gate for key, gate, _message in _STOP_LINES if normalized.get(key) == "yes"
    ]
    return {
        "schema_version": PLAN_SCHEMA_VERSION,
        "status": "blocked_named_gate_required"
        if stop_lines
        else "fresh_install_wizard_ready",
        "mode": "local_only_dry_run",
        "question_schema": _build_question_schema(),
        "operator_inputs": normalized,
        "safety": dict(_SAFETY_BOUNDARY),
        "secret_handoff": {
            "policy_doc": SECRET_HANDOFF_POLICY_DOC,
            "mode": normalized["secret_handoff"],
            "raw_secret_allowed_in_plan": False,
            "operator_local_channel_required": normalized["secret_handoff"]
            == "operator_local",
        },
        "installer_readiness": _build_installer_readiness(normalized),
        "installer_evidence": _build_installer_evidence(),
        "current_head_package_preflight": _build_current_head_package_preflight(),
        "clean_installer_rc_acceptance": _build_rc_acceptance_checklist(),
        "multi_instance_ipam_rc_decision": _build_multi_instance_ipam_rc_decision(),
        "secret_input_contract": _build_secret_input_contract(),
        "rendered_plan": _build_rendered_plan(normalized, required_gates, stop_lines),
        "stop_lines": stop_lines,
        "local_dry_run_steps": list(_LOCAL_DRY_RUN_STEPS),
        "generated_artifacts": [
            "fresh-install-answers.json",
            "fresh-install-plan.json",
            "operator-secret-checklist.md",
        ],
        "blocked_without_named_gate": list(_BLOCKED_WITHOUT_NAMED_GATE),
        "docs": {
            "runbook": "docs/FRESH_INSTALL_WIZARD.ru.md",
            "secret_handoff": SECRET_HANDOFF_POLICY_DOC,
            "operator_index": FRESH_INSTALLER_OPERATOR_INDEX_DOC,
        },
    }


def build_fresh_install_wizard_boundary() -> dict[str, Any]:
    return build_fresh_install_plan(DEFAULT_FRESH_INSTALL_ANSWERS)


def _normalize_answers(answers: dict[str, str]) -> dict[str, str]:
    normalized = DEFAULT_FRESH_INSTALL_ANSWERS | {
        key: str(value).strip()
        for key, value in answers.items()
        if value is not None
    }
    for key in ("project_name", "server_name"):
        if not normalized[key]:
            raise ValueError(f"{key} cannot be blank")
    for key, value in normalized.items():
        if _contains_secret_marker(value):
            raise ValueError(f"secret-bearing installer input is not allowed: {key}")
    for key, allowed in _ALLOWED_VALUES.items():
        value = normalized[key]
        if value not in allowed:
            raise ValueError(f"invalid {key}: {value}")
    return normalized


def _build_question_schema() -> dict[str, Any]:
    fields: list[dict[str, Any]] = []
    for field in _QUESTION_FIELDS:
        key = str(field["key"])
        fields.append(
            {
                "key": key,
                "prompt": field["prompt"],
                "default": DEFAULT_FRESH_INSTALL_ANSWERS[key],
                "required": field["required"],
                "allowed_values": field["allowed_values"],
                "gate": field["gate"],
            }
        )
    return {
        "version": QUESTION_SCHEMA_VERSION,
        "answer_schema_version": ANSWER_SCHEMA_VERSION,
        "fields": fields,
    }


def _build_rendered_plan(
    normalized: dict[str, str],
    required_gates: list[str],
    stop_lines: list[str],
) -> dict[str, Any]:
    return {
        "title": "AMN2 fresh install local dry-run plan",
        "target": {
            "project_name": normalized["project_name"],
            "server_name": normalized["server_name"],
            "runtime": normalized["runtime"],
            "vpn_protocol": normalized["vpn_protocol"],
        },
        "requires_named_gates": required_gates,
        "phases": [
            {
                "id": "local-preflight",
                "status": "local_only",
                "actions": list(_LOCAL_DRY_RUN_STEPS),
            },
            {
                "id": "secret-handoff-checklist",
                "status": "operator_local_only",
                "policy_doc": SECRET_HANDOFF_POLICY_DOC,
                "raw_secret_allowed_in_plan": False,
            },
            {
                "id": "target-preflight-matrix",
                "status": "local_plan_only",
                "checks": _build_target_preflight()["checks"],
                "live_execution": "blocked_without_named_gate",
            },
            {
                "id": "runtime-mode-decision",
                "status": "local_plan_only",
                **_build_runtime_decision(normalized),
            },
            {
                "id": "package-hygiene-checklist",
                "status": "local_plan_only",
                "package_rebuild_allowed": False,
                "required_checks": list(_PACKAGE_HYGIENE_REQUIRED_CHECKS),
                "do_not_rewrite_vps_smoked_evidence": True,
            },
            {
                "id": "current-head-package-preflight",
                "status": "local_plan_only",
                "target_head": CURRENT_PACKAGE_PREFLIGHT_HEAD,
                "latest_vps_smoked_head": LATEST_VPS_SMOKED_PACKAGE_HEAD,
                "package_build_allowed": False,
                "live_apply_allowed": False,
                "live_smoke_allowed": False,
                "required_checks": list(_CURRENT_HEAD_PACKAGE_PREFLIGHT_REQUIRED_CHECKS),
            },
            {
                "id": "package-asset-path-preflight",
                "status": "local_plan_only",
                "gate": "package/preflight only",
                "live_apply_allowed": False,
                "required_checks": list(_ASSET_PATH_PREFLIGHT_REQUIRED_CHECKS),
            },
            {
                "id": "clean-installer-rc-acceptance",
                "status": "local_only",
                "live_apply_allowed": False,
                "acceptance_sections": list(_RC_ACCEPTANCE_SECTIONS),
                "required_evidence": list(_RC_REQUIRED_EVIDENCE),
            },
            {
                "id": "multi-instance-ipam-rc-decision",
                **_build_multi_instance_ipam_rc_decision(),
                "status": "local_plan_only",
            },
            {
                "id": "public-config-write-prerequisite-split",
                **_build_public_config_write_prerequisite_split(),
            },
            {
                "id": "public-exposure-readiness-design",
                **_build_public_exposure_readiness_design(),
            },
            {
                "id": "config-delivery-channel-readiness",
                **_build_config_delivery_channel_readiness_plan_view(),
            },
            {
                "id": "write-api-scope-decision",
                **_build_write_api_scope_decision(),
            },
            {
                "id": "backup-restore-import-readiness",
                **_build_backup_restore_import_readiness(),
            },
            {
                "id": "telegram-identity-readiness",
                **_build_telegram_identity_readiness(),
            },
            {
                "id": "secret-input-contract",
                "status": "local_only_security",
                "raw_secret_input_allowed": False,
                "blocks_fields": list(DEFAULT_FRESH_INSTALL_ANSWERS),
                "safe_error_mode": "field_only_no_value_echo",
            },
            {
                "id": "smoke-evidence-template",
                "status": "local_template_only",
                "secret_payload_allowed": False,
                "required_sections": list(_SMOKE_EVIDENCE_REQUIRED_SECTIONS),
            },
            {
                "id": "existing-server-reconciliation-input",
                "status": "local_template_only",
                "mode": "report_only",
                "apply_allowed": False,
                "allowed_inputs": list(_RECONCILIATION_ALLOWED_INPUTS),
                "blocked_outputs": list(_RECONCILIATION_BLOCKED_OUTPUTS),
            },
            {
                "id": "installer-docs-index",
                "status": "local_docs_only",
                "path": FRESH_INSTALLER_OPERATOR_INDEX_DOC,
            },
            {
                "id": "question-answer-render",
                "status": "local_only",
                "answer_schema_version": ANSWER_SCHEMA_VERSION,
            },
            {
                "id": "named-gate-stop",
                "status": "blocked_until_named_gate"
                if required_gates
                else "no_live_gate_requested",
                "stop_lines": stop_lines,
            },
        ],
    }


def _build_installer_readiness(normalized: dict[str, str]) -> dict[str, Any]:
    return {
        "schema_version": READINESS_SCHEMA_VERSION,
        "target_preflight": _build_target_preflight(),
        "runtime_decision": _build_runtime_decision(normalized),
        "package_hygiene": {
            "package_rebuild_allowed_by_default": False,
            "do_not_rewrite_vps_smoked_evidence": True,
            "required_checks": list(_PACKAGE_HYGIENE_REQUIRED_CHECKS),
        },
    }


def _build_installer_evidence() -> dict[str, Any]:
    return {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "smoke_evidence_template": {
            "mode": "local_template_only",
            "live_smoke_allowed_by_default": False,
            "secret_payload_allowed": False,
            "required_sections": list(_SMOKE_EVIDENCE_REQUIRED_SECTIONS),
        },
        "existing_server_reconciliation_input": {
            "mode": "report_only",
            "apply_allowed_by_default": False,
            "allowed_inputs": list(_RECONCILIATION_ALLOWED_INPUTS),
            "blocked_outputs": list(_RECONCILIATION_BLOCKED_OUTPUTS),
        },
        "docs_index": {
            "path": FRESH_INSTALLER_OPERATOR_INDEX_DOC,
            "status": "local_docs_only",
        },
    }


def _build_current_head_package_preflight() -> dict[str, Any]:
    return {
        "schema_version": PACKAGE_PREFLIGHT_SCHEMA_VERSION,
        "mode": "local_plan_only",
        "target_head": CURRENT_PACKAGE_PREFLIGHT_HEAD,
        "latest_vps_smoked_head": LATEST_VPS_SMOKED_PACKAGE_HEAD,
        "package_build_allowed_by_default": False,
        "live_apply_allowed_by_default": False,
        "live_smoke_allowed_by_default": False,
        "do_not_rewrite_vps_smoked_evidence": True,
        "required_checks": list(_CURRENT_HEAD_PACKAGE_PREFLIGHT_REQUIRED_CHECKS),
        "asset_path_preflight": _build_asset_path_preflight(),
        "requires_named_gate_for_live_apply": (
            f"P7-C001 live package/apply/smoke gate for {CURRENT_PACKAGE_PREFLIGHT_HEAD}"
        ),
    }


def _build_asset_path_preflight() -> dict[str, Any]:
    return {
        "status": "asset_path_preflight_ready",
        "gate": "package/preflight only",
        "live_apply_allowed": False,
        "required_checks": list(_ASSET_PATH_PREFLIGHT_REQUIRED_CHECKS),
        "artifacts": {
            "package_zip": "dist/amn2-vps-update-and-smoke-kit-b121865.zip",
            "package_sha256_file": "dist/amn2-vps-update-and-smoke-kit-b121865.zip.sha256.txt",
            "source_zip": "dist/amn2-codex-vps-test-prep-b121865-source.zip",
            "source_sha256_file": "dist/amn2-codex-vps-test-prep-b121865-source.zip.sha256.txt",
            "operator_runbook": (
                "dist/amn2-vps-update-and-smoke-kit-b121865/"
                "AMN2_VPS_UPDATE_AND_SMOKE_b121865.ru.md"
            ),
            "apply_script": "dist/amn2-vps-update-and-smoke-kit-b121865/amn2_apply_source_zip.sh",
            "smoke_script": "dist/amn2-vps-update-and-smoke-kit-b121865/amn2_api_loopback_smoke.sh",
        },
        "helper_default_bindings": {
            "source_zip_commit": CURRENT_PACKAGE_PREFLIGHT_HEAD,
            "source_sha256": CURRENT_SOURCE_ZIP_SHA256,
            "expected_commit": CURRENT_PACKAGE_PREFLIGHT_HEAD,
        },
    }


def _build_rc_acceptance_checklist() -> dict[str, Any]:
    return {
        "schema_version": RC_ACCEPTANCE_SCHEMA_VERSION,
        "mode": "local_only",
        "status": "rc_checklist_ready",
        "target_head": CURRENT_PACKAGE_PREFLIGHT_HEAD,
        "known_good_vps_head": LATEST_VPS_SMOKED_PACKAGE_HEAD,
        "live_apply_allowed": False,
        "acceptance_sections": list(_RC_ACCEPTANCE_SECTIONS),
        "required_evidence": list(_RC_REQUIRED_EVIDENCE),
        "named_live_gate_required": (
            f"P7-C001 live package/apply/smoke gate for {CURRENT_PACKAGE_PREFLIGHT_HEAD}"
        ),
    }


def _build_multi_instance_ipam_rc_decision() -> dict[str, Any]:
    return {
        "status": "multi_instance_ipam_rc_decision_ready",
        "mode": "local_plan_only",
        "policy_doc": MULTI_INSTANCE_IPAM_MODEL_DOC,
        "gate": "local-only/docs/tests",
        "live_multi_instance_apply_allowed": False,
        "runtime_config_write_allowed": False,
        "firewall_change_allowed": False,
        "peer_migration_allowed": False,
        "config_delivery_allowed": False,
        "service_restart_allowed": False,
        "required_checks": list(_MULTI_INSTANCE_IPAM_REQUIRED_CHECKS),
        "safe_outputs": list(_MULTI_INSTANCE_IPAM_SAFE_OUTPUTS),
        "blocked_outputs": list(_MULTI_INSTANCE_IPAM_BLOCKED_OUTPUTS),
    }


def _build_public_config_write_prerequisite_split() -> dict[str, Any]:
    return {
        "schema_version": PUBLIC_CONFIG_WRITE_SPLIT_SCHEMA_VERSION,
        "status": "blocked_by_preconditions",
        "mode": "local_only_docs_tests",
        "gate": "P7-I004",
        "source_evidence": (
            "research/amn2/phase-7-public-config-write-preflight-b121865-2026-06-14.md"
        ),
        "combined_gate_retry_allowed": False,
        "live_changes_allowed": False,
        "readiness_tracks": [
            dict(track) for track in _PUBLIC_CONFIG_WRITE_READINESS_TRACKS
        ],
        "observed_blockers": list(_PUBLIC_CONFIG_WRITE_OBSERVED_BLOCKERS),
        "blocked_actions": list(_PUBLIC_CONFIG_WRITE_BLOCKED_ACTIONS),
    }


def _build_public_exposure_readiness_design() -> dict[str, Any]:
    return {
        "schema_version": PUBLIC_EXPOSURE_READINESS_SCHEMA_VERSION,
        "status": "readiness_design_ready",
        "mode": "local_only_docs_tests",
        "gate": "P7-I005",
        "target_gate": "P7-C002",
        "source_evidence": (
            "research/amn2/phase-7-public-config-write-preflight-b121865-2026-06-14.md"
        ),
        "live_exposure_allowed": False,
        "requires_named_gate_for_apply": "P7-C002 public exposure gate",
        "checklists": [
            dict(checklist) for checklist in _PUBLIC_EXPOSURE_READINESS_CHECKLISTS
        ],
        "blocked_actions": list(_PUBLIC_EXPOSURE_BLOCKED_ACTIONS),
    }


def _build_config_delivery_channel_readiness() -> dict[str, Any]:
    return {
        "schema_version": CONFIG_DELIVERY_CHANNEL_READINESS_SCHEMA_VERSION,
        "status": "readiness_design_ready",
        "mode": "local_only_docs_tests",
        "gate": "P7-I006",
        "target_gate": "P7-C003",
        "source_evidence": (
            "research/amn2/phase-7-public-config-write-preflight-b121865-2026-06-14.md"
        ),
        "live_delivery_allowed": False,
        "requires_named_gate_for_apply": "P7-C003 config delivery gate",
        "checklists": [
            dict(checklist) for checklist in _CONFIG_DELIVERY_CHANNEL_CHECKLISTS
        ],
        "blocked_actions": list(_CONFIG_DELIVERY_BLOCKED_ACTIONS),
    }


def _build_config_delivery_channel_readiness_plan_view() -> dict[str, Any]:
    readiness = dict(_build_config_delivery_channel_readiness())
    plan_checklists: list[dict[str, Any]] = []
    for checklist in readiness["checklists"]:
        plan_checklist = dict(checklist)
        forbidden_evidence = plan_checklist.pop("forbidden_evidence", None)
        if forbidden_evidence is not None:
            plan_checklist["forbidden_evidence_count"] = len(forbidden_evidence)
            plan_checklist["evidence_policy"] = "names_redacted_from_rendered_plan"
        plan_checklists.append(plan_checklist)
    readiness["checklists"] = plan_checklists
    return readiness


def _build_write_api_scope_decision() -> dict[str, Any]:
    return {
        "schema_version": WRITE_API_SCOPE_DECISION_SCHEMA_VERSION,
        "status": "decision_ready",
        "mode": "local_only_docs_tests",
        "gate": "P7-I007",
        "target_gate": "P7-C005",
        "source_evidence": (
            "research/amn2/phase-7-public-config-write-preflight-b121865-2026-06-14.md"
        ),
        "selected_policy": "keep_public_api_read_only_for_rc",
        "write_api_enabled": False,
        "public_write_routes_allowed": False,
        "local_agent_mutation_allowed": False,
        "production_peer_user_mutation_allowed": False,
        "requires_named_gate_for_apply": "P7-C005 write API / install mutation gate",
        "decision_options": [
            dict(option) for option in _WRITE_API_DECISION_OPTIONS
        ],
        "required_before_any_write": list(_WRITE_API_REQUIRED_BEFORE_ANY_WRITE),
        "blocked_actions": list(_WRITE_API_BLOCKED_ACTIONS),
    }


def _build_backup_restore_import_readiness() -> dict[str, Any]:
    return {
        "schema_version": BACKUP_RESTORE_IMPORT_READINESS_SCHEMA_VERSION,
        "status": "readiness_checklist_ready",
        "mode": "local_only_docs_tests",
        "gate": "P7-I008",
        "target_gate": "P7-C006",
        "source_evidence": (
            "research/amn2/phase-7-public-config-write-preflight-b121865-2026-06-14.md"
        ),
        "live_backup_allowed": False,
        "restore_apply_allowed": False,
        "archive_import_allowed": False,
        "reboot_allowed": False,
        "requires_named_gate_for_apply": "P7-C006 backup/restore/import gate",
        "checklists": [
            dict(checklist) for checklist in _BACKUP_RESTORE_IMPORT_CHECKLISTS
        ],
        "blocked_actions": list(_BACKUP_RESTORE_IMPORT_BLOCKED_ACTIONS),
    }


def _build_telegram_identity_readiness() -> dict[str, Any]:
    return {
        "schema_version": TELEGRAM_IDENTITY_READINESS_SCHEMA_VERSION,
        "status": "readiness_checklist_ready",
        "mode": "local_only_docs_tests",
        "gate": "P7-I009",
        "target_gate": "P7-C007",
        "source_evidence": (
            "research/amn2/phase-7-public-config-write-preflight-b121865-2026-06-14.md"
        ),
        "telegram_api_enabled": False,
        "token_use_allowed": False,
        "profile_mutation_allowed": False,
        "media_mutation_allowed": False,
        "live_bot_send_allowed": False,
        "requires_named_gate_for_apply": (
            "P7-C007 Telegram identity/profile/media mutation gate"
        ),
        "checklists": [
            dict(checklist) for checklist in _TELEGRAM_IDENTITY_CHECKLISTS
        ],
        "blocked_actions": list(_TELEGRAM_IDENTITY_BLOCKED_ACTIONS),
    }


def _build_secret_input_contract() -> dict[str, Any]:
    return {
        "status": "secret_input_contract_ready",
        "raw_secret_input_allowed": False,
        "blocks_fields": list(DEFAULT_FRESH_INSTALL_ANSWERS),
        "safe_error_mode": "field_only_no_value_echo",
        "forbidden_marker_categories": [
            "env_file",
            "client_config",
            "qr_payload",
            "vpn_import_uri",
            "key_material",
            "shared_secret_material",
            "auth_header_material",
            "token_material",
        ],
    }


def _contains_secret_marker(value: str) -> bool:
    candidate = value.strip()
    if not candidate:
        return False
    candidate_lower = candidate.lower()
    return any(marker.lower() in candidate_lower for marker in _SECRET_INPUT_MARKERS)


def _build_target_preflight() -> dict[str, Any]:
    return {
        "mode": "local_plan_only",
        "live_execution": "blocked_without_named_gate",
        "checks": [dict(check) for check in _TARGET_PREFLIGHT_CHECKS],
    }


def _build_runtime_decision(normalized: dict[str, str]) -> dict[str, Any]:
    return {
        "selected": normalized["runtime"],
        "supported_modes": ["docker", "host_systemd"],
        "decision_source": "operator_answer",
        "service_restart_allowed": False,
    }
