from __future__ import annotations

from collections.abc import Callable
from typing import Any


QUESTION_SCHEMA_VERSION = "fresh-install-questions.v1"
ANSWER_SCHEMA_VERSION = "fresh-install-answers.v1"
PLAN_SCHEMA_VERSION = "fresh-install-plan.v1"
SECRET_HANDOFF_POLICY_DOC = "docs/AMN2_SECRET_HANDOFF_PROTOCOL.ru.md"

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
        "prompt": "Project name",
        "required": True,
        "allowed_values": None,
        "gate": None,
    },
    {
        "key": "server_name",
        "prompt": "Server name",
        "required": True,
        "allowed_values": None,
        "gate": None,
    },
    {
        "key": "runtime",
        "prompt": "Runtime: docker or host_systemd",
        "required": True,
        "allowed_values": ["docker", "host_systemd"],
        "gate": None,
    },
    {
        "key": "vpn_protocol",
        "prompt": "VPN protocol",
        "required": True,
        "allowed_values": ["amneziawg", "wireguard", "xray"],
        "gate": None,
    },
    {
        "key": "public_exposure",
        "prompt": "Open public exposure now? yes/no",
        "required": True,
        "allowed_values": ["no", "yes"],
        "gate": "P6-C001",
    },
    {
        "key": "config_delivery",
        "prompt": "Enable real config delivery now? yes/no",
        "required": True,
        "allowed_values": ["no", "yes"],
        "gate": "P6-C002",
    },
    {
        "key": "write_api",
        "prompt": "Enable production write API now? yes/no",
        "required": True,
        "allowed_values": ["no", "yes"],
        "gate": "P6-C003",
    },
    {
        "key": "destructive_cleanup",
        "prompt": "Run destructive cleanup/reinstall now? yes/no",
        "required": True,
        "allowed_values": ["no", "yes"],
        "gate": "P6-C007",
    },
    {
        "key": "telegram_bot",
        "prompt": "Telegram bot credential mode",
        "required": True,
        "allowed_values": ["not_configured", "operator_local"],
        "gate": None,
    },
    {
        "key": "secret_handoff",
        "prompt": "Secret handoff mode",
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
    ("public_exposure", "P6-C001", "P6-C001 required before public exposure"),
    ("config_delivery", "P6-C002", "P6-C002 required before config delivery"),
    ("write_api", "P6-C003", "P6-C003 required before write API"),
    (
        "destructive_cleanup",
        "P6-C007",
        "P6-C007 required before destructive cleanup/reinstall",
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


def build_fresh_install_manifest() -> dict[str, Any]:
    return {
        "status": "fresh_install_manifest_ready",
        "mode": "local_only_dry_run",
        "question_schema": _build_question_schema(),
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
