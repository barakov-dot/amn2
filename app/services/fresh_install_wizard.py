from __future__ import annotations

from collections.abc import Callable
from typing import Any


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

QUESTION_PROMPTS: tuple[tuple[str, str], ...] = (
    ("project_name", "Project name"),
    ("server_name", "Server name"),
    ("runtime", "Runtime: docker or host_systemd"),
    ("vpn_protocol", "VPN protocol"),
    ("public_exposure", "Open public exposure now? yes/no"),
    ("config_delivery", "Enable real config delivery now? yes/no"),
    ("write_api", "Enable production write API now? yes/no"),
    ("destructive_cleanup", "Run destructive cleanup/reinstall now? yes/no"),
    ("telegram_bot", "Telegram bot credential mode"),
    ("secret_handoff", "Secret handoff mode"),
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

_STOP_LINES: tuple[tuple[str, str], ...] = (
    ("public_exposure", "P6-C001 required before public exposure"),
    ("config_delivery", "P6-C002 required before config delivery"),
    ("write_api", "P6-C003 required before write API"),
    ("destructive_cleanup", "P6-C007 required before destructive cleanup/reinstall"),
)


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
        for key, message in _STOP_LINES
        if normalized.get(key) == "yes"
    ]
    return {
        "status": "blocked_named_gate_required"
        if stop_lines
        else "fresh_install_wizard_ready",
        "mode": "local_only_dry_run",
        "operator_inputs": normalized,
        "safety": {
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
        },
        "stop_lines": stop_lines,
        "local_dry_run_steps": [
            "python -m app.toolchain check",
            "python -m app.cli install plan --answers fresh-install-answers.json --pretty",
            "python -m app.cli server retest-plan --config servers.yml --server local --db data/amneziya.sqlite3",
        ],
        "generated_artifacts": [
            "fresh-install-answers.json",
            "fresh-install-plan.json",
            "operator-secret-checklist.md",
        ],
        "blocked_without_named_gate": [
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
        ],
        "docs": {
            "runbook": "docs/FRESH_INSTALL_WIZARD.ru.md",
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
