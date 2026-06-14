import json
from pathlib import Path

import pytest

from app.services.fresh_install_wizard import (
    DEFAULT_FRESH_INSTALL_ANSWERS,
    build_fresh_install_manifest,
    build_fresh_install_plan,
    collect_fresh_install_answers,
)


ROOT = Path(__file__).resolve().parents[2]


def test_build_fresh_install_plan_is_local_only_and_secret_free():
    answers = {
        **DEFAULT_FRESH_INSTALL_ANSWERS,
        "project_name": "Neobyatnaya AMNZ",
        "server_name": "local",
        "runtime": "docker",
        "vpn_protocol": "amneziawg",
        "telegram_bot": "operator_local",
        "secret_handoff": "operator_local",
    }

    plan = build_fresh_install_plan(answers)

    assert plan["status"] == "fresh_install_wizard_ready"
    assert plan["mode"] == "local_only_dry_run"
    assert plan["safety"]["live_vps_commands_enabled"] is False
    assert plan["safety"]["destructive_cleanup_enabled"] is False
    assert plan["safety"]["public_exposure_enabled"] is False
    assert plan["safety"]["config_delivery_enabled"] is False
    assert plan["safety"]["write_api_enabled"] is False
    assert plan["safety"]["vps_apply_enabled_default"] is False
    assert "python -m app.toolchain check" in plan["local_dry_run_steps"]
    assert "python -m app.cli install plan --answers fresh-install-answers.json --pretty" in plan[
        "local_dry_run_steps"
    ]
    assert plan["operator_inputs"]["telegram_bot"] == "operator_local"
    assert plan["operator_inputs"]["secret_handoff"] == "operator_local"
    assert plan["schema_version"] == "fresh-install-plan.v1"
    assert plan["question_schema"]["version"] == "fresh-install-questions.v1"
    assert plan["question_schema"]["answer_schema_version"] == "fresh-install-answers.v1"
    assert plan["secret_handoff"]["policy_doc"] == "docs/AMN2_SECRET_HANDOFF_PROTOCOL.ru.md"
    assert plan["secret_handoff"]["mode"] == "operator_local"
    assert plan["secret_handoff"]["raw_secret_allowed_in_plan"] is False
    assert plan["rendered_plan"]["title"] == "AMN2 fresh install local dry-run plan"
    assert plan["rendered_plan"]["target"]["server_name"] == "local"
    assert plan["rendered_plan"]["phases"][0]["id"] == "local-preflight"
    assert plan["rendered_plan"]["phases"][-1]["id"] == "named-gate-stop"

    plan_text = json.dumps(plan, ensure_ascii=False)
    forbidden = (
        "ssh ",
        "rm -",
        "systemctl restart",
        "docker restart",
        "VPS_APPLY_ENABLED=true",
        "PrivateKey",
        "PresharedKey",
        "vpn://",
        ".conf",
        "telegram_bot_token",
    )
    for marker in forbidden:
        assert marker not in plan_text


def test_build_fresh_install_plan_turns_gated_yes_answers_into_stop_lines():
    answers = {
        **DEFAULT_FRESH_INSTALL_ANSWERS,
        "project_name": "Neobyatnaya AMNZ",
        "server_name": "local",
        "public_exposure": "yes",
        "config_delivery": "yes",
        "write_api": "yes",
        "destructive_cleanup": "yes",
    }

    plan = build_fresh_install_plan(answers)

    assert plan["status"] == "blocked_named_gate_required"
    assert plan["mode"] == "local_only_dry_run"
    assert plan["safety"]["live_vps_commands_enabled"] is False
    assert plan["stop_lines"] == [
        "P6-C001 required before public exposure",
        "P6-C002 required before config delivery",
        "P6-C003 required before write API",
        "P6-C007 required before destructive cleanup/reinstall",
    ]
    assert plan["rendered_plan"]["requires_named_gates"] == [
        "P6-C001",
        "P6-C002",
        "P6-C003",
        "P6-C007",
    ]


def test_build_fresh_install_manifest_describes_questions_without_secrets():
    manifest = build_fresh_install_manifest()

    assert manifest["question_schema"]["version"] == "fresh-install-questions.v1"
    assert manifest["question_schema"]["answer_schema_version"] == "fresh-install-answers.v1"
    assert manifest["question_schema"]["fields"][0] == {
        "key": "project_name",
        "prompt": "Название проекта",
        "default": "AMN2",
        "required": True,
        "allowed_values": None,
        "gate": None,
    }
    prompts = [field["prompt"] for field in manifest["question_schema"]["fields"]]
    assert prompts == [
        "Название проекта",
        "Имя сервера",
        "Режим запуска: docker или host_systemd",
        "VPN-протокол",
        "Открывать публичный доступ сейчас? yes/no",
        "Включать реальную выдачу конфигов сейчас? yes/no",
        "Включать production write API сейчас? yes/no",
        "Запускать destructive cleanup/reinstall сейчас? yes/no",
        "Режим Telegram bot credential",
        "Режим передачи секретов",
    ]
    assert any("Название" in prompt for prompt in prompts)
    assert manifest["secret_handoff_policy"]["policy_doc"] == (
        "docs/AMN2_SECRET_HANDOFF_PROTOCOL.ru.md"
    )
    assert manifest["secret_handoff_policy"]["forbidden_in_plan"] == [
        ".env",
        "servers.yml",
        "telegram_bot_token",
        "web_admin_password",
        "session_secret",
        "client_config",
        "qr_payload",
        "vpn://",
    ]

    manifest_text = json.dumps(manifest, ensure_ascii=False)
    assert "PrivateKey" not in manifest_text
    assert "PresharedKey" not in manifest_text


def test_build_fresh_install_manifest_includes_read_only_preflight_runtime_and_package_hygiene():
    manifest = build_fresh_install_manifest()
    readiness = manifest["installer_readiness"]

    assert readiness["schema_version"] == "fresh-install-readiness.v1"
    assert readiness["target_preflight"]["mode"] == "local_plan_only"
    assert readiness["target_preflight"]["live_execution"] == "blocked_without_named_gate"
    assert [check["id"] for check in readiness["target_preflight"]["checks"]] == [
        "os-release",
        "python-runtime",
        "docker-runtime",
        "network-ports",
        "disk-space",
        "time-sync",
        "package-tools",
    ]
    assert all(check["read_only"] is True for check in readiness["target_preflight"]["checks"])

    assert readiness["runtime_decision"] == {
        "selected": "docker",
        "supported_modes": ["docker", "host_systemd"],
        "decision_source": "operator_answer",
        "service_restart_allowed": False,
    }

    assert readiness["package_hygiene"]["package_rebuild_allowed_by_default"] is False
    assert readiness["package_hygiene"]["do_not_rewrite_vps_smoked_evidence"] is True
    assert readiness["package_hygiene"]["required_checks"] == [
        "toolchain_check",
        "full_pytest",
        "git_diff_check",
        "source_zip_checksum",
        "forbidden_source_entries",
        "shell_lf_no_bom",
        "markdown_hygiene",
        "commit_binding",
    ]


def test_manifest_includes_current_head_package_preflight_plan_without_live_apply():
    manifest = build_fresh_install_manifest()
    package_preflight = manifest["current_head_package_preflight"]

    assert package_preflight["schema_version"] == "fresh-install-package-preflight.v1"
    assert package_preflight["mode"] == "local_plan_only"
    assert package_preflight["target_head"] == "ff77d4c"
    assert package_preflight["latest_vps_smoked_head"] == "c46f664"
    assert package_preflight["package_build_allowed_by_default"] is False
    assert package_preflight["live_apply_allowed_by_default"] is False
    assert package_preflight["live_smoke_allowed_by_default"] is False
    assert package_preflight["do_not_rewrite_vps_smoked_evidence"] is True
    assert package_preflight["required_checks"] == [
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
    assert package_preflight["requires_named_gate_for_live_apply"] == (
        "current-head live apply/smoke gate for ff77d4c"
    )


def test_current_head_package_preflight_includes_asset_path_checks():
    manifest = build_fresh_install_manifest()
    package_preflight = manifest["current_head_package_preflight"]

    assert package_preflight["asset_path_preflight"]["status"] == (
        "asset_path_preflight_ready"
    )
    assert package_preflight["asset_path_preflight"]["gate"] == (
        "package/preflight only"
    )
    assert package_preflight["asset_path_preflight"]["live_apply_allowed"] is False
    assert package_preflight["asset_path_preflight"]["required_checks"] == [
        "operator_kit_required_files_exist",
        "operator_runbook_paths_resolve",
        "package_manifest_paths_match_archive",
        "source_zip_paths_match_manifest",
        "no_secret_material_in_asset_manifest",
    ]
    assert "asset_path_preflight" in package_preflight["required_checks"]


def test_fresh_install_plan_renders_readiness_phases_without_live_commands():
    plan = build_fresh_install_plan(DEFAULT_FRESH_INSTALL_ANSWERS)

    phases = {phase["id"]: phase for phase in plan["rendered_plan"]["phases"]}

    assert phases["target-preflight-matrix"]["status"] == "local_plan_only"
    assert phases["runtime-mode-decision"]["selected"] == "docker"
    assert phases["runtime-mode-decision"]["service_restart_allowed"] is False
    assert phases["package-hygiene-checklist"]["package_rebuild_allowed"] is False
    assert "markdown_hygiene" in phases["package-hygiene-checklist"]["required_checks"]
    assert phases["current-head-package-preflight"]["status"] == "local_plan_only"
    assert phases["current-head-package-preflight"]["target_head"] == "ff77d4c"
    assert phases["current-head-package-preflight"]["live_apply_allowed"] is False
    assert phases["current-head-package-preflight"]["live_smoke_allowed"] is False
    assert phases["package-asset-path-preflight"]["status"] == "local_plan_only"
    assert phases["package-asset-path-preflight"]["live_apply_allowed"] is False

    plan_text = json.dumps(plan, ensure_ascii=False)
    for marker in ("ssh ", "systemctl restart", "docker restart", "VPS_APPLY_ENABLED=true"):
        assert marker not in plan_text


def test_manifest_includes_docs_test_evidence_readiness_without_secret_payloads():
    manifest = build_fresh_install_manifest()
    evidence = manifest["installer_evidence"]

    assert evidence["schema_version"] == "fresh-install-evidence.v1"
    assert evidence["smoke_evidence_template"]["mode"] == "local_template_only"
    assert evidence["smoke_evidence_template"]["live_smoke_allowed_by_default"] is False
    assert evidence["smoke_evidence_template"]["secret_payload_allowed"] is False
    assert evidence["smoke_evidence_template"]["required_sections"] == [
        "selected_commit",
        "loopback_http_codes",
        "auth_scope_status",
        "listener_summary",
        "audit_summary",
        "external_closed_probe_status",
        "forbidden_marker_result",
        "final_verdict",
    ]

    reconciliation = evidence["existing_server_reconciliation_input"]
    assert reconciliation["mode"] == "report_only"
    assert reconciliation["apply_allowed_by_default"] is False
    assert reconciliation["allowed_inputs"] == [
        "server_inventory_summary",
        "read_only_peer_counts",
        "runtime_mode_observation",
        "operator_notes",
    ]
    assert reconciliation["blocked_outputs"] == [
        "auto_fix",
        "peer_import",
        "config_overwrite",
        "peer_creation",
        "peer_removal",
    ]

    assert evidence["docs_index"]["path"] == "docs/FRESH_INSTALLER_OPERATOR_INDEX.ru.md"


def test_fresh_install_plan_renders_docs_test_evidence_phases():
    plan = build_fresh_install_plan(DEFAULT_FRESH_INSTALL_ANSWERS)
    phases = {phase["id"]: phase for phase in plan["rendered_plan"]["phases"]}

    assert phases["smoke-evidence-template"]["status"] == "local_template_only"
    assert phases["smoke-evidence-template"]["secret_payload_allowed"] is False
    assert phases["existing-server-reconciliation-input"]["mode"] == "report_only"
    assert phases["existing-server-reconciliation-input"]["apply_allowed"] is False
    assert phases["installer-docs-index"]["path"] == "docs/FRESH_INSTALLER_OPERATOR_INDEX.ru.md"

    plan_text = json.dumps(plan, ensure_ascii=False)
    for marker in ("PrivateKey", "PresharedKey", "vpn://", ".conf", "ssh "):
        assert marker not in plan_text


def test_fresh_installer_operator_index_doc_exists():
    manifest = build_fresh_install_manifest()

    index_doc = ROOT / manifest["installer_evidence"]["docs_index"]["path"]

    assert index_doc.exists()


def test_fresh_install_secret_handoff_policy_doc_exists():
    manifest = build_fresh_install_manifest()

    policy_doc = ROOT / manifest["secret_handoff_policy"]["policy_doc"]

    assert policy_doc.exists()


def test_collect_fresh_install_answers_uses_defaults_for_blank_answers():
    prompts: list[str] = []
    provided = iter(
        [
            "Neobyatnaya AMNZ",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
        ]
    )

    answers = collect_fresh_install_answers(
        input_fn=lambda prompt: prompts.append(prompt) or next(provided)
    )

    assert answers["project_name"] == "Neobyatnaya AMNZ"
    assert answers["server_name"] == DEFAULT_FRESH_INSTALL_ANSWERS["server_name"]
    assert answers["runtime"] == DEFAULT_FRESH_INSTALL_ANSWERS["runtime"]
    assert answers["public_exposure"] == "no"
    assert answers["destructive_cleanup"] == "no"
    assert len(prompts) == len(DEFAULT_FRESH_INSTALL_ANSWERS)


def test_fresh_install_plan_rejects_unsafe_or_blank_answers():
    with pytest.raises(ValueError, match="project_name cannot be blank"):
        build_fresh_install_plan({**DEFAULT_FRESH_INSTALL_ANSWERS, "project_name": ""})

    with pytest.raises(ValueError, match="invalid runtime"):
        build_fresh_install_plan(
            {
                **DEFAULT_FRESH_INSTALL_ANSWERS,
                "project_name": "Neobyatnaya AMNZ",
                "runtime": "kubernetes",
            }
        )
