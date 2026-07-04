import json
import subprocess
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
        "P7-C002 required before public exposure",
        "P7-C003 required before config delivery",
        "P7-C005 required before write API",
        "P7-C004 required before destructive cleanup/reinstall",
    ]
    assert plan["rendered_plan"]["requires_named_gates"] == [
        "P7-C002",
        "P7-C003",
        "P7-C005",
        "P7-C004",
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
        "Открывать публичный доступ сейчас (yes/no)",
        "Включать выдачу реальных конфигов сейчас (yes/no)",
        "Включать write API для установки сейчас (yes/no)",
        "Запускать очистку или переустановку сейчас (yes/no)",
        "Режим Telegram-бота",
        "Режим передачи секретов",
    ]
    assert any("Название" in prompt for prompt in prompts)
    prompt_text = " ".join(prompts).lower()
    assert "production" not in prompt_text
    assert "destructive" not in prompt_text
    assert "cleanup" not in prompt_text
    assert "credential" not in prompt_text
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
    expected_head = _expected_git_head()

    assert package_preflight["schema_version"] == "fresh-install-package-preflight.v1"
    assert package_preflight["mode"] == "local_plan_only"
    assert package_preflight["current_source_head"] == expected_head
    assert package_preflight["target_head"] == "b121865"
    assert package_preflight["latest_vps_smoked_head"] == "b121865"
    assert (
        package_preflight["package_status_for_current_source_head"]
        == "not_package_rebuilt_not_vps_smoked"
    )
    assert package_preflight["prebuilt_artifact_head"] == "b121865"
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
        "P7-C001 live package/apply/smoke gate for b121865"
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
        "package_local_helper_defaults_match_commit",
    ]
    assert "asset_path_preflight" in package_preflight["required_checks"]
    assert package_preflight["asset_path_preflight"]["artifacts"] == {
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
    }
    assert package_preflight["asset_path_preflight"]["helper_default_bindings"] == {
        "source_zip_commit": "b121865",
        "source_sha256": "D0FB561D5A12C3B2C095521C3B44923B001F49C8E94CA5C13DB1E811ABB17647",
        "expected_commit": "b121865",
    }


def test_manifest_includes_clean_installer_rc_acceptance_checklist():
    manifest = build_fresh_install_manifest()
    checklist = manifest["clean_installer_rc_acceptance"]

    assert checklist["schema_version"] == "clean-installer-rc-acceptance.v1"
    assert checklist["mode"] == "local_only"
    assert checklist["status"] == "rc_checklist_ready"
    assert checklist["target_head"] == "b121865"
    assert checklist["known_good_vps_head"] == "b121865"
    assert checklist["live_apply_allowed"] is False
    assert checklist["acceptance_sections"] == [
        "answers",
        "target_preflight",
        "package_preflight",
        "smoke_evidence",
        "secret_handoff",
        "rollback",
        "stop_lines",
    ]
    assert checklist["required_evidence"] == [
        "rendered_plan_secret_free",
        "package_sha256_recorded",
        "source_sha256_recorded",
        "operator_runbook_paths_verified",
        "helper_default_bindings_verified",
        "known_good_baseline_preserved",
        "multi_instance_ipam_conflict_model_reviewed",
    ]
    assert checklist["named_live_gate_required"] == (
        "P7-C001 live package/apply/smoke gate for b121865"
    )


def test_manifest_includes_multi_instance_ipam_rc_decision_model():
    manifest = build_fresh_install_manifest()
    model = manifest["multi_instance_ipam_rc_decision"]

    assert model["status"] == "multi_instance_ipam_rc_decision_ready"
    assert model["mode"] == "local_plan_only"
    assert model["policy_doc"] == "docs/MULTI_INSTANCE_IPAM_CONFLICT_MODEL.ru.md"
    assert model["live_multi_instance_apply_allowed"] is False
    assert model["runtime_config_write_allowed"] is False
    assert model["config_delivery_allowed"] is False
    assert model["service_restart_allowed"] is False
    assert model["required_checks"] == [
        "unique_runtime_instance_id",
        "unique_listen_port_per_instance",
        "non_overlapping_vpn_cidr",
        "unique_interface_name",
        "endpoint_pair_review",
        "dns_ipv6_policy_review",
    ]
    assert model["blocked_outputs"] == [
        "runtime_config_write",
        "firewall_change",
        "peer_migration",
        "config_delivery",
        "service_restart",
    ]


def test_manifest_includes_public_config_write_prerequisite_split():
    manifest = build_fresh_install_manifest()
    split = manifest["public_config_write_prerequisite_split"]

    assert split["schema_version"] == "public-config-write-prerequisite-split.v1"
    assert split["status"] == "blocked_by_preconditions"
    assert split["mode"] == "local_only_docs_tests"
    assert split["source_evidence"] == (
        "research/amn2/phase-7-public-config-write-preflight-b121865-2026-06-14.md"
    )
    assert split["combined_gate_retry_allowed"] is False
    assert split["live_changes_allowed"] is False
    assert [item["id"] for item in split["readiness_tracks"]] == [
        "public-exposure-readiness",
        "config-delivery-channel-readiness",
        "write-api-scope-decision",
    ]
    assert split["readiness_tracks"][0]["gate"] == "P7-C002"
    assert split["readiness_tracks"][0]["status"] == "blocked"
    assert "admin_credential_contract" in split["readiness_tracks"][0]["required_decisions"]
    assert split["readiness_tracks"][1]["gate"] == "P7-C003"
    assert "smtp_or_operator_local_channel" in split["readiness_tracks"][1][
        "required_decisions"
    ]
    assert split["readiness_tracks"][2]["gate"] == "P7-C005"
    assert "keep_public_api_read_only_for_rc" in split["readiness_tracks"][2][
        "decision_options"
    ]
    assert split["blocked_actions"] == [
        "public_listener_change",
        "domain_tls_reverse_proxy_apply",
        "config_artifact_output",
        "write_api_route_enablement",
        "vps_apply_enabled_true",
        "local_agent_mutation",
        "live_peer_user_mutation",
    ]


def test_manifest_includes_public_exposure_readiness_design():
    manifest = build_fresh_install_manifest()
    readiness = manifest["public_exposure_readiness_design"]

    assert readiness["schema_version"] == "public-exposure-readiness-design.v1"
    assert readiness["status"] == "readiness_design_ready"
    assert readiness["mode"] == "local_only_docs_tests"
    assert readiness["gate"] == "P7-I005"
    assert readiness["target_gate"] == "P7-C002"
    assert readiness["live_exposure_allowed"] is False
    assert readiness["requires_named_gate_for_apply"] == "P7-C002 public exposure gate"
    assert [check["id"] for check in readiness["checklists"]] == [
        "admin-credential-contract",
        "domain-tls-reverse-proxy-plan",
        "firewall-listener-plan",
        "external-probe-matrix",
        "rollback-to-loopback",
    ]
    assert readiness["checklists"][0]["required"] == [
        "WEB_ADMIN_USERNAME present",
        "WEB_ADMIN_PASSWORD_HASH present",
        "APP_SECRET_KEY present",
        "no raw credential value in evidence",
    ]
    assert readiness["checklists"][1]["requires_operator_inputs"] == [
        "domain_name",
        "tls_mode",
        "reverse_proxy_kind",
    ]
    assert readiness["checklists"][2]["blocked_direct_listeners"] == [
        "0.0.0.0:3030",
        "0.0.0.0:3040",
    ]
    assert readiness["checklists"][3]["expected_before_apply"] == {
        "3030": "closed",
        "3040": "closed",
        "80": "closed_or_proxy_planned",
        "443": "closed_or_proxy_planned",
    }
    assert readiness["checklists"][4]["rollback_goal"] == "web_loopback_only"
    assert readiness["blocked_actions"] == [
        "public_listener_change",
        "firewall_apply",
        "reverse_proxy_apply",
        "tls_certificate_issue",
        "public_openapi_publication",
        "direct_public_api_3040",
    ]


def test_manifest_includes_config_delivery_channel_readiness():
    manifest = build_fresh_install_manifest()
    readiness = manifest["config_delivery_channel_readiness"]

    assert readiness["schema_version"] == "config-delivery-channel-readiness.v1"
    assert readiness["status"] == "readiness_design_ready"
    assert readiness["mode"] == "local_only_docs_tests"
    assert readiness["gate"] == "P7-I006"
    assert readiness["target_gate"] == "P7-C003"
    assert readiness["live_delivery_allowed"] is False
    assert readiness["requires_named_gate_for_apply"] == "P7-C003 config delivery gate"
    assert [check["id"] for check in readiness["checklists"]] == [
        "delivery-channel-decision",
        "secret-safe-evidence-protocol",
        "client-import-matrix",
        "one-time-delivery-policy",
        "delivery-revocation-story",
    ]
    assert readiness["checklists"][0]["allowed_channels"] == [
        "smtp_email",
        "operator_local",
    ]
    assert readiness["checklists"][1]["forbidden_evidence"] == [
        "client_config_body",
        "qr_payload",
        "vpn_import_uri",
        "private_key",
        "preshared_key",
        "smtp_secret",
    ]
    assert readiness["checklists"][2]["required_artifacts"] == [
        "conf_file",
        "vpn_import_link",
        "qr_vpn_import_link",
    ]
    assert readiness["checklists"][3]["required_properties"] == [
        "single_use",
        "short_ttl",
        "purpose_bound",
        "audit_redacted",
    ]
    assert readiness["checklists"][4]["required_steps"] == [
        "disable_delivery_channel",
        "revoke_or_expire_delivery_token",
        "record_safe_revocation_summary",
    ]
    assert readiness["blocked_actions"] == [
        "config_artifact_output",
        "smtp_send",
        "telegram_config_send",
        "public_config_link_issue",
        "public_config_link_redeem",
        "qr_generation_for_delivery",
    ]


def test_manifest_includes_write_api_scope_decision():
    manifest = build_fresh_install_manifest()
    decision = manifest["write_api_scope_decision"]

    assert decision["schema_version"] == "write-api-scope-decision.v1"
    assert decision["status"] == "decision_ready"
    assert decision["mode"] == "local_only_docs_tests"
    assert decision["gate"] == "P7-I007"
    assert decision["target_gate"] == "P7-C005"
    assert decision["selected_policy"] == "keep_public_api_read_only_for_rc"
    assert decision["write_api_enabled"] is False
    assert decision["public_write_routes_allowed"] is False
    assert decision["local_agent_mutation_allowed"] is False
    assert decision["production_peer_user_mutation_allowed"] is False
    assert decision["requires_named_gate_for_apply"] == (
        "P7-C005 write API / install mutation gate"
    )
    assert [option["id"] for option in decision["decision_options"]] == [
        "keep-public-api-read-only-for-rc",
        "separate-write-api-implementation-slice",
        "operator-only-web-write-window",
    ]
    assert decision["decision_options"][0]["selected"] is True
    assert decision["decision_options"][0]["write_routes_enabled"] is False
    assert decision["decision_options"][1]["requires_new_named_gate"] == "P7-C005"
    assert decision["required_before_any_write"] == [
        "route_inventory_still_zero_or_explicitly_scoped",
        "auth_scope_model_for_write",
        "idempotency_and_audit_contract",
        "rollback_or_compensating_action_story",
        "operator_confirmation_boundary",
        "safe_evidence_no_secret_or_peer_material",
    ]
    assert decision["blocked_actions"] == [
        "write_api_route_enablement",
        "api_clients_crud",
        "install_mutation_route",
        "local_agent_mutation",
        "vps_apply_enabled_true",
        "production_peer_user_mutation",
        "server_config_rewrite",
    ]


def test_manifest_includes_backup_restore_import_readiness():
    manifest = build_fresh_install_manifest()
    readiness = manifest["backup_restore_import_readiness"]

    assert readiness["schema_version"] == (
        "backup-restore-import-prerequisite-checklist.v1"
    )
    assert readiness["status"] == "readiness_checklist_ready"
    assert readiness["mode"] == "local_only_docs_tests"
    assert readiness["gate"] == "P7-I008"
    assert readiness["target_gate"] == "P7-C006"
    assert readiness["live_backup_allowed"] is False
    assert readiness["restore_apply_allowed"] is False
    assert readiness["archive_import_allowed"] is False
    assert readiness["reboot_allowed"] is False
    assert readiness["requires_named_gate_for_apply"] == (
        "P7-C006 backup/restore/import gate"
    )
    assert [check["id"] for check in readiness["checklists"]] == [
        "backup-scope-decision",
        "encryption-and-retention-policy",
        "restore-preview-safety",
        "import-source-validation",
        "disaster-recovery-drill-plan",
    ]
    assert readiness["checklists"][0]["required_decisions"] == [
        "source_state_scope",
        "artifact_inventory",
        "operator_retention_choice",
    ]
    assert readiness["checklists"][1]["required_properties"] == [
        "encrypted_at_rest",
        "operator_local_secret_handoff",
        "retention_window_declared",
        "safe_evidence_only",
    ]
    assert readiness["checklists"][2]["required_steps"] == [
        "restore_preview_only",
        "target_isolation_confirmed",
        "no_overwrite_without_named_gate",
    ]
    assert readiness["blocked_actions"] == [
        "backup_archive_create",
        "restore_apply",
        "archive_import_apply",
        "reboot",
        "destructive_migration",
        "remote_backup_download",
    ]


def test_manifest_includes_telegram_identity_readiness():
    manifest = build_fresh_install_manifest()
    readiness = manifest["telegram_identity_readiness"]

    assert readiness["schema_version"] == (
        "telegram-identity-profile-media-prerequisite-checklist.v1"
    )
    assert readiness["status"] == "readiness_checklist_ready"
    assert readiness["mode"] == "local_only_docs_tests"
    assert readiness["gate"] == "P7-I009"
    assert readiness["target_gate"] == "P7-C007"
    assert readiness["telegram_api_enabled"] is False
    assert readiness["token_use_allowed"] is False
    assert readiness["profile_mutation_allowed"] is False
    assert readiness["media_mutation_allowed"] is False
    assert readiness["live_bot_send_allowed"] is False
    assert readiness["requires_named_gate_for_apply"] == (
        "P7-C007 Telegram identity/profile/media mutation gate"
    )
    assert [check["id"] for check in readiness["checklists"]] == [
        "telegram-identity-scope-decision",
        "credential-handoff-and-storage-policy",
        "profile-media-asset-plan",
        "operator-preview-and-rollback",
        "post-mutation-relock-audit",
    ]
    assert readiness["checklists"][0]["required_decisions"] == [
        "bot_identity_target",
        "allowed_profile_fields",
        "operator_approval_window",
    ]
    assert readiness["checklists"][1]["required_properties"] == [
        "operator_local_secret_handoff",
        "no_token_in_evidence",
        "no_token_in_rendered_plan",
        "credential_rotation_story",
    ]
    assert readiness["checklists"][2]["required_artifacts"] == [
        "profile_display_name_plan",
        "profile_description_plan",
        "profile_media_asset_reference",
    ]
    assert readiness["blocked_actions"] == [
        "telegram_token_use",
        "live_bot_send",
        "profile_name_mutation",
        "profile_description_mutation",
        "profile_photo_mutation",
        "media_upload",
    ]


def test_fresh_install_plan_renders_public_config_write_prerequisite_split():
    plan = build_fresh_install_plan(DEFAULT_FRESH_INSTALL_ANSWERS)
    phases = {phase["id"]: phase for phase in plan["rendered_plan"]["phases"]}

    split = phases["public-config-write-prerequisite-split"]
    assert split["status"] == "blocked_by_preconditions"
    assert split["combined_gate_retry_allowed"] is False
    assert split["live_changes_allowed"] is False
    assert [item["gate"] for item in split["readiness_tracks"]] == [
        "P7-C002",
        "P7-C003",
        "P7-C005",
    ]


def test_fresh_install_plan_renders_public_exposure_readiness_design():
    plan = build_fresh_install_plan(DEFAULT_FRESH_INSTALL_ANSWERS)
    phases = {phase["id"]: phase for phase in plan["rendered_plan"]["phases"]}

    readiness = phases["public-exposure-readiness-design"]
    assert readiness["status"] == "readiness_design_ready"
    assert readiness["target_gate"] == "P7-C002"
    assert readiness["live_exposure_allowed"] is False
    assert readiness["requires_named_gate_for_apply"] == "P7-C002 public exposure gate"


def test_fresh_install_plan_renders_config_delivery_channel_readiness():
    plan = build_fresh_install_plan(DEFAULT_FRESH_INSTALL_ANSWERS)
    phases = {phase["id"]: phase for phase in plan["rendered_plan"]["phases"]}

    readiness = phases["config-delivery-channel-readiness"]
    assert readiness["status"] == "readiness_design_ready"
    assert readiness["target_gate"] == "P7-C003"
    assert readiness["live_delivery_allowed"] is False
    assert readiness["requires_named_gate_for_apply"] == "P7-C003 config delivery gate"


def test_fresh_install_plan_renders_write_api_scope_decision():
    plan = build_fresh_install_plan(DEFAULT_FRESH_INSTALL_ANSWERS)
    phases = {phase["id"]: phase for phase in plan["rendered_plan"]["phases"]}

    decision = phases["write-api-scope-decision"]
    assert decision["status"] == "decision_ready"
    assert decision["target_gate"] == "P7-C005"
    assert decision["selected_policy"] == "keep_public_api_read_only_for_rc"
    assert decision["write_api_enabled"] is False
    assert decision["public_write_routes_allowed"] is False
    assert decision["requires_named_gate_for_apply"] == (
        "P7-C005 write API / install mutation gate"
    )


def test_fresh_install_plan_renders_backup_restore_import_readiness():
    plan = build_fresh_install_plan(DEFAULT_FRESH_INSTALL_ANSWERS)
    phases = {phase["id"]: phase for phase in plan["rendered_plan"]["phases"]}

    readiness = phases["backup-restore-import-readiness"]
    assert readiness["status"] == "readiness_checklist_ready"
    assert readiness["target_gate"] == "P7-C006"
    assert readiness["live_backup_allowed"] is False
    assert readiness["restore_apply_allowed"] is False
    assert readiness["archive_import_allowed"] is False
    assert readiness["reboot_allowed"] is False
    assert readiness["requires_named_gate_for_apply"] == (
        "P7-C006 backup/restore/import gate"
    )


def test_fresh_install_plan_renders_telegram_identity_readiness():
    plan = build_fresh_install_plan(DEFAULT_FRESH_INSTALL_ANSWERS)
    phases = {phase["id"]: phase for phase in plan["rendered_plan"]["phases"]}

    readiness = phases["telegram-identity-readiness"]
    assert readiness["status"] == "readiness_checklist_ready"
    assert readiness["target_gate"] == "P7-C007"
    assert readiness["telegram_api_enabled"] is False
    assert readiness["token_use_allowed"] is False
    assert readiness["profile_mutation_allowed"] is False
    assert readiness["media_mutation_allowed"] is False
    assert readiness["requires_named_gate_for_apply"] == (
        "P7-C007 Telegram identity/profile/media mutation gate"
    )


def test_fresh_install_plan_renders_rc_acceptance_and_secret_input_contract():
    plan = build_fresh_install_plan(DEFAULT_FRESH_INSTALL_ANSWERS)
    phases = {phase["id"]: phase for phase in plan["rendered_plan"]["phases"]}

    assert phases["clean-installer-rc-acceptance"]["status"] == "local_only"
    assert phases["clean-installer-rc-acceptance"]["live_apply_allowed"] is False
    assert phases["secret-input-contract"]["raw_secret_input_allowed"] is False
    assert phases["secret-input-contract"]["blocks_fields"] == [
        "project_name",
        "server_name",
        "runtime",
        "vpn_protocol",
        "public_exposure",
        "config_delivery",
        "write_api",
        "destructive_cleanup",
        "telegram_bot",
        "secret_handoff",
    ]
    assert phases["multi-instance-ipam-rc-decision"]["status"] == "local_plan_only"
    assert phases["multi-instance-ipam-rc-decision"]["live_multi_instance_apply_allowed"] is False
    assert "non_overlapping_vpn_cidr" in phases["multi-instance-ipam-rc-decision"][
        "required_checks"
    ]


def test_fresh_install_plan_renders_readiness_phases_without_live_commands():
    plan = build_fresh_install_plan(DEFAULT_FRESH_INSTALL_ANSWERS)
    expected_head = _expected_git_head()

    phases = {phase["id"]: phase for phase in plan["rendered_plan"]["phases"]}

    assert phases["target-preflight-matrix"]["status"] == "local_plan_only"
    assert phases["runtime-mode-decision"]["selected"] == "docker"
    assert phases["runtime-mode-decision"]["service_restart_allowed"] is False
    assert phases["package-hygiene-checklist"]["package_rebuild_allowed"] is False
    assert "markdown_hygiene" in phases["package-hygiene-checklist"]["required_checks"]
    assert phases["current-head-package-preflight"]["status"] == "local_plan_only"
    assert phases["current-head-package-preflight"]["current_source_head"] == expected_head
    assert phases["current-head-package-preflight"]["target_head"] == "b121865"
    assert (
        phases["current-head-package-preflight"]["package_status_for_current_source_head"]
        == "not_package_rebuilt_not_vps_smoked"
    )
    assert phases["current-head-package-preflight"]["prebuilt_artifact_head"] == "b121865"
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


def test_fresh_install_plan_rejects_secret_bearing_answers():
    for key, value in {
        "project_name": "AMN2 vpn://secret",
        "server_name": "local PrivateKey = abc",
        "telegram_bot": "telegram_bot_token",
        "secret_handoff": ".env",
    }.items():
        with pytest.raises(ValueError, match=f"secret-bearing installer input is not allowed: {key}"):
            build_fresh_install_plan({**DEFAULT_FRESH_INSTALL_ANSWERS, key: value})


def _expected_git_head() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()
