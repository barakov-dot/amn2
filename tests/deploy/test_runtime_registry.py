from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]


def test_runtime_manifest_describes_supported_modes_and_git_policy():
    manifest_path = ROOT / "deploy/runtime/manifest.yml"

    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))

    assert manifest["schema_version"] == 1
    assert manifest["project"] == "amn2"
    assert set(manifest["runtime_modes"]) == {"host_systemd", "docker"}
    assert "docker" in manifest["runtime_modes"]["docker"]["required_commands"]
    assert "awg" in manifest["runtime_modes"]["host_systemd"]["required_commands"]
    assert "sshpass" in manifest["common"]["optional_commands"]
    assert "data" in manifest["common"]["project_dirs"]
    assert "config_templates" in manifest["common"]["project_dirs"]
    assert ".env" in manifest["git_policy"]["never_store"]
    assert "servers.yml" in manifest["git_policy"]["never_store"]
    assert "deploy/runtime/collect_debug_snapshot.sh" in manifest["diagnostics"]["scripts"]
    assert "APP_SECRET_KEY" in manifest["diagnostics"]["redacted_keys"]


def test_runtime_manifest_defines_persistent_telegram_admission_contract():
    manifest_path = ROOT / "deploy/runtime/manifest.yml"

    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    telegram = manifest["telegram_persistent"]

    assert telegram["activation"] == "separate_exact_gate"
    assert telegram["allowed_updates"] == ["message", "callback_query"]
    assert telegram["settings"] == {
        "expected_bot_username": "TELEGRAM_EXPECTED_BOT_USERNAME",
        "admission_timeout_seconds": "TELEGRAM_ADMISSION_TIMEOUT_SECONDS",
        "polling_timeout_seconds": "TELEGRAM_POLLING_TIMEOUT_SECONDS",
        "runtime_lock_path": "TELEGRAM_RUNTIME_LOCK_PATH",
    }


def test_runtime_checker_is_read_only_and_knows_both_runtimes():
    checker_path = ROOT / "deploy/runtime/check_vps.sh"

    text = checker_path.read_text(encoding="utf-8")

    assert "AMN_RUNTIME" in text
    assert "host_systemd" in text
    assert "docker" in text
    assert "docker ps --format '{{.Names}}'" in text
    assert 'docker exec "$AMN_CONTAINER_NAME" awg show "$AMN_INTERFACE"' in text
    assert 'docker exec "$AMN_CONTAINER_NAME" command -v awg' not in text
    assert "systemctl is-active" in text
    assert "optional_command sshpass" in text
    for mutating in ("apt install", "systemctl restart", "docker rm", "rm -", "ufw allow"):
        assert mutating not in text


def test_debug_snapshot_script_is_read_only_and_redacts_secrets():
    script_path = ROOT / "deploy/runtime/collect_debug_snapshot.sh"

    text = script_path.read_text(encoding="utf-8")

    assert "AMN_RUNTIME" in text
    assert "AMN_LOG_LINES" in text
    assert "redact_stream" in text
    assert "TELEGRAM_BOT_TOKEN" in text
    assert "APP_SECRET_KEY" in text
    assert "WEB_ADMIN_SESSION_SECRET" in text
    assert "validate_port AMN_WEB_PORT" in text
    assert "validate_port AMN_VPN_PORT" in text
    assert "run_shell()" not in text
    assert 'bash -lc "$command"' not in text
    assert 'ss "$@"' in text
    assert "python -m app.cli server check" in text
    assert "deploy/runtime/check_vps.sh" in text
    assert "docker inspect" in text
    assert 'docker exec "$AMN_CONTAINER_NAME" awg show "$AMN_INTERFACE"' in text
    assert 'docker exec "$AMN_CONTAINER_NAME" command -v awg' not in text
    for mutating in ("apt install", "systemctl restart", "docker rm", "rm -", "ufw allow", "docker stop"):
        assert mutating not in text


def test_runtime_examples_are_parseable_and_cover_host_and_docker():
    host_path = ROOT / "deploy/examples/servers.host_systemd.example.yml"
    docker_path = ROOT / "deploy/examples/servers.docker.example.yml"

    host = yaml.safe_load(host_path.read_text(encoding="utf-8"))
    docker = yaml.safe_load(docker_path.read_text(encoding="utf-8"))

    assert host["servers"][0]["runtime"] == {
        "type": "host_systemd",
        "service_name": "awg-quick@awg0",
    }
    assert docker["servers"][0]["runtime"] == {
        "type": "docker",
        "container_name": "amnezia-awg",
        "config_path": "/opt/amnezia/awg/awg0.conf",
    }
    assert host["servers"][0]["vpn"]["port"] == 30001
    assert docker["servers"][0]["vpn"]["interface"] == "awg0"


def test_runtime_docs_point_to_manifest_checker_and_examples():
    doc_path = ROOT / "docs/RUNTIME_REGISTRY.ru.md"

    text = doc_path.read_text(encoding="utf-8")

    assert "deploy/runtime/manifest.yml" in text
    assert "deploy/runtime/check_vps.sh" in text
    assert "deploy/runtime/collect_debug_snapshot.sh" in text
    assert "deploy/examples/servers.docker.example.yml" in text
    assert "docker exec amnezia-awg command -v awg" not in text
    assert "Не храним в Git" in text


def test_vps_log_collection_doc_lists_commands_and_redaction_rules():
    doc_path = ROOT / "docs/VPS_LOG_COLLECTION.ru.md"

    text = doc_path.read_text(encoding="utf-8")

    assert "deploy/runtime/collect_debug_snapshot.sh" in text
    assert "git log -1 --oneline" in text
    assert "python -m app.cli server check" in text
    assert "docker ps --format" in text
    assert "docker exec amnezia-awg command -v awg" not in text
    assert "journalctl -u amneziya-web" in text
    assert "tail -n 200 logs/app.log" in text
    assert "TELEGRAM_BOT_TOKEN" in text
    assert "APP_SECRET_KEY" in text


def test_vps_retest_protocol_doc_lists_repeatable_test_steps():
    doc_path = ROOT / "docs/VPS_RETEST_PROTOCOL.ru.md"
    checklist_path = ROOT / "docs/PRODUCTION_VPS_CHECKLIST.ru.md"

    text = doc_path.read_text(encoding="utf-8")
    checklist = checklist_path.read_text(encoding="utf-8")

    assert "git pull origin codex-vps-test-prep" in text
    assert "codex/remote-operation-vps-gate-prep" in text
    assert "git log -1 --oneline" in text
    assert "python -m pip install -e ." in text
    assert "python -m app.cli bot check-network" in text
    assert "python -m app.cli server check --config servers.yml --server debian-vps-1 --dry-run" in text
    assert "python -m app.cli server apply-peer --config servers.yml --server debian-vps-1 --public-key TEST_PEER_PUBLIC_KEY --preshared-key-stdin --vpn-ip TEST_VPN_IP --dry-run" in text
    assert "--preshared-key-stdin" in text
    assert "python -m app.cli server revoke-peer --config servers.yml --server debian-vps-1 --public-key TEST_PEER_PUBLIC_KEY --dry-run" in text
    assert "Operation ID: server.peer.apply" in text
    assert "Consistency status: dry-run" in text
    assert "bash deploy/runtime/check_vps.sh" in text
    assert "AMN_RUNTIME=docker AMN_CONTAINER_NAME=amnezia-awg AMN_INTERFACE=awg0 bash deploy/runtime/collect_debug_snapshot.sh" in text
    assert "что нажимал" in text
    assert "docs/VPS_RETEST_PROTOCOL.ru.md" in checklist


def test_api_vps_smoke_evidence_template_is_safe_and_linked():
    template_path = ROOT / "docs/API_VPS_SMOKE_EVIDENCE.ru.md"
    retest_path = ROOT / "docs/VPS_RETEST_PROTOCOL.ru.md"
    checklist_path = ROOT / "docs/PRODUCTION_VPS_CHECKLIST.ru.md"
    handoff_path = ROOT / "docs/NEXT_CHAT_HANDOFF.ru.md"

    template = template_path.read_text(encoding="utf-8")
    retest = retest_path.read_text(encoding="utf-8")
    checklist = checklist_path.read_text(encoding="utf-8")
    handoff = handoff_path.read_text(encoding="utf-8")

    assert "Заполнять после реального VPS smoke" in template
    assert "codex/read-only-api-route-shell" in template
    assert "python -m app.cli api smoke-cycle" in template
    assert "GET /api/users/summary" in template
    assert "api_read" in template
    assert "raw API token" in template
    assert "Authorization header" in template
    assert "token hash" in template
    assert "PrivateKey" in template
    assert "PresharedKey" in template
    assert "VPS verdict" in template
    assert "Next local action" in template
    assert "docs/API_VPS_SMOKE_EVIDENCE.ru.md" in retest
    assert "docs/API_VPS_SMOKE_EVIDENCE.ru.md" in checklist
    assert "docs/API_VPS_SMOKE_EVIDENCE.ru.md" in handoff


def test_production_launch_gate_keeps_first_prod_run_operator_only():
    gate_path = ROOT / "docs/AMN2_PRODUCTION_LAUNCH_GATE.ru.md"
    handoff_path = ROOT / "docs/NEXT_CHAT_HANDOFF.ru.md"
    phase_path = ROOT / "docs/PROJECT_PHASE_MAP.ru.md"
    checklist_path = ROOT / "docs/PRODUCTION_VPS_CHECKLIST.ru.md"

    gate = gate_path.read_text(encoding="utf-8")
    handoff = handoff_path.read_text(encoding="utf-8")
    phase = phase_path.read_text(encoding="utf-8")
    checklist = checklist_path.read_text(encoding="utf-8")

    assert "controlled-prod-ready" in gate
    assert "c92bd1a" in gate
    assert "VPS_APPLY_ENABLED=false" in gate
    assert "python -m app.cli backup create" in gate
    assert "python -m app.cli backup verify" in gate
    assert "python -m app.cli bot check-network" in gate
    assert "python -m app.cli server preflight" in gate
    assert "python -m app.cli api smoke-cycle" in gate
    assert "sudo systemctl enable --now amneziya-web" in gate
    assert "sudo systemctl enable --now amneziya-bot" in gate
    assert "127.0.0.1:3040" in gate
    assert "API 3040 наружу не выставлять" in gate
    assert "/api/clients write CRUD" in gate
    assert "API `config:read`" in gate
    assert "Local Agent" in gate
    assert "backup/import/reboot" in gate
    assert "raw API token" in gate
    assert "Authorization header" in gate
    assert "PrivateKey" in gate
    assert "PresharedKey" in gate
    assert "docs/AMN2_PRODUCTION_LAUNCH_GATE.ru.md" in handoff
    assert "docs/AMN2_PRODUCTION_LAUNCH_GATE.ru.md" in phase
    assert "docs/AMN2_PRODUCTION_LAUNCH_GATE.ru.md" in checklist


def test_api_vps_smoke_evidence_records_42ffa65_launch_without_claiming_c92():
    evidence_path = ROOT / "docs/API_VPS_SMOKE_EVIDENCE.ru.md"

    evidence = evidence_path.read_text(encoding="utf-8")

    assert "## Production Launch Gate Attempt: 2026-06-07 / 42ffa65" in evidence
    assert "source_overlay_commit: 42ffa65" in evidence
    assert "backup_file: backups/amneziya-backup-20260607T192423Z.tar.enc" in evidence
    assert "backup_verify: passed" in evidence
    assert "api_smoke_status: passed" in evidence
    assert "api_checked_routes: 6" in evidence
    assert "web_login_http: 200" in evidence
    assert "127.0.0.1:3030" in evidence
    assert "127.0.0.1:3040" in evidence
    assert "current_gate_target: c92bd1a" in evidence
    assert "c92bd1a_alignment_status: pending" in evidence


def test_c92_source_overlay_alignment_runbook_is_linked_and_safe():
    runbook_path = ROOT / "docs/AMN2_C92_SOURCE_OVERLAY_ALIGNMENT.ru.md"
    gate_path = ROOT / "docs/AMN2_PRODUCTION_LAUNCH_GATE.ru.md"
    handoff_path = ROOT / "docs/NEXT_CHAT_HANDOFF.ru.md"
    checklist_path = ROOT / "docs/PRODUCTION_VPS_CHECKLIST.ru.md"

    runbook = runbook_path.read_text(encoding="utf-8")
    gate = gate_path.read_text(encoding="utf-8")
    handoff = handoff_path.read_text(encoding="utf-8")
    checklist = checklist_path.read_text(encoding="utf-8")

    assert "amn2-vps-update-and-smoke-kit-c92bd1a.zip" in runbook
    assert "EC48DBA7C91F189512AB77EB5490432C85DA79F987068A98C1CC7F3082387F12" in runbook
    assert "272CC013A416937AAA2256A1643B2C77F707874D28FDCB2EA16534E349DD4FC2" in runbook
    assert "sha256sum -c amn2-vps-update-and-smoke-kit-c92bd1a.zip.sha256.txt" in runbook
    assert "bash ./amn2_apply_source_zip.sh" in runbook
    assert "cat .amn2_source_overlay_commit" in runbook
    assert "c92bd1a" in runbook
    assert "VPS_APPLY_ENABLED=false" in runbook
    assert "dotenv_values(\".env\")" in runbook
    assert "source .env" not in runbook
    assert ". ./.env" not in runbook
    assert "set -a" not in runbook
    assert "python -m app.cli backup create" in runbook
    assert "python -m app.cli backup verify" in runbook
    assert "python -m app.cli api smoke-cycle" in runbook
    assert "python -m app.cli web serve --host 127.0.0.1 --port 3030" in runbook
    assert "sudo systemctl enable --now amneziya-web" in runbook
    assert "## 8b. Service Deployment" in runbook
    assert "Этот service deployment не требуется" in runbook
    assert "systemd_launch_status: deferred-working-server" in runbook
    assert "127.0.0.1:3030" in runbook
    assert "127.0.0.1:3040" in runbook
    assert "raw API token" in runbook
    assert "PrivateKey" in runbook
    assert "docs/AMN2_C92_SOURCE_OVERLAY_ALIGNMENT.ru.md" in gate
    assert "docs/AMN2_C92_SOURCE_OVERLAY_ALIGNMENT.ru.md" in handoff
    assert "docs/AMN2_C92_SOURCE_OVERLAY_ALIGNMENT.ru.md" in checklist


def test_api_vps_smoke_evidence_records_c92_manual_prelaunch_with_service_deferred():
    evidence_path = ROOT / "docs/API_VPS_SMOKE_EVIDENCE.ru.md"

    evidence = evidence_path.read_text(encoding="utf-8")

    assert "## c92bd1a Source Overlay Alignment: 2026-06-07" in evidence
    assert "source_update_status: passed" in evidence
    assert "source_overlay_commit: c92bd1a" in evidence
    assert "backup_file: backups/amneziya-backup-20260607T195439Z.tar.enc" in evidence
    assert "backup_verify: passed" in evidence
    assert "dotenv_shell_source_status: failed-on-special-character" in evidence
    assert "dotenv_safe_loader_next_step: use python-dotenv for APP_SECRET_KEY only" in evidence
    assert "api_smoke_status: passed" in evidence
    assert "api_checked_routes: 6" in evidence
    assert "decision: c92bd1a-manual-prelaunch-pass-systemd-deferred" in evidence
    assert "web_systemd_launch_status: deferred-working-server" in evidence
    assert "manual_web_runtime_status: passed" in evidence
    assert "web_login_http: 200" in evidence
    assert "web_listener: 127.0.0.1:3030" in evidence
    assert "web_listener_after_cleanup: stopped" in evidence
