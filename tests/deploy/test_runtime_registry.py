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
    assert "codex/vps-gate-remote-ops-integration" in text
    assert "git log -1 --oneline" in text
    assert "python -m pip install -e ." in text
    assert "python -m app.cli bot check-network" in text
    assert "python -m app.cli server check --config servers.yml --server debian-vps-1 --dry-run" in text
    assert "python -m app.cli server apply-peer --config servers.yml --server debian-vps-1 --public-key TEST_PEER_PUBLIC_KEY --preshared-key TEST_PEER_PSK --vpn-ip TEST_VPN_IP --dry-run" in text
    assert "python -m app.cli server revoke-peer --config servers.yml --server debian-vps-1 --public-key TEST_PEER_PUBLIC_KEY --dry-run" in text
    assert "Operation ID: server.peer.apply" in text
    assert "Consistency status: dry-run" in text
    assert "bash deploy/runtime/check_vps.sh" in text
    assert "AMN_RUNTIME=docker AMN_CONTAINER_NAME=amnezia-awg AMN_INTERFACE=awg0 bash deploy/runtime/collect_debug_snapshot.sh" in text
    assert "что нажимал" in text
    assert "docs/VPS_RETEST_PROTOCOL.ru.md" in checklist
