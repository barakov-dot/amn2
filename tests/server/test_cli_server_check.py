import io

import app.cli as cli
from app.cli import build_parser
from app.cli import read_preshared_key_arg
from app.cli import run_server_peer_sync
from app.cli import run_server_preflight
from app.cli import run_server_traffic_collection
from app.cli import run_server_traffic_collection_dry_run
from app.cli import run_server_check
from app.db.connection import connect
from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.server_config.loader import load_server_config, select_server
from tests.server_config.test_loader import DOCKER_YAML
from tests.server_config.test_loader import VALID_YAML


def test_cli_accepts_server_check_arguments():
    parser = build_parser()

    args = parser.parse_args(["server", "check", "--config", "servers.yml", "--server", "debian-vps-1", "--dry-run"])

    assert args.command == "server"
    assert args.server_command == "check"
    assert args.config == "servers.yml"
    assert args.server == "debian-vps-1"
    assert args.dry_run is True


def test_run_server_check_dry_run_prints_read_only_commands(tmp_path):
    path = tmp_path / "servers.yml"
    path.write_text(VALID_YAML, encoding="utf-8")
    config = load_server_config(path)
    server = select_server(config, "debian-vps-1")

    output = run_server_check(server, dry_run=True)

    assert "Dry-run server check" in output
    assert "ssh root@" in output
    assert "cat /etc/os-release" in output
    assert "systemctl is-active awg-quick@awg0" in output
    assert "No changes will be made" in output


def test_run_server_check_dry_run_prints_docker_read_only_commands(tmp_path):
    path = tmp_path / "servers.yml"
    path.write_text(DOCKER_YAML, encoding="utf-8")
    config = load_server_config(path)
    server = select_server(config, "debian-vps-1")

    output = run_server_check(server, dry_run=True)

    assert "Dry-run server check" in output
    assert "command -v docker" in output
    assert "docker ps --format {{.Names}}" in output
    assert "docker exec amnezia-awg command -v awg" not in output
    assert "docker exec amnezia-awg awg show awg0" in output
    assert "systemctl is-active" not in output


def test_cli_accepts_server_apply_peer_dry_run_arguments():
    parser = build_parser()

    args = parser.parse_args(
        [
            "server",
            "apply-peer",
            "--config",
            "servers.yml",
            "--server",
            "debian-vps-1",
            "--public-key",
            "peer-public",
            "--preshared-key",
            "secret-psk",
            "--vpn-ip",
            "10.8.0.2",
            "--dry-run",
        ]
    )

    assert args.command == "server"
    assert args.server_command == "apply-peer"
    assert args.public_key == "peer-public"
    assert args.preshared_key == "secret-psk"
    assert args.vpn_ip == "10.8.0.2"
    assert args.dry_run is True
    assert args.apply is False


def test_cli_accepts_server_apply_peer_apply_arguments():
    parser = build_parser()

    args = parser.parse_args(
        [
            "server",
            "apply-peer",
            "--config",
            "servers.yml",
            "--server",
            "debian-vps-1",
            "--public-key",
            "peer-public",
            "--preshared-key",
            "secret-psk",
            "--vpn-ip",
            "10.8.0.2",
            "--apply",
        ]
    )

    assert args.command == "server"
    assert args.server_command == "apply-peer"
    assert args.apply is True
    assert args.dry_run is False


def test_cli_accepts_server_apply_peer_preshared_key_stdin_argument():
    parser = build_parser()

    args = parser.parse_args(
        [
            "server",
            "apply-peer",
            "--config",
            "servers.yml",
            "--server",
            "debian-vps-1",
            "--public-key",
            "peer-public",
            "--preshared-key-stdin",
            "--vpn-ip",
            "10.8.0.2",
            "--dry-run",
        ]
    )

    assert args.command == "server"
    assert args.server_command == "apply-peer"
    assert args.preshared_key is None
    assert args.preshared_key_stdin is True


def test_cli_rejects_both_preshared_key_inputs_for_server_apply_peer():
    parser = build_parser()

    try:
        parser.parse_args(
            [
                "server",
                "apply-peer",
                "--config",
                "servers.yml",
                "--server",
                "debian-vps-1",
                "--public-key",
                "peer-public",
                "--preshared-key",
                "secret-psk",
                "--preshared-key-stdin",
                "--vpn-ip",
                "10.8.0.2",
                "--dry-run",
            ]
        )
    except SystemExit as exc:
        assert exc.code == 2
    else:
        raise AssertionError("apply-peer must accept only one preshared-key input mode")


def test_read_preshared_key_arg_reads_one_stdin_line_without_newline(monkeypatch):
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("secret-psk\nignored\n"))
    parser = build_parser()
    args = parser.parse_args(
        [
            "server",
            "apply-peer",
            "--config",
            "servers.yml",
            "--server",
            "debian-vps-1",
            "--public-key",
            "peer-public",
            "--preshared-key-stdin",
            "--vpn-ip",
            "10.8.0.2",
            "--dry-run",
        ]
    )

    assert read_preshared_key_arg(args) == "secret-psk"


def test_read_preshared_key_arg_rejects_empty_stdin(monkeypatch):
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("\n"))
    parser = build_parser()
    args = parser.parse_args(
        [
            "server",
            "apply-peer",
            "--config",
            "servers.yml",
            "--server",
            "debian-vps-1",
            "--public-key",
            "peer-public",
            "--preshared-key-stdin",
            "--vpn-ip",
            "10.8.0.2",
            "--dry-run",
        ]
    )

    try:
        read_preshared_key_arg(args)
    except SystemExit as exc:
        assert "non-empty preshared key" in str(exc)
    else:
        raise AssertionError("empty stdin must not be accepted as a preshared key")


def test_cli_requires_explicit_apply_or_dry_run_for_server_apply_peer():
    parser = build_parser()

    try:
        parser.parse_args(
            [
                "server",
                "apply-peer",
                "--config",
                "servers.yml",
                "--server",
                "debian-vps-1",
                "--public-key",
                "peer-public",
                "--preshared-key",
                "secret-psk",
                "--vpn-ip",
                "10.8.0.2",
            ]
        )
    except SystemExit as exc:
        assert exc.code == 2
    else:
        raise AssertionError("apply-peer must require --apply or --dry-run")


def test_cli_accepts_server_revoke_peer_dry_run_arguments():
    parser = build_parser()

    args = parser.parse_args(
        [
            "server",
            "revoke-peer",
            "--config",
            "servers.yml",
            "--server",
            "debian-vps-1",
            "--public-key",
            "peer-public",
            "--dry-run",
        ]
    )

    assert args.command == "server"
    assert args.server_command == "revoke-peer"
    assert args.public_key == "peer-public"
    assert args.dry_run is True
    assert args.apply is False


def test_cli_accepts_server_revoke_peer_apply_arguments():
    parser = build_parser()

    args = parser.parse_args(
        [
            "server",
            "revoke-peer",
            "--config",
            "servers.yml",
            "--server",
            "debian-vps-1",
            "--public-key",
            "peer-public",
            "--apply",
        ]
    )

    assert args.command == "server"
    assert args.server_command == "revoke-peer"
    assert args.public_key == "peer-public"
    assert args.apply is True
    assert args.dry_run is False


def test_cli_apply_peer_blocks_live_mutation_when_vps_apply_disabled(tmp_path, monkeypatch):
    path = tmp_path / "servers.yml"
    path.write_text(VALID_YAML, encoding="utf-8")
    called = False

    class DisabledSettings:
        vps_apply_enabled = False

    def fail_apply_peer(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("apply_peer must not run while VPS_APPLY_ENABLED=false")

    monkeypatch.setattr(cli, "Settings", DisabledSettings)
    monkeypatch.setattr(cli, "apply_peer", fail_apply_peer)
    monkeypatch.setattr(
        cli.sys,
        "argv",
        [
            "amneziya",
            "server",
            "apply-peer",
            "--config",
            str(path),
            "--server",
            "debian-vps-1",
            "--public-key",
            "peer-public",
            "--preshared-key",
            "secret-psk",
            "--vpn-ip",
            "10.8.0.2",
            "--apply",
        ],
    )

    try:
        cli.main()
    except SystemExit as exc:
        assert "VPS_APPLY_ENABLED=true is required" in str(exc)
    else:
        raise AssertionError("live apply-peer must be blocked by default")
    assert called is False


def test_cli_revoke_peer_blocks_live_mutation_when_vps_apply_disabled(tmp_path, monkeypatch):
    path = tmp_path / "servers.yml"
    path.write_text(VALID_YAML, encoding="utf-8")
    called = False

    class DisabledSettings:
        vps_apply_enabled = False

    def fail_revoke_peer(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("revoke_peer must not run while VPS_APPLY_ENABLED=false")

    monkeypatch.setattr(cli, "Settings", DisabledSettings)
    monkeypatch.setattr(cli, "revoke_peer", fail_revoke_peer)
    monkeypatch.setattr(
        cli.sys,
        "argv",
        [
            "amneziya",
            "server",
            "revoke-peer",
            "--config",
            str(path),
            "--server",
            "debian-vps-1",
            "--public-key",
            "peer-public",
            "--apply",
        ],
    )

    try:
        cli.main()
    except SystemExit as exc:
        assert "VPS_APPLY_ENABLED=true is required" in str(exc)
    else:
        raise AssertionError("live revoke-peer must be blocked by default")
    assert called is False


def test_cli_accepts_server_collect_traffic_arguments():
    parser = build_parser()

    args = parser.parse_args(
        [
            "server",
            "collect-traffic",
            "--config",
            "servers.yml",
            "--server",
            "debian-vps-1",
            "--db",
            "data/amneziya.sqlite3",
            "--dry-run",
        ]
    )

    assert args.command == "server"
    assert args.server_command == "collect-traffic"
    assert args.db == "data/amneziya.sqlite3"
    assert args.dry_run is True


def test_run_server_traffic_collection_dry_run_prints_read_only_command(tmp_path):
    path = tmp_path / "servers.yml"
    path.write_text(VALID_YAML, encoding="utf-8")
    config = load_server_config(path)
    server = select_server(config, "debian-vps-1")

    output = run_server_traffic_collection_dry_run(server)

    assert "Dry-run traffic collection" in output
    assert "awg show awg0 dump" in output
    assert "No changes will be made" in output


def test_run_server_traffic_collection_dry_run_prints_docker_pending_command(tmp_path):
    path = tmp_path / "servers.yml"
    path.write_text(DOCKER_YAML, encoding="utf-8")
    config = load_server_config(path)
    server = select_server(config, "debian-vps-1")

    output = run_server_traffic_collection_dry_run(server)

    assert "Dry-run traffic collection" in output
    assert "docker exec amnezia-awg awg show awg0 dump" in output
    assert "Known peers will be stored in the local database" in output
    assert "No changes will be made" in output


def test_run_server_traffic_collection_accepts_docker_runtime(tmp_path, monkeypatch):
    path = tmp_path / "servers.yml"
    path.write_text(DOCKER_YAML, encoding="utf-8")
    config = load_server_config(path)
    server = select_server(config, "debian-vps-1")
    monkeypatch.setattr(
        "app.cli.SystemSshClient",
        lambda server: RecordingSshClient("awg0\tserver-public\tserver-private\t51820\toff\n"),
    )

    output = run_server_traffic_collection(server, db_path=tmp_path / "amneziya.sqlite3")

    assert "Traffic collection stored snapshots: 0" in output
    assert "Unknown peers: 0" in output


def test_cli_accepts_server_sync_peers_arguments():
    parser = build_parser()

    args = parser.parse_args(
        [
            "server",
            "sync-peers",
            "--config",
            "servers.yml",
            "--server",
            "debian-vps-1",
            "--db",
            "data/amneziya.sqlite3",
        ]
    )

    assert args.command == "server"
    assert args.server_command == "sync-peers"
    assert args.db == "data/amneziya.sqlite3"


def test_run_server_peer_sync_reports_known_unknown_and_missing(tmp_path, monkeypatch):
    path = tmp_path / "servers.yml"
    db_path = tmp_path / "amneziya.sqlite3"
    path.write_text(DOCKER_YAML, encoding="utf-8")
    config = load_server_config(path)
    server = select_server(config, "debian-vps-1")
    _seed_known_peer(db_path, server)
    monkeypatch.setattr(
        "app.cli.SystemSshClient",
        lambda server: RecordingSshClient(
            "\n".join(
                [
                    "awg0\tserver-public\tserver-private\t51820\toff",
                    "known-peer\tpsk\t203.0.113.20:50000\t10.8.0.2/32\t1700000000\t1024\t2048\t25",
                    "unknown-peer\tpsk\t(none)\t10.8.0.3/32\t0\t0\t0\toff",
                ]
            )
        ),
    )

    output = run_server_peer_sync(server, db_path=db_path)

    assert "Peer sync report: debian-vps-1" in output
    assert "known remote peers: 1" in output
    assert "unknown remote peers: 1" in output
    assert "missing local peers: 0" in output
    assert "unknown-peer 10.8.0.3/32" in output


def test_cli_accepts_server_preflight_arguments():
    parser = build_parser()

    args = parser.parse_args(
        [
            "server",
            "preflight",
            "--config",
            "servers.yml",
            "--server",
            "debian-vps-1",
            "--db",
            "data/amneziya.sqlite3",
        ]
    )

    assert args.command == "server"
    assert args.server_command == "preflight"
    assert args.config == "servers.yml"
    assert args.server == "debian-vps-1"
    assert args.db == "data/amneziya.sqlite3"


def test_cli_accepts_server_retest_plan_arguments():
    parser = build_parser()

    args = parser.parse_args(
        [
            "server",
            "retest-plan",
            "--config",
            "servers.yml",
            "--server",
            "debian-vps-1",
            "--db",
            "data/amneziya.sqlite3",
        ]
    )

    assert args.command == "server"
    assert args.server_command == "retest-plan"
    assert args.config == "servers.yml"
    assert args.server == "debian-vps-1"
    assert args.db == "data/amneziya.sqlite3"


def test_run_server_preflight_reports_local_readiness(tmp_path):
    path = tmp_path / "servers.yml"
    db_path = tmp_path / "amneziya.sqlite3"
    path.write_text(
        VALID_YAML.replace(
            "allowed_ips: 0.0.0.0/0",
            "allowed_ips: 0.0.0.0/0\n      server_public_key: real-server-public-key",
        ),
        encoding="utf-8",
    )

    output = run_server_preflight(
        config_path=path,
        server_name="debian-vps-1",
        db_path=db_path,
    )

    assert "Preflight report: debian-vps-1" in output
    assert "server config: ok" in output
    assert "database sync: ok" in output
    assert "server check dry-run: ok" in output
    assert "peer apply dry-run: ok" in output
    assert "peer revoke dry-run: ok" in output
    assert "traffic dry-run: ok" in output
    assert "backup target: ok" in output
    assert "VPS_APPLY_ENABLED=false" in output


def test_run_server_retest_plan_prints_safe_vps_sequence(tmp_path):
    path = tmp_path / "servers.yml"
    db_path = tmp_path / "amneziya.sqlite3"
    path.write_text(DOCKER_YAML, encoding="utf-8")

    assert hasattr(cli, "run_server_retest_plan")
    output = cli.run_server_retest_plan(
        config_path=path,
        server_name="debian-vps-1",
        db_path=db_path,
    )

    assert "VPS retest plan: debian-vps-1" in output
    assert "git pull origin codex-vps-test-prep" in output
    assert "python -m app.cli server preflight" in output
    assert f"--config {path}" in output
    assert "--server debian-vps-1" in output
    assert f"--db {db_path}" in output
    assert "python -m app.cli server check" in output
    assert "python -m app.cli server sync-peers" in output
    assert "python -m app.cli api serve --host 127.0.0.1 --port 3040" in output
    assert "python -m app.cli api smoke-cycle" in output
    assert "checked_routes: 6" in output
    assert "raw token is hidden and revoked automatically" in output
    assert "export API_TOKEN" not in output
    assert "python -m app.cli api token issue" not in output
    assert "python -m app.cli api smoke-check" not in output
    assert "python -m app.cli api token revoke" not in output
    assert "VPS_APPLY_ENABLED=false" in output
    assert "runtime: docker" in output
    assert "container: amnezia-awg" in output
    assert "config_path: /opt/amnezia/awg/awg0.conf" in output
    assert "approve one test order" in output


class RecordingSshClient:
    def __init__(self, stdout: str):
        self.calls = []
        self._stdout = stdout

    def run(self, command: str, stdin: str | None = None):
        from app.server.ssh import CommandResult

        self.calls.append((command, stdin))
        return CommandResult(exit_code=0, stdout=self._stdout, stderr="")


def _seed_known_peer(db_path, server):
    conn = connect(db_path)
    initialize_schema(conn)
    repo = Repository(conn)
    server_id = repo.upsert_server_config(
        name=server.name,
        host=server.ssh.host,
        ssh_port=server.ssh.port,
        endpoint_host=server.vpn.endpoint_host,
        vpn_port=int(server.vpn.port),
        vpn_network_cidr=server.vpn.network_cidr,
        server_address=server.vpn.server_address,
        server_public_key=server.vpn.server_public_key or "",
        runtime=server.runtime.type,
        firewall=server.firewall.provider,
        max_devices=server.vpn.max_devices,
    )
    user_id = repo.upsert_user(
        telegram_id=1001,
        username="known",
        first_name="Known",
        last_name=None,
    )
    repo.create_device(
        user_id=user_id,
        server_id=server_id,
        name="known-device",
        duration_days=7,
        vpn_ip="10.8.0.2",
        peer_public_key="known-peer",
        peer_private_key_encrypted="v1:encrypted-private",
        preshared_key_encrypted="v1:encrypted-psk",
        config_version="amneziawg_v2",
    )
