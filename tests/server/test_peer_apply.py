import pytest

from app.server.peer_apply import (
    PeerApplyError,
    PeerApplyInput,
    ServerConfigPeerApplier,
    apply_peer,
    build_peer_apply_dry_run,
    build_peer_revoke_dry_run,
    revoke_peer,
)
from app.server.ssh import CommandResult
from app.server_config.loader import load_server_config, select_server
from tests.server_config.test_loader import DOCKER_YAML
from tests.server_config.test_loader import VALID_YAML


def test_build_peer_apply_dry_run_lists_commands_without_secrets(tmp_path):
    server = _server(tmp_path)
    peer = PeerApplyInput(
        public_key="peer-public",
        preshared_key="secret-psk",
        vpn_ip="10.8.0.2",
    )

    report = build_peer_apply_dry_run(server, peer)

    assert "Dry-run peer apply" in report
    assert "awg set awg0 peer peer-public" in report
    assert "allowed-ips 10.8.0.2/32" in report
    assert "systemctl reload awg-quick@awg0" in report
    assert "secret-psk" not in report
    assert "No changes will be made" in report


def test_build_peer_apply_dry_run_includes_safe_operation_metadata(tmp_path):
    server = _server(tmp_path)
    peer = PeerApplyInput(
        public_key="peer-public",
        preshared_key="secret-psk",
        vpn_ip="10.8.0.2",
    )

    report = build_peer_apply_dry_run(server, peer)

    assert "Operation ID: server.peer.apply" in report
    assert "Risk class: remote-state-write" in report
    assert "Consistency status: dry-run" in report
    assert "Local side effects: none" in report
    assert "Remote side effects: awg-peer-add, service-reload" in report
    assert "Rollback note:" in report
    assert "secret-psk" not in report
    assert "PresharedKey" not in report


def test_build_peer_apply_dry_run_marks_docker_runtime_as_pending(tmp_path):
    server = _docker_server(tmp_path)
    peer = PeerApplyInput(
        public_key="peer-public",
        preshared_key="secret-psk",
        vpn_ip="10.8.0.2",
    )

    report = build_peer_apply_dry_run(server, peer)

    assert "docker exec amnezia-awg cat /opt/amnezia/awg/awg0.conf" in report
    assert "docker exec -i amnezia-awg sh -c" in report
    assert "docker restart amnezia-awg" in report
    assert "Peer will be written to persistent config" in report
    assert "allowed-ips 10.8.0.2/32" in report
    assert "No changes will be made" in report
    assert "systemctl reload" not in report
    assert "secret-psk" not in report


def test_apply_peer_runs_guarded_commands_without_putting_psk_in_command(tmp_path):
    server = _server(tmp_path)
    peer = PeerApplyInput(
        public_key="peer-public",
        preshared_key="secret-psk",
        vpn_ip="10.8.0.2",
    )
    ssh = RecordingSshClient()

    report = apply_peer(server, peer, ssh_client=ssh)

    assert "Peer apply succeeded" in report
    assert len(ssh.calls) == 1
    command, stdin = ssh.calls[0]
    assert "awg set awg0 peer peer-public" in command
    assert "allowed-ips 10.8.0.2/32" in command
    assert "systemctl reload awg-quick@awg0" in command
    assert "secret-psk" not in command
    assert stdin == "secret-psk\n"
    assert "secret-psk" not in report


def test_apply_peer_runs_docker_exec_without_putting_psk_in_command(tmp_path):
    server = _docker_server(tmp_path)
    peer = PeerApplyInput(
        public_key="peer-public",
        preshared_key="secret-psk",
        vpn_ip="10.8.0.2",
    )
    ssh = RecordingSshClient(
        results=[
            CommandResult(exit_code=0, stdout=_docker_config(), stderr=""),
            CommandResult(exit_code=0, stdout="", stderr=""),
            CommandResult(exit_code=0, stdout="amnezia-awg\n", stderr=""),
        ]
    )

    report = apply_peer(server, peer, ssh_client=ssh)

    assert "Peer apply succeeded" in report
    assert len(ssh.calls) == 3
    read_command, read_stdin = ssh.calls[0]
    write_command, write_stdin = ssh.calls[1]
    restart_command, restart_stdin = ssh.calls[2]
    assert read_command == "docker exec amnezia-awg cat /opt/amnezia/awg/awg0.conf"
    assert read_stdin is None
    assert write_command == "docker exec -i amnezia-awg sh -c 'cat > \"$1\"' sh /opt/amnezia/awg/awg0.conf"
    assert "PublicKey = peer-public" in write_stdin
    assert "PresharedKey = secret-psk" in write_stdin
    assert "AllowedIPs = 10.8.0.2/32" in write_stdin
    assert restart_command == "docker restart amnezia-awg"
    assert restart_stdin is None
    assert "secret-psk" not in read_command
    assert "secret-psk" not in write_command
    assert "secret-psk" not in restart_command
    assert "secret-psk" not in report


def test_apply_peer_blocks_docker_config_network_mismatch(tmp_path):
    server = _docker_server(tmp_path)
    peer = PeerApplyInput(
        public_key="peer-public",
        preshared_key="secret-psk",
        vpn_ip="10.8.0.2",
    )
    ssh = RecordingSshClient(
        results=[
            CommandResult(
                exit_code=0,
                stdout=_docker_config(address="10.8.1.0/24"),
                stderr="",
            ),
        ]
    )

    with pytest.raises(PeerApplyError) as exc_info:
        apply_peer(server, peer, ssh_client=ssh)

    assert "network mismatch" in str(exc_info.value)
    assert "10.8.1.0/24" in str(exc_info.value)
    assert "10.8.0.0/24" in str(exc_info.value)
    assert len(ssh.calls) == 1
    assert ssh.calls[0] == ("docker exec amnezia-awg cat /opt/amnezia/awg/awg0.conf", None)


def test_server_config_peer_applier_lists_allocated_ips_from_docker_config(tmp_path):
    server = _docker_server(tmp_path)
    ssh = RecordingSshClient(
        results=[
            CommandResult(
                exit_code=0,
                stdout=_docker_config_with_peer()
                + "\n".join(
                    [
                        "[Peer]",
                        "PublicKey = second-public",
                        "PresharedKey = second-psk",
                        "AllowedIPs = 10.8.0.3/32, 10.8.0.99/32",
                        "",
                    ]
                ),
                stderr="",
            ),
        ]
    )
    applier = ServerConfigPeerApplier(server, ssh_client=ssh)

    allocated_ips = applier.list_allocated_ips(server=server)

    assert allocated_ips == ["10.8.0.2/32", "10.8.0.3/32"]
    assert ssh.calls == [("docker exec amnezia-awg cat /opt/amnezia/awg/awg0.conf", None)]


def test_apply_peer_raises_redacted_error_when_remote_command_fails(tmp_path):
    server = _server(tmp_path)
    peer = PeerApplyInput(
        public_key="peer-public",
        preshared_key="secret-psk",
        vpn_ip="10.8.0.2",
    )
    ssh = RecordingSshClient(
        result=CommandResult(
            exit_code=1,
            stdout="",
            stderr="remote failed with secret-psk",
        )
    )

    with pytest.raises(PeerApplyError) as exc_info:
        apply_peer(server, peer, ssh_client=ssh)

    assert "Peer apply failed" in str(exc_info.value)
    assert "secret-psk" not in str(exc_info.value)


def test_docker_config_read_failure_redacts_secret_stderr(tmp_path):
    server = _docker_server(tmp_path)
    peer = PeerApplyInput(
        public_key="peer-public",
        preshared_key="secret-psk",
        vpn_ip="10.8.0.2",
    )
    ssh = RecordingSshClient(
        result=CommandResult(
            exit_code=1,
            stdout="[Interface]\nPrivateKey = server-private\n[Peer]\nPresharedKey = secret-psk\n",
            stderr=(
                "failed with vpn://W0ludGVyZmFjZV0K and "
                "Authorization: Bearer remote-token-value"
            ),
        )
    )

    with pytest.raises(PeerApplyError) as exc_info:
        apply_peer(server, peer, ssh_client=ssh)

    message = str(exc_info.value)
    assert "server-private" not in message
    assert "secret-psk" not in message
    assert "vpn://" not in message
    assert "remote-token-value" not in message


def test_docker_restart_failure_redacts_secret_output(tmp_path):
    server = _docker_server(tmp_path)
    peer = PeerApplyInput(
        public_key="peer-public",
        preshared_key="secret-psk",
        vpn_ip="10.8.0.2",
    )
    ssh = RecordingSshClient(
        results=[
            CommandResult(exit_code=0, stdout=_docker_config(), stderr=""),
            CommandResult(exit_code=0, stdout="", stderr=""),
            CommandResult(
                exit_code=1,
                stdout="restart failed with secret-psk",
                stderr="Authorization: Bearer docker-restart-token",
            ),
        ]
    )

    with pytest.raises(PeerApplyError) as exc_info:
        apply_peer(server, peer, ssh_client=ssh)

    message = str(exc_info.value)
    assert "secret-psk" not in message
    assert "docker-restart-token" not in message


def test_build_peer_revoke_dry_run_lists_remove_command(tmp_path):
    server = _server(tmp_path)

    report = build_peer_revoke_dry_run(server, "peer-public")

    assert "Dry-run peer revoke" in report
    assert "awg set awg0 peer peer-public remove" in report
    assert "systemctl reload awg-quick@awg0" in report
    assert "No changes will be made" in report


def test_build_peer_revoke_dry_run_includes_safe_operation_metadata(tmp_path):
    server = _server(tmp_path)

    report = build_peer_revoke_dry_run(server, "peer-public")

    assert "Operation ID: server.peer.revoke" in report
    assert "Risk class: remote-state-write" in report
    assert "Consistency status: dry-run" in report
    assert "Local side effects: none" in report
    assert "Remote side effects: awg-peer-remove, service-reload" in report
    assert "Rollback note:" in report
    assert "secret" not in report.lower()


def test_build_peer_revoke_dry_run_lists_docker_remove_command(tmp_path):
    server = _docker_server(tmp_path)

    report = build_peer_revoke_dry_run(server, "peer-public")

    assert "Dry-run peer revoke" in report
    assert "docker exec amnezia-awg cat /opt/amnezia/awg/awg0.conf" in report
    assert "docker exec -i amnezia-awg sh -c" in report
    assert "docker restart amnezia-awg" in report
    assert "Peer will be removed from persistent config" in report
    assert "systemctl reload" not in report
    assert "No changes will be made" in report


def test_revoke_peer_runs_guarded_remove_command(tmp_path):
    server = _server(tmp_path)
    ssh = RecordingSshClient()

    report = revoke_peer(server, "peer-public", ssh_client=ssh)

    assert "Peer revoke succeeded" in report
    assert len(ssh.calls) == 1
    command, stdin = ssh.calls[0]
    assert "awg set awg0 peer peer-public remove" in command
    assert "systemctl reload awg-quick@awg0" in command
    assert stdin is None


def test_revoke_peer_runs_docker_exec_remove_command(tmp_path):
    server = _docker_server(tmp_path)
    ssh = RecordingSshClient(
        results=[
            CommandResult(exit_code=0, stdout=_docker_config_with_peer(), stderr=""),
            CommandResult(exit_code=0, stdout="", stderr=""),
            CommandResult(exit_code=0, stdout="amnezia-awg\n", stderr=""),
        ]
    )

    report = revoke_peer(server, "peer-public", ssh_client=ssh)

    assert "Peer revoke succeeded" in report
    assert len(ssh.calls) == 3
    assert ssh.calls[0] == ("docker exec amnezia-awg cat /opt/amnezia/awg/awg0.conf", None)
    assert ssh.calls[1][0] == "docker exec -i amnezia-awg sh -c 'cat > \"$1\"' sh /opt/amnezia/awg/awg0.conf"
    assert "PublicKey = peer-public" not in ssh.calls[1][1]
    assert ssh.calls[2] == ("docker restart amnezia-awg", None)


def _server(tmp_path):
    path = tmp_path / "servers.yml"
    path.write_text(VALID_YAML, encoding="utf-8")
    return select_server(load_server_config(path), "debian-vps-1")


def _docker_server(tmp_path):
    path = tmp_path / "servers.yml"
    path.write_text(DOCKER_YAML, encoding="utf-8")
    return select_server(load_server_config(path), "debian-vps-1")


class RecordingSshClient:
    def __init__(self, *, result=None, results=None):
        self.calls = []
        self._result = result or CommandResult(exit_code=0, stdout="ok", stderr="")
        self._results = list(results or [])

    def run(self, command: str, stdin: str | None = None) -> CommandResult:
        self.calls.append((command, stdin))
        if self._results:
            return self._results.pop(0)
        return self._result


def _docker_config(*, address: str = "10.8.0.1/24") -> str:
    return "\n".join(
        [
            "[Interface]",
            "PrivateKey = server-private",
            f"Address = {address}",
            "ListenPort = 30001",
            "",
        ]
    )


def _docker_config_with_peer() -> str:
    return _docker_config() + "\n".join(
        [
            "[Peer]",
            "PublicKey = peer-public",
            "PresharedKey = secret-psk",
            "AllowedIPs = 10.8.0.2/32",
            "",
        ]
    )
