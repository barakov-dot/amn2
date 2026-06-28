from app.agent.runtime import (
    CommandResult,
    FakeLocalRuntimeAdapter,
    LocalCommandRuntimeAdapter,
    ProtocolSnapshot,
    RuntimeSnapshot,
)
from app.server_config.models import (
    FirewallConfig,
    RuntimeConfig,
    ServerConfig,
    SshAuthConfig,
    SshConfig,
    VpnConfig,
)


class FakeCommandRunner:
    def __init__(self, results):
        self.results = results
        self.calls = []

    def run(self, args):
        self.calls.append(args)
        return self.results[args]


def _server(runtime):
    return ServerConfig(
        name="debian-vps-1",
        enabled=True,
        location="default",
        ssh=SshConfig(
            host="127.0.0.1",
            port=22,
            user="root",
            auth=SshAuthConfig(type="key", private_key_path=None),
        ),
        vpn=VpnConfig(
            endpoint_host="127.0.0.1",
            port=30001,
            interface="awg0",
            network_cidr="10.8.1.0/24",
            server_address="10.8.1.1/24",
            dns="1.1.1.1",
            allowed_ips="0.0.0.0/0",
            max_devices=254,
            server_public_key="server-public-key",
        ),
        firewall=FirewallConfig(provider="ufw", open_vpn_port=True),
        runtime=runtime,
    )


def test_fake_local_runtime_adapter_returns_default_snapshot():
    snapshot = FakeLocalRuntimeAdapter().snapshot()

    assert snapshot == RuntimeSnapshot(
        server_name="local-agent-dev",
        runtime_type="fake",
        status="running",
        protocols=(
            ProtocolSnapshot(
                name="amneziawg",
                status="unknown",
                runtime_type="fake",
                capabilities=("detect", "status"),
                container_name=None,
                interface=None,
                client_count=None,
            ),
        ),
    )


def test_fake_local_runtime_adapter_returns_custom_snapshot():
    custom = RuntimeSnapshot(
        server_name="custom-local",
        runtime_type="docker",
        status="running",
        protocols=(
            ProtocolSnapshot(
                name="xray",
                status="running",
                runtime_type="docker",
                capabilities=("detect", "status"),
                container_name="amnezia-xray",
                interface=None,
                client_count=3,
            ),
        ),
    )

    assert FakeLocalRuntimeAdapter(snapshot=custom).snapshot() == custom


def test_runtime_snapshot_repr_does_not_include_sensitive_terms():
    snapshot = RuntimeSnapshot(
        server_name="local-agent-dev",
        runtime_type="fake",
        status="running",
        protocols=(
            ProtocolSnapshot(
                name="amneziawg",
                status="unknown",
                runtime_type="fake",
                capabilities=("detect", "status"),
            ),
        ),
    )

    snapshot_repr = repr(snapshot).lower()

    for sensitive_term in (
        "privatekey",
        "private_key",
        "preshared",
        "token",
        "vpn://",
        "client_config",
        "password",
    ):
        assert sensitive_term not in snapshot_repr


def test_local_command_runtime_adapter_detects_running_docker_awg():
    runner = FakeCommandRunner(
        {
            ("docker", "ps", "--format", "{{.Names}}"): CommandResult(
                exit_code=0,
                stdout="amnezia-awg2\n",
                stderr="",
            ),
            ("docker", "exec", "amnezia-awg2", "awg", "show", "awg0", "dump"): CommandResult(
                exit_code=0,
                stdout=(
                    "awg0\tserver-public-key\tprivate\t30001\toff\n"
                    "peer-1\tpsk\tendpoint\t10.8.1.2/32\tlatest\t1\t2\t25\n"
                    "peer-2\tpsk\tendpoint\t10.8.1.3/32\tlatest\t1\t2\t25\n"
                ),
                stderr="",
            ),
        }
    )

    snapshot = LocalCommandRuntimeAdapter(
        _server(RuntimeConfig(type="docker", container_name="amnezia-awg2")),
        runner=runner,
    ).snapshot()

    assert snapshot.server_name == "debian-vps-1"
    assert snapshot.runtime_type == "docker"
    assert snapshot.status == "running"
    assert snapshot.protocols[0].status == "running"
    assert snapshot.protocols[0].container_name == "amnezia-awg2"
    assert snapshot.protocols[0].interface == "awg0"
    assert snapshot.protocols[0].client_count == 2


def test_local_command_runtime_adapter_reports_stopped_docker_container():
    runner = FakeCommandRunner(
        {
            ("docker", "ps", "--format", "{{.Names}}"): CommandResult(
                exit_code=0,
                stdout="other-container\n",
                stderr="",
            ),
        }
    )

    snapshot = LocalCommandRuntimeAdapter(
        _server(RuntimeConfig(type="docker", container_name="amnezia-awg2")),
        runner=runner,
    ).snapshot()

    assert snapshot.status == "stopped"
    assert snapshot.protocols[0].status == "stopped"
    assert snapshot.protocols[0].client_count is None


def test_local_command_runtime_adapter_detects_running_xray_docker_container():
    runner = FakeCommandRunner(
        {
            ("docker", "ps", "--format", "{{.Names}}"): CommandResult(
                exit_code=0,
                stdout="amnezia-xray\n",
                stderr="",
            ),
        }
    )

    snapshot = LocalCommandRuntimeAdapter(
        _server(RuntimeConfig(type="xray_docker", container_name="amnezia-xray")),
        runner=runner,
    ).snapshot()

    assert snapshot.runtime_type == "xray_docker"
    assert snapshot.status == "running"
    assert snapshot.protocols == (
        ProtocolSnapshot(
            name="xray",
            status="running",
            runtime_type="xray_docker",
            capabilities=("detect", "status", "validation"),
            container_name="amnezia-xray",
            interface=None,
            client_count=None,
        ),
    )


def test_local_command_runtime_adapter_reports_stopped_xray_docker_container():
    runner = FakeCommandRunner(
        {
            ("docker", "ps", "--format", "{{.Names}}"): CommandResult(
                exit_code=0,
                stdout="amnezia-awg2\n",
                stderr="",
            ),
        }
    )

    snapshot = LocalCommandRuntimeAdapter(
        _server(RuntimeConfig(type="xray_docker", container_name="amnezia-xray")),
        runner=runner,
    ).snapshot()

    assert snapshot.status == "stopped"
    assert snapshot.protocols[0].name == "xray"
    assert snapshot.protocols[0].capabilities == ("detect", "status", "validation")
    assert snapshot.protocols[0].interface is None


def test_local_command_runtime_adapter_detects_running_host_systemd():
    runner = FakeCommandRunner(
        {
            ("systemctl", "is-active", "awg-quick@awg0"): CommandResult(
                exit_code=0,
                stdout="active\n",
                stderr="",
            ),
            ("awg", "show", "awg0", "dump"): CommandResult(
                exit_code=0,
                stdout="awg0\tserver-public-key\tprivate\t30001\toff\n",
                stderr="",
            ),
        }
    )

    snapshot = LocalCommandRuntimeAdapter(
        _server(RuntimeConfig(type="host_systemd", service_name="awg-quick@awg0")),
        runner=runner,
    ).snapshot()

    assert snapshot.runtime_type == "host_systemd"
    assert snapshot.status == "running"
    assert snapshot.protocols[0].status == "running"
    assert snapshot.protocols[0].client_count == 0
