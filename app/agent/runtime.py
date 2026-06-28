from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Literal, Protocol

from app.server_config.models import ServerConfig


RuntimeStatus = Literal["running", "degraded", "stopped", "unknown"]
ProtocolStatus = Literal["running", "degraded", "stopped", "unknown"]


@dataclass(frozen=True)
class ProtocolSnapshot:
    name: str
    status: ProtocolStatus
    runtime_type: str
    capabilities: tuple[str, ...]
    container_name: str | None = None
    interface: str | None = None
    client_count: int | None = None


@dataclass(frozen=True)
class RuntimeSnapshot:
    server_name: str
    runtime_type: str
    status: RuntimeStatus
    protocols: tuple[ProtocolSnapshot, ...]


class LocalRuntimeAdapter(Protocol):
    def snapshot(self) -> RuntimeSnapshot:
        pass


@dataclass(frozen=True)
class CommandResult:
    exit_code: int
    stdout: str
    stderr: str


class CommandRunner(Protocol):
    def run(self, args: tuple[str, ...]) -> CommandResult:
        pass


class LocalSystemCommandRunner:
    def run(self, args: tuple[str, ...]) -> CommandResult:
        try:
            completed = subprocess.run(
                args,
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return CommandResult(exit_code=1, stdout="", stderr=str(exc))

        return CommandResult(
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )


class LocalCommandRuntimeAdapter:
    def __init__(
        self,
        server: ServerConfig,
        runner: CommandRunner | None = None,
    ) -> None:
        self._server = server
        self._runner = runner or LocalSystemCommandRunner()

    def snapshot(self) -> RuntimeSnapshot:
        if self._server.runtime.type == "docker":
            protocol = self._docker_snapshot()
        elif self._server.runtime.type == "xray_docker":
            protocol = self._xray_docker_snapshot()
        elif self._server.runtime.type == "host_systemd":
            protocol = self._host_systemd_snapshot()
        else:
            protocol = self._protocol_snapshot(status="unknown")

        return RuntimeSnapshot(
            server_name=self._server.name,
            runtime_type=self._server.runtime.type,
            status=protocol.status,
            protocols=(protocol,),
        )

    def _docker_snapshot(self) -> ProtocolSnapshot:
        container_name = self._server.runtime.container_name
        docker_ps = self._runner.run(("docker", "ps", "--format", "{{.Names}}"))

        if docker_ps.exit_code != 0 or container_name is None:
            return self._protocol_snapshot(status="stopped", container_name=container_name)

        containers = {line.strip() for line in docker_ps.stdout.splitlines() if line.strip()}
        if container_name not in containers:
            return self._protocol_snapshot(status="stopped", container_name=container_name)

        dump = self._runner.run(
            ("docker", "exec", container_name, "awg", "show", self._server.vpn.interface, "dump")
        )
        if dump.exit_code != 0:
            return self._protocol_snapshot(status="degraded", container_name=container_name)

        return self._protocol_snapshot(
            status="running",
            container_name=container_name,
            client_count=_count_dump_peers(dump.stdout),
        )

    def _xray_docker_snapshot(self) -> ProtocolSnapshot:
        container_name = self._server.runtime.container_name
        docker_ps = self._runner.run(("docker", "ps", "--format", "{{.Names}}"))

        if docker_ps.exit_code != 0 or container_name is None:
            return self._protocol_snapshot(
                name="xray",
                status="stopped",
                container_name=container_name,
                capabilities=("detect", "status", "validation"),
                include_interface=False,
            )

        containers = {line.strip() for line in docker_ps.stdout.splitlines() if line.strip()}
        status: ProtocolStatus = "running" if container_name in containers else "stopped"
        return self._protocol_snapshot(
            name="xray",
            status=status,
            container_name=container_name,
            capabilities=("detect", "status", "validation"),
            include_interface=False,
        )

    def _host_systemd_snapshot(self) -> ProtocolSnapshot:
        service_name = self._server.runtime.service_name or f"awg-quick@{self._server.vpn.interface}"
        service_status = self._runner.run(("systemctl", "is-active", service_name))

        if service_status.exit_code != 0 or service_status.stdout.strip() != "active":
            return self._protocol_snapshot(status="stopped")

        dump = self._runner.run(("awg", "show", self._server.vpn.interface, "dump"))
        if dump.exit_code != 0:
            return self._protocol_snapshot(status="degraded")

        return self._protocol_snapshot(
            status="running",
            client_count=_count_dump_peers(dump.stdout),
        )

    def _protocol_snapshot(
        self,
        *,
        name: str = "amneziawg",
        status: ProtocolStatus,
        container_name: str | None = None,
        capabilities: tuple[str, ...] = ("detect", "status"),
        include_interface: bool = True,
        client_count: int | None = None,
    ) -> ProtocolSnapshot:
        return ProtocolSnapshot(
            name=name,
            status=status,
            runtime_type=self._server.runtime.type,
            capabilities=capabilities,
            container_name=container_name,
            interface=self._server.vpn.interface if include_interface else None,
            client_count=client_count,
        )


class FakeLocalRuntimeAdapter:
    def __init__(self, snapshot: RuntimeSnapshot | None = None) -> None:
        self._snapshot = snapshot or RuntimeSnapshot(
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

    def snapshot(self) -> RuntimeSnapshot:
        return self._snapshot


def _count_dump_peers(output: str) -> int:
    lines = [line for line in output.splitlines() if line.strip()]
    return max(len(lines) - 1, 0)
