from dataclasses import dataclass
import ipaddress
import shlex

from app.security.redaction import redact
from app.server.ssh import SshClient, SystemSshClient
from app.server_config.models import ServerConfig


@dataclass(frozen=True)
class PeerApplyInput:
    public_key: str
    preshared_key: str
    vpn_ip: str


class PeerApplyError(RuntimeError):
    pass


class ServerConfigPeerApplier:
    def __init__(
        self,
        server: ServerConfig,
        *,
        ssh_client: SshClient | None = None,
        password: str | None = None,
    ) -> None:
        self._server = server
        self._ssh_client = ssh_client or SystemSshClient(server, password=password)

    def apply_peer(
        self,
        *,
        server,
        peer_public_key: str,
        preshared_key: str,
        vpn_ip: str,
    ) -> None:
        apply_peer(
            self._server,
            PeerApplyInput(
                public_key=peer_public_key,
                preshared_key=preshared_key,
                vpn_ip=vpn_ip,
            ),
            ssh_client=self._ssh_client,
        )

    def remove_peer(self, *, server, peer_public_key: str) -> None:
        revoke_peer(self._server, peer_public_key, ssh_client=self._ssh_client)

    def list_allocated_ips(self, *, server) -> list[str]:
        return list_allocated_ips(self._server, ssh_client=self._ssh_client)


def build_peer_apply_dry_run(server: ServerConfig, peer: PeerApplyInput) -> str:
    if server.runtime.type == "docker":
        return _build_docker_peer_apply_dry_run(server, peer)

    commands = [
        (
            f"awg set {server.vpn.interface} "
            f"peer {peer.public_key} "
            "preshared-key <redacted-psk-file> "
            f"allowed-ips {peer.vpn_ip}/32"
        ),
        f"systemctl reload {server.runtime.service_name}",
    ]
    lines = [
        f"Dry-run peer apply: {redact(server.name)}",
        "No changes will be made.",
        f"Target: ssh {server.ssh.user}@{redact(server.ssh.host)} -p {server.ssh.port}",
        "Planned commands:",
    ]
    lines.extend(f"- {redact(command)}" for command in commands)
    return "\n".join(lines)


def build_peer_revoke_dry_run(server: ServerConfig, peer_public_key: str) -> str:
    if server.runtime.type == "docker":
        return _build_docker_peer_revoke_dry_run(server, peer_public_key)

    commands = [
        (
            f"awg set {server.vpn.interface} "
            f"peer {peer_public_key} "
            "remove"
        ),
        f"systemctl reload {server.runtime.service_name}",
    ]
    lines = [
        f"Dry-run peer revoke: {redact(server.name)}",
        "No changes will be made.",
        f"Target: ssh {server.ssh.user}@{redact(server.ssh.host)} -p {server.ssh.port}",
        "Planned commands:",
    ]
    lines.extend(f"- {redact(command)}" for command in commands)
    return "\n".join(lines)


def apply_peer(server: ServerConfig, peer: PeerApplyInput, *, ssh_client: SshClient) -> str:
    if server.runtime.type == "docker":
        return _apply_docker_peer(server, peer, ssh_client=ssh_client)
    command = _build_apply_command(server, peer)
    result = ssh_client.run(command, stdin=f"{peer.preshared_key}\n")
    if result.exit_code != 0:
        stdout = result.stdout.replace(peer.preshared_key, "[REDACTED]")
        stderr = result.stderr.replace(peer.preshared_key, "[REDACTED]")
        raise PeerApplyError(
            redact(
                "Peer apply failed "
                f"(exit_code={result.exit_code}). "
                f"stdout={stdout!r} stderr={stderr!r}"
            )
        )
    return redact(f"Peer apply succeeded: {server.name} {peer.public_key} {peer.vpn_ip}/32")


def revoke_peer(
    server: ServerConfig,
    peer_public_key: str,
    *,
    ssh_client: SshClient,
) -> str:
    if server.runtime.type == "docker":
        return _revoke_docker_peer(server, peer_public_key, ssh_client=ssh_client)
    command = _build_revoke_command(server, peer_public_key)
    result = ssh_client.run(command)
    if result.exit_code != 0:
        raise PeerApplyError(
            redact(
                "Peer revoke failed "
                f"(exit_code={result.exit_code}). "
                f"stdout={result.stdout!r} stderr={result.stderr!r}"
            )
        )
    return redact(f"Peer revoke succeeded: {server.name} {peer_public_key}")


def list_allocated_ips(server: ServerConfig, *, ssh_client: SshClient) -> list[str]:
    if server.runtime.type != "docker":
        return []
    config_path = _require_docker_config_path(server)
    config_text = _read_docker_config(server, config_path, ssh_client=ssh_client)
    return _docker_config_peer_allowed_ips(config_text)


def _build_apply_command(server: ServerConfig, peer: PeerApplyInput) -> str:
    interface = shlex.quote(server.vpn.interface)
    public_key = shlex.quote(peer.public_key)
    allowed_ips = shlex.quote(f"{peer.vpn_ip}/32")
    service_name = shlex.quote(_require_service_name(server))
    return (
        "set -e; "
        'psk_file="$(mktemp)"; '
        'trap \'rm -f "$psk_file"\' EXIT; '
        'chmod 600 "$psk_file"; '
        'cat > "$psk_file"; '
        f"awg set {interface} peer {public_key} "
        'preshared-key "$psk_file" '
        f"allowed-ips {allowed_ips}; "
        f"systemctl reload {service_name}"
    )


def _build_revoke_command(server: ServerConfig, peer_public_key: str) -> str:
    interface = shlex.quote(server.vpn.interface)
    public_key = shlex.quote(peer_public_key)
    service_name = shlex.quote(_require_service_name(server))
    return (
        "set -e; "
        f"awg set {interface} peer {public_key} remove; "
        f"systemctl reload {service_name}"
    )


def _build_docker_peer_apply_dry_run(server: ServerConfig, peer: PeerApplyInput) -> str:
    container = server.runtime.container_name or "<missing-container>"
    config_path = server.runtime.config_path or "<missing-config-path>"
    return "\n".join(
        [
            f"Dry-run peer apply: {redact(server.name)}",
            "No changes will be made.",
            f"Target: ssh {server.ssh.user}@{redact(server.ssh.host)} -p {server.ssh.port}",
            f"Container: {redact(container)}",
            "Peer will be written to persistent config, then the Docker container will be restarted.",
            "Planned commands:",
            f"- docker exec {container} cat {config_path}",
            f"- docker exec -i {container} sh -c 'cat > \"$1\"' sh {config_path}",
            f"- docker restart {container}",
            f"Peer: {redact(peer.public_key)} allowed-ips {redact(peer.vpn_ip)}/32",
        ]
    )


def _build_docker_peer_revoke_dry_run(server: ServerConfig, peer_public_key: str) -> str:
    container = server.runtime.container_name or "<missing-container>"
    config_path = server.runtime.config_path or "<missing-config-path>"
    return "\n".join(
        [
            f"Dry-run peer revoke: {redact(server.name)}",
            "No changes will be made.",
            f"Target: ssh {server.ssh.user}@{redact(server.ssh.host)} -p {server.ssh.port}",
            f"Container: {redact(container)}",
            "Peer will be removed from persistent config, then the Docker container will be restarted.",
            "Planned commands:",
            f"- docker exec {container} cat {config_path}",
            f"- docker exec -i {container} sh -c 'cat > \"$1\"' sh {config_path}",
            f"- docker restart {container}",
            f"Peer: {redact(peer_public_key)}",
        ]
    )


def _require_service_name(server: ServerConfig) -> str:
    if not server.runtime.service_name:
        raise PeerApplyError("host_systemd runtime requires runtime.service_name")
    return server.runtime.service_name


def _apply_docker_peer(
    server: ServerConfig,
    peer: PeerApplyInput,
    *,
    ssh_client: SshClient,
) -> str:
    config_path = _require_docker_config_path(server)
    config_text = _read_docker_config(server, config_path, ssh_client=ssh_client)
    _validate_docker_config_network(server, config_text, peer)
    next_config = _upsert_peer_block(config_text, peer)
    _write_docker_config(server, config_path, next_config, ssh_client=ssh_client)
    _restart_docker_container(server, ssh_client=ssh_client)
    return redact(
        f"Peer apply succeeded: {server.name} {peer.public_key} {peer.vpn_ip}/32 "
        f"(Docker container restarted)"
    )


def _revoke_docker_peer(
    server: ServerConfig,
    peer_public_key: str,
    *,
    ssh_client: SshClient,
) -> str:
    config_path = _require_docker_config_path(server)
    config_text = _read_docker_config(server, config_path, ssh_client=ssh_client)
    next_config, _removed = _remove_peer_block(config_text, peer_public_key)
    _write_docker_config(server, config_path, next_config, ssh_client=ssh_client)
    _restart_docker_container(server, ssh_client=ssh_client)
    return redact(
        f"Peer revoke succeeded: {server.name} {peer_public_key} "
        f"(Docker container restarted)"
    )


def _read_docker_config(
    server: ServerConfig,
    config_path: str,
    *,
    ssh_client: SshClient,
) -> str:
    command = f"docker exec {_docker_container(server)} cat {shlex.quote(config_path)}"
    result = ssh_client.run(command)
    if result.exit_code != 0:
        raise PeerApplyError(
            redact(
                "Docker config read failed "
                f"(exit_code={result.exit_code}). "
                f"stdout={_stream_status(result.stdout)} "
                f"stderr={result.stderr!r}"
            )
        )
    return result.stdout


def _validate_docker_config_network(
    server: ServerConfig,
    config_text: str,
    peer: PeerApplyInput,
) -> None:
    actual_network = _docker_config_interface_network(config_text)
    expected_network = ipaddress.ip_network(server.vpn.network_cidr, strict=False)
    peer_ip = ipaddress.ip_address(peer.vpn_ip)

    if actual_network != expected_network:
        raise PeerApplyError(
            "Docker config network mismatch: "
            f"runtime.config_path Address is {actual_network}, "
            f"servers.yml vpn.network_cidr is {expected_network}. "
            "Refusing to add peer until server config matches live AmneziaWG network."
        )
    if peer_ip not in actual_network:
        raise PeerApplyError(
            "Peer IP is outside live AmneziaWG network: "
            f"{peer.vpn_ip} not in {actual_network}"
        )


def _docker_config_interface_network(config_text: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    in_interface = False
    for raw_line in config_text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            section_name = stripped.strip("[]").strip().lower()
            in_interface = section_name == "interface"
            continue
        if not in_interface or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        if key.strip().lower() != "address":
            continue
        first_address = value.split(",", 1)[0].strip()
        try:
            return ipaddress.ip_interface(first_address).network
        except ValueError as exc:
            raise PeerApplyError(
                f"Docker config Address is invalid: {first_address}"
            ) from exc
    raise PeerApplyError("Docker config Address is missing in [Interface]")


def _docker_config_peer_allowed_ips(config_text: str) -> list[str]:
    allocated_ips: list[str] = []
    for block in _split_config_blocks(config_text):
        if not _is_peer_block(block):
            continue
        for line in block:
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, value = stripped.split("=", 1)
            if key.strip().lower() != "allowedips":
                continue
            first_allowed_ip = value.split(",", 1)[0].strip()
            try:
                ipaddress.ip_interface(first_allowed_ip)
            except ValueError as exc:
                raise PeerApplyError(
                    f"Docker config peer AllowedIPs is invalid: {first_allowed_ip}"
                ) from exc
            allocated_ips.append(first_allowed_ip)
            break
    return allocated_ips


def _write_docker_config(
    server: ServerConfig,
    config_path: str,
    config_text: str,
    *,
    ssh_client: SshClient,
) -> None:
    command = (
        f"docker exec -i {_docker_container(server)} "
        f"sh -c {shlex.quote('cat > \"$1\"')} sh {shlex.quote(config_path)}"
    )
    result = ssh_client.run(command, stdin=_ensure_trailing_newline(config_text))
    if result.exit_code != 0:
        raise PeerApplyError(
            redact(
                "Docker config write failed "
                f"(exit_code={result.exit_code}). "
                f"stdout={_stream_status(result.stdout)} "
                f"stderr={result.stderr!r}"
            )
        )


def _restart_docker_container(server: ServerConfig, *, ssh_client: SshClient) -> None:
    command = f"docker restart {_docker_container(server)}"
    result = ssh_client.run(command)
    if result.exit_code != 0:
        raise PeerApplyError(
            redact(
                "Docker container restart failed "
                f"(exit_code={result.exit_code}). "
                f"stdout={_stream_status(result.stdout)} "
                f"stderr={result.stderr!r}"
            )
        )


def _upsert_peer_block(config_text: str, peer: PeerApplyInput) -> str:
    without_peer, _removed = _remove_peer_block(config_text, peer.public_key)
    prefix = without_peer.rstrip()
    if prefix:
        prefix += "\n\n"
    return (
        prefix
        + "[Peer]\n"
        + f"PublicKey = {peer.public_key}\n"
        + f"PresharedKey = {peer.preshared_key}\n"
        + f"AllowedIPs = {peer.vpn_ip}/32\n"
    )


def _remove_peer_block(config_text: str, peer_public_key: str) -> tuple[str, bool]:
    blocks = _split_config_blocks(config_text)
    kept: list[list[str]] = []
    removed = False
    for block in blocks:
        if _is_peer_block(block) and _peer_block_public_key(block) == peer_public_key:
            removed = True
            continue
        kept.append(block)
    return _join_config_blocks(kept), removed


def _split_config_blocks(config_text: str) -> list[list[str]]:
    blocks: list[list[str]] = []
    current: list[str] = []
    for line in config_text.splitlines():
        if line.strip().lower() == "[peer]" and current:
            blocks.append(current)
            current = [line]
            continue
        current.append(line)
    if current:
        blocks.append(current)
    return blocks


def _join_config_blocks(blocks: list[list[str]]) -> str:
    return "\n".join("\n".join(block).rstrip() for block in blocks if block).rstrip() + "\n"


def _is_peer_block(block: list[str]) -> bool:
    return bool(block) and block[0].strip().lower() == "[peer]"


def _peer_block_public_key(block: list[str]) -> str | None:
    for line in block:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        if key.strip().lower() == "publickey":
            return value.strip()
    return None


def _require_docker_config_path(server: ServerConfig) -> str:
    if not server.runtime.config_path:
        raise PeerApplyError(
            "docker runtime requires runtime.config_path for peer apply/revoke"
        )
    return server.runtime.config_path


def _docker_container(server: ServerConfig) -> str:
    if not server.runtime.container_name:
        raise PeerApplyError("docker runtime requires runtime.container_name")
    return shlex.quote(server.runtime.container_name)


def _ensure_trailing_newline(value: str) -> str:
    if value.endswith("\n"):
        return value
    return value + "\n"


def _stream_status(value: str) -> str:
    return "present" if value else "empty"
