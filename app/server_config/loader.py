import ipaddress
from pathlib import Path
import re
from typing import Any

import yaml

from app.server_config.models import (
    FirewallConfig,
    RuntimeConfig,
    ServerConfig,
    ServersConfig,
    SshAuthConfig,
    SshConfig,
    VpnConfig,
)


class ConfigError(ValueError):
    pass


_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9_.@:-]+$")


def load_server_config(path: str | Path) -> ServersConfig:
    config_path = Path(path)
    if not config_path.is_file():
        raise ConfigError(f"Server config not found: {config_path}")
    data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("servers"), list):
        raise ConfigError("servers.yml must contain a servers list")
    _reject_placeholders(data)
    return ServersConfig(servers=[_parse_server(item) for item in data["servers"]])


def select_server(config: ServersConfig, name: str) -> ServerConfig:
    for server in config.servers:
        if server.name == name:
            return server
    available = ", ".join(server.name for server in config.servers) or "<none>"
    raise ConfigError(f"Server '{name}' not found. Available: {available}")


def _parse_server(item: Any) -> ServerConfig:
    if not isinstance(item, dict):
        raise ConfigError("Each server entry must be an object")
    ssh = _required_dict(item, "ssh")
    auth = _required_dict(ssh, "auth")
    vpn = _required_dict(item, "vpn")
    firewall = _required_dict(item, "firewall")
    runtime = _required_dict(item, "runtime")
    return ServerConfig(
        name=_parse_required_identifier(item, "name", field_name="server.name"),
        enabled=bool(_required(item, "enabled")),
        location=_parse_required_identifier(item, "location", field_name="server.location"),
        ssh=SshConfig(
            host=_parse_required_host(ssh, "host", field_name="ssh.host"),
            port=_parse_required_port(ssh, "port", field_name="ssh.port"),
            user=str(_required(ssh, "user")),
            auth=SshAuthConfig(
                type=str(_required(auth, "type")),
                private_key_path=None if auth.get("private_key_path") is None else str(auth["private_key_path"]),
            ),
        ),
        vpn=VpnConfig(
            endpoint_host=_parse_required_host(vpn, "endpoint_host", field_name="vpn.endpoint_host"),
            port=_parse_required_port(vpn, "port", field_name="vpn.port", allow_auto=True),
            interface=_parse_required_identifier(vpn, "interface", field_name="vpn.interface"),
            network_cidr=_effective_network_cidr(vpn),
            server_address=_parse_required_ip_or_interface(vpn, "server_address", field_name="vpn.server_address"),
            dns=_parse_required_ip_address(vpn, "dns", field_name="vpn.dns"),
            allowed_ips=_parse_required_ip_network(vpn, "allowed_ips", field_name="vpn.allowed_ips"),
            max_devices=_parse_required_positive_int(vpn, "max_devices", field_name="vpn.max_devices"),
            server_public_key=(
                None
                if vpn.get("server_public_key") is None
                else str(vpn["server_public_key"])
            ),
        ),
        firewall=FirewallConfig(
            provider=str(_required(firewall, "provider")),
            open_vpn_port=bool(_required(firewall, "open_vpn_port")),
        ),
        runtime=_parse_runtime(runtime),
    )


def _parse_required_port(
    data: dict[str, Any],
    key: str,
    *,
    field_name: str,
    allow_auto: bool = False,
) -> int | str:
    value = _required(data, key)
    if value == "auto":
        if allow_auto:
            return "auto"
        raise ConfigError(f"{field_name} must be between 1 and 65535")
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{field_name} must be between 1 and 65535") from exc
    if not 1 <= port <= 65535:
        raise ConfigError(f"{field_name} must be between 1 and 65535")
    return port


def _parse_required_positive_int(data: dict[str, Any], key: str, *, field_name: str) -> int:
    value = _required(data, key)
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{field_name} must be greater than 0") from exc
    if parsed < 1:
        raise ConfigError(f"{field_name} must be greater than 0")
    return parsed


def _parse_required_host(data: dict[str, Any], key: str, *, field_name: str) -> str:
    host = str(_required(data, key)).strip()
    if not host or any(char.isspace() for char in host) or "://" in host or "/" in host:
        raise ConfigError(f"{field_name} must be a host name or IP address")
    return host


def _parse_required_identifier(data: dict[str, Any], key: str, *, field_name: str) -> str:
    value = str(_required(data, key)).strip()
    if not value or not _IDENTIFIER_RE.fullmatch(value) or ".." in value:
        raise ConfigError(f"{field_name} must be a non-empty identifier")
    return value


def _optional_runtime_config_path(data: dict[str, Any], key: str) -> str | None:
    path = _optional_str(data, key)
    if path is None:
        return None
    if not path.startswith("/") or any(char in path for char in ("\n", "\r", "\x00")):
        raise ConfigError("runtime.config_path must be an absolute POSIX path")
    return path


def _parse_required_ip_network(data: dict[str, Any], key: str, *, field_name: str) -> str:
    value = str(_required(data, key)).strip()
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError as exc:
        raise ConfigError(f"{field_name} must be an IP network") from exc


def _parse_required_ip_address(data: dict[str, Any], key: str, *, field_name: str) -> str:
    value = str(_required(data, key)).strip()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ConfigError(f"{field_name} must be an IP address") from exc


def _parse_required_ip_or_interface(data: dict[str, Any], key: str, *, field_name: str) -> str:
    value = str(_required(data, key)).strip()
    try:
        if "/" in value:
            return str(ipaddress.ip_interface(value))
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ConfigError(f"{field_name} must be an IP address or interface") from exc


def _effective_network_cidr(vpn: dict[str, Any]) -> str:
    configured_network = _parse_required_ip_network(vpn, "network_cidr", field_name="vpn.network_cidr")
    server_address = _parse_required_ip_or_interface(vpn, "server_address", field_name="vpn.server_address")
    if "/" not in server_address:
        return configured_network
    interface = ipaddress.ip_interface(server_address)
    if interface.network.prefixlen == interface.max_prefixlen:
        return configured_network
    return str(interface.network)


def _parse_runtime(runtime: dict[str, Any]) -> RuntimeConfig:
    runtime_type = str(_required(runtime, "type"))
    if runtime_type == "host_systemd":
        return RuntimeConfig(
            type=runtime_type,
            service_name=_parse_required_identifier(runtime, "service_name", field_name="runtime.service_name"),
            container_name=_optional_str(runtime, "container_name"),
            config_path=_optional_runtime_config_path(runtime, "config_path"),
        )
    if runtime_type in {"docker", "xray_docker"}:
        return RuntimeConfig(
            type=runtime_type,
            service_name=_optional_str(runtime, "service_name"),
            container_name=_parse_required_identifier(runtime, "container_name", field_name="runtime.container_name"),
            config_path=_optional_runtime_config_path(runtime, "config_path"),
        )
    raise ConfigError(f"Unsupported runtime type: {runtime_type}")


def _optional_str(data: dict[str, Any], key: str) -> str | None:
    if data.get(key) is None:
        return None
    return str(data[key])


def _required(data: dict[str, Any], key: str) -> Any:
    if key not in data:
        raise ConfigError(f"Missing required field: {key}")
    return data[key]


def _required_dict(data: dict[str, Any], key: str) -> dict[str, Any]:
    value = _required(data, key)
    if not isinstance(value, dict):
        raise ConfigError(f"Field must be an object: {key}")
    return value


def _reject_placeholders(value: Any) -> None:
    if isinstance(value, dict):
        for child in value.values():
            _reject_placeholders(child)
    elif isinstance(value, list):
        for child in value:
            _reject_placeholders(child)
    elif isinstance(value, str) and value.startswith("CHANGE_ME"):
        raise ConfigError("Server config contains placeholder values")
