from pathlib import Path

import pytest

from app.server_config.loader import ConfigError, load_server_config, select_server


VALID_YAML = """
servers:
  - name: debian-vps-1
    enabled: true
    location: default
    ssh:
      host: 203.0.113.10
      port: 22
      user: root
      auth:
        type: key
        private_key_path: C:/Users/me/.ssh/id_ed25519
    vpn:
      endpoint_host: 203.0.113.10
      port: 30001
      interface: awg0
      network_cidr: 10.8.0.0/24
      server_address: 10.8.0.1/24
      dns: 1.1.1.1
      allowed_ips: 0.0.0.0/0
      max_devices: 254
    firewall:
      provider: ufw
      open_vpn_port: true
    runtime:
      type: host_systemd
      service_name: awg-quick@awg0
"""

DOCKER_YAML = """
servers:
  - name: debian-vps-1
    enabled: true
    location: default
    ssh:
      host: 203.0.113.10
      port: 22
      user: root
      auth:
        type: key
        private_key_path: C:/Users/me/.ssh/id_ed25519
    vpn:
      endpoint_host: 203.0.113.10
      port: 30001
      interface: awg0
      network_cidr: 10.8.0.0/24
      server_address: 10.8.0.1/24
      dns: 1.1.1.1
      allowed_ips: 0.0.0.0/0
      max_devices: 254
      server_public_key: server-public-key
    firewall:
      provider: ufw
      open_vpn_port: true
    runtime:
      type: docker
      container_name: amnezia-awg
      config_path: /opt/amnezia/awg/awg0.conf
"""


def test_load_server_config_reads_valid_servers_yml(tmp_path: Path):
    path = tmp_path / "servers.yml"
    path.write_text(VALID_YAML, encoding="utf-8")

    config = load_server_config(path)
    server = select_server(config, "debian-vps-1")

    assert server.name == "debian-vps-1"
    assert server.ssh.host == "203.0.113.10"
    assert server.vpn.interface == "awg0"
    assert server.runtime.service_name == "awg-quick@awg0"


def test_load_server_config_uses_server_address_prefix_as_effective_network(tmp_path: Path):
    path = tmp_path / "servers.yml"
    path.write_text(
        VALID_YAML.replace("server_address: 10.8.0.1/24", "server_address: 10.8.1.1/24"),
        encoding="utf-8",
    )

    config = load_server_config(path)
    server = select_server(config, "debian-vps-1")

    assert server.vpn.network_cidr == "10.8.1.0/24"
    assert server.vpn.server_address == "10.8.1.1/24"


def test_load_server_config_reads_docker_runtime(tmp_path: Path):
    path = tmp_path / "servers.yml"
    path.write_text(DOCKER_YAML, encoding="utf-8")

    config = load_server_config(path)
    server = select_server(config, "debian-vps-1")

    assert server.runtime.type == "docker"
    assert server.runtime.container_name == "amnezia-awg"
    assert server.runtime.config_path == "/opt/amnezia/awg/awg0.conf"
    assert server.runtime.service_name is None


def test_loader_rejects_docker_runtime_without_container_name(tmp_path: Path):
    path = tmp_path / "servers.yml"
    path.write_text(
        DOCKER_YAML.replace("      container_name: amnezia-awg\n", ""),
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="container_name"):
        load_server_config(path)


@pytest.mark.parametrize(
    ("content", "error"),
    [
        (VALID_YAML.replace("      port: 22\n", "      port: 0\n"), "ssh.port"),
        (VALID_YAML.replace("      port: 22\n", "      port: 65536\n"), "ssh.port"),
        (VALID_YAML.replace("      port: 30001\n", "      port: 0\n"), "vpn.port"),
        (VALID_YAML.replace("      port: 30001\n", "      port: 65536\n"), "vpn.port"),
        (VALID_YAML.replace("      max_devices: 254\n", "      max_devices: 0\n"), "vpn.max_devices"),
    ],
)
def test_loader_rejects_out_of_range_numeric_values(tmp_path: Path, content: str, error: str):
    path = tmp_path / "servers.yml"
    path.write_text(content, encoding="utf-8")

    with pytest.raises(ConfigError, match=error):
        load_server_config(path)


@pytest.mark.parametrize(
    ("content", "error"),
    [
        (VALID_YAML.replace("      host: 203.0.113.10\n", "      host: ''\n"), "ssh.host"),
        (VALID_YAML.replace("      host: 203.0.113.10\n", "      host: https://203.0.113.10\n"), "ssh.host"),
        (VALID_YAML.replace("      endpoint_host: 203.0.113.10\n", "      endpoint_host: ''\n"), "vpn.endpoint_host"),
        (
            VALID_YAML.replace("      endpoint_host: 203.0.113.10\n", "      endpoint_host: vpn.example.test/path\n"),
            "vpn.endpoint_host",
        ),
        (
            DOCKER_YAML.replace("      config_path: /opt/amnezia/awg/awg0.conf\n", "      config_path: awg0.conf\n"),
            "runtime.config_path",
        ),
    ],
)
def test_loader_rejects_invalid_host_and_runtime_path_values(
    tmp_path: Path,
    content: str,
    error: str,
):
    path = tmp_path / "servers.yml"
    path.write_text(content, encoding="utf-8")

    with pytest.raises(ConfigError, match=error):
        load_server_config(path)


@pytest.mark.parametrize(
    ("content", "error"),
    [
        (VALID_YAML.replace("      network_cidr: 10.8.0.0/24\n", "      network_cidr: not-a-cidr\n"), "vpn.network_cidr"),
        (VALID_YAML.replace("      server_address: 10.8.0.1/24\n", "      server_address: not-an-address\n"), "vpn.server_address"),
        (VALID_YAML.replace("      dns: 1.1.1.1\n", "      dns: not-an-ip\n"), "vpn.dns"),
        (VALID_YAML.replace("      allowed_ips: 0.0.0.0/0\n", "      allowed_ips: not-a-cidr\n"), "vpn.allowed_ips"),
    ],
)
def test_loader_rejects_invalid_network_values(tmp_path: Path, content: str, error: str):
    path = tmp_path / "servers.yml"
    path.write_text(content, encoding="utf-8")

    with pytest.raises(ConfigError, match=error):
        load_server_config(path)


@pytest.mark.parametrize(
    ("content", "error"),
    [
        (VALID_YAML.replace("  - name: debian-vps-1\n", "  - name: ''\n"), "server.name"),
        (VALID_YAML.replace("    location: default\n", "    location: 'bad location'\n"), "server.location"),
        (VALID_YAML.replace("      interface: awg0\n", "      interface: '../awg0'\n"), "vpn.interface"),
        (VALID_YAML.replace("      service_name: awg-quick@awg0\n", "      service_name: ''\n"), "runtime.service_name"),
        (DOCKER_YAML.replace("      container_name: amnezia-awg\n", "      container_name: '../amnezia-awg'\n"), "runtime.container_name"),
    ],
)
def test_loader_rejects_invalid_identifier_values(tmp_path: Path, content: str, error: str):
    path = tmp_path / "servers.yml"
    path.write_text(content, encoding="utf-8")

    with pytest.raises(ConfigError, match=error):
        load_server_config(path)


def test_loader_rejects_duplicate_server_names(tmp_path: Path):
    path = tmp_path / "servers.yml"
    server_entry = VALID_YAML.split("servers:\n", maxsplit=1)[1]
    path.write_text(f"servers:\n{server_entry}{server_entry}", encoding="utf-8")

    with pytest.raises(ConfigError, match="Duplicate server name: debian-vps-1"):
        load_server_config(path)


def test_select_server_lists_available_names(tmp_path: Path):
    path = tmp_path / "servers.yml"
    path.write_text(VALID_YAML, encoding="utf-8")

    config = load_server_config(path)

    with pytest.raises(ConfigError, match="debian-vps-1"):
        select_server(config, "missing")


def test_loader_rejects_placeholder_values(tmp_path: Path):
    path = tmp_path / "servers.yml"
    path.write_text(VALID_YAML.replace("203.0.113.10", "CHANGE_ME_SERVER_IP"), encoding="utf-8")

    with pytest.raises(ConfigError, match="placeholder"):
        load_server_config(path)
