"""Offline synthetic data only; never import/connect real client profiles."""
import base64
import json
import zlib

import pytest

from app.vpn import config_templates as exports


NAME = "Neobyatnaya.NET"
CONFIG = """[Interface]
PrivateKey = synthetic-client-key
Address = 192.0.2.2/32
DNS = 1.1.1.1, 8.8.8.8
MTU = 1280
Jc = 4
Jmin = 40
Jmax = 70
S1 = 16
S2 = 16
S3 = 16
S4 = 16
H1 = 1-2
H2 = 3-4
H3 = 5-6
H4 = 7-8
I1 = <b 0x1234>
I2 = <t>
I3 = <r 4>
I4 = <rc 4>
I5 = <rd 4>
HeaderProtectionKey = synthetic-header-key
ContentPaddingAddition = 10
RekeyAfterTime = 120
RekeyTimeout = 5
RejectAfterTime = 180
KeepaliveTimeout = 10
MaxHandshakeAttempts = 18
RandomTrailers = on
DisableCookies = off

[Peer]
PublicKey = synthetic-server-key
PresharedKey = synthetic-psk
Endpoint = vpn.example.test:30002
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""


def decode(link):
    encoded = link.removeprefix("vpn://")
    packed = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    raw = zlib.decompress(packed[4:])
    assert int.from_bytes(packed[:4], "big") == len(raw)
    return json.loads(raw)


@pytest.mark.parametrize("client", ["amneziavpn", "defaultvpn"])
def test_named_native_export_preserves_raw_and_every_awg_field(client):
    artifact = exports.build_client_import_artifact(CONFIG, target_client=client)
    document = decode(artifact.vpn_import_link)
    assert artifact.filename == NAME + ".vpn"
    assert artifact.content == artifact.vpn_import_link.encode("ascii")
    assert document["description"] == NAME
    assert set(document) == {"description", "hostName", "dns1", "dns2", "defaultContainer", "containers"}
    assert document["dns1"] == "1.1.1.1"
    assert document["dns2"] == "8.8.8.8"
    container = document["containers"][0]
    assert container["container"] == document["defaultContainer"] == "amnezia-awg"
    assert container["awg"]["isThirdPartyConfig"] is True
    last = json.loads(container["awg"]["last_config"])
    assert last["config"] == CONFIG
    assert last["mtu"] == "1280"
    assert last["client_priv_key"] == "synthetic-client-key"
    assert last["psk_key"] == "synthetic-psk"
    assert last["allowed_ips"] == ["0.0.0.0/0", "::/0"]
    assert last["server_pub_key"] == "synthetic-server-key"
    assert last["persistent_keep_alive"] == "25"
    assert last["client_ip"] == "192.0.2.2/32"
    for line in CONFIG.split("[Peer]", 1)[0].splitlines()[5:]:
        if " = " not in line:
            continue
        key, value = line.split(" = ", 1)
        assert last[key] == value
    assert artifact.client_import_verified is False
    if client == "defaultvpn":
        assert "mtu" in artifact.compatibility_note.lower()
    assert "synthetic-client-key" not in repr(artifact)
    assert "vpn://" not in repr(artifact)


def test_standalone_uses_exact_filename_without_modifying_config():
    artifact = exports.build_client_import_artifact(CONFIG, target_client="amneziawg")
    assert artifact.filename == NAME + ".conf"
    assert artifact.content == CONFIG.encode()
    assert artifact.vpn_import_link is None
    assert len(NAME) == 15


def test_existing_link_api_can_explicitly_select_native_client():
    link = exports.build_vpn_import_link(CONFIG, target_client="amneziavpn")
    assert decode(link)["description"] == NAME


def test_legacy_link_api_stays_byte_compatible():
    link = exports.build_vpn_import_link(CONFIG)
    body = link.removeprefix("vpn://")
    assert base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)).decode() == CONFIG


@pytest.mark.parametrize("client", ["amneziavpn", "amneziawg", "defaultvpn"])
def test_existing_name_is_not_overwritten_or_suffixed(client):
    with pytest.raises(ValueError, match="name_conflict"):
        exports.build_client_import_artifact(CONFIG, target_client=client, existing_names=[NAME.lower()])


@pytest.mark.parametrize("bad", [
    CONFIG.replace("Jc = 4", "UnknownFutureField = sensitive-marker"),
    CONFIG.replace("Jc = 4", "Jc = 4\nJc = 5"),
    CONFIG + "\n[Peer]\nPublicKey = another-peer\n",
    CONFIG.replace("MTU = 1280", "PostUp = sensitive-marker"),
    CONFIG.replace("PresharedKey = synthetic-psk", "PresharedKey = synthetic-psk\nPreSharedKey = sensitive-marker"),
    CONFIG.replace("Endpoint = vpn.example.test:30002", "Endpoint = user:secret@vpn.example.test:30002"),
    CONFIG.replace("DNS = 1.1.1.1, 8.8.8.8", "DNS = 1.1.1.1, 8.8.8.8, 9.9.9.9"),
    CONFIG.replace("[Peer]", "[Admin]"),
], ids=["unknown", "duplicate", "multi-peer", "script", "psk-alias", "userinfo", "dns-count", "section"])
def test_rejects_lossy_ambiguous_or_unsupported_inputs_without_echoing_values(bad):
    with pytest.raises(ValueError) as error:
        exports.build_client_import_artifact(bad, target_client="amneziavpn")
    assert "sensitive-marker" not in str(error.value)
    assert "synthetic" not in str(error.value)


def test_ipv6_endpoint_keeps_host_and_port():
    config = CONFIG.replace("vpn.example.test:30002", "[2001:db8::1]:30002")
    document = decode(exports.build_vpn_import_link(config, target_client="amneziavpn"))
    assert document["hostName"] == "2001:db8::1"
    assert json.loads(document["containers"][0]["awg"]["last_config"])["port"] == 30002


def test_unknown_client_rejected():
    with pytest.raises(ValueError, match="unsupported_client"):
        exports.build_client_import_artifact(CONFIG, target_client="unknown")


def test_native_export_retains_crlf_exactly():
    config = CONFIG.replace("\n", "\r\n")
    artifact = exports.build_client_import_artifact(config, target_client="amneziavpn")
    assert json.loads(decode(artifact.vpn_import_link)["containers"][0]["awg"]["last_config"])["config"] == config


def test_standalone_link_is_not_misrepresented_as_supported():
    with pytest.raises(ValueError, match="requires_conf_file"):
        exports.build_vpn_import_link(CONFIG, target_client="amneziawg")


def test_single_dns_and_optional_mtu_are_not_replaced_with_unrelated_defaults():
    config = CONFIG.replace("1.1.1.1, 8.8.8.8", "1.1.1.1").replace("MTU = 1280\n", "")
    doc = decode(exports.build_vpn_import_link(config, target_client="amneziavpn"))
    assert doc["dns1"] == doc["dns2"] == "1.1.1.1"
    assert "mtu" not in json.loads(doc["containers"][0]["awg"]["last_config"])
