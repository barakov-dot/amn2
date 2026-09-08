"""Explicit, in-memory client exports. No IO, key generation or delivery.

Native envelope follows amnezia-client 5.0.1.5 ImportController's data contract.
Client import/connectivity is deliberately not inferred from serialization.
"""
from __future__ import annotations

import base64
import configparser
import ipaddress
import json
import re
import zlib
from collections.abc import Iterable
from dataclasses import dataclass, field
from urllib.parse import urlsplit

DISPLAY_NAME = "Neobyatnaya.NET"
AWG_FIELDS = frozenset((
    "Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4",
    "I1", "I2", "I3", "I4", "I5", "HeaderProtectionKey", "ContentPaddingAddition",
    "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime", "KeepaliveTimeout",
    "MaxHandshakeAttempts", "RandomTrailers", "DisableCookies",
))
_INTERFACE = AWG_FIELDS | {"PrivateKey", "Address", "DNS", "MTU"}
_PEER = {"PublicKey", "PresharedKey", "PreSharedKey", "Endpoint", "AllowedIPs", "PersistentKeepalive"}


@dataclass(frozen=True)
class ClientImportArtifact:
    target_client: str
    filename: str
    content: bytes = field(repr=False)
    vpn_import_link: str | None = field(repr=False)
    client_import_verified: bool = False
    compatibility_note: str = "Requires import verification in the selected client/version."


def _parse(config_text: str) -> tuple[dict[str, str], dict[str, str]]:
    try:
        if not isinstance(config_text, str) or not 0 < len(config_text) <= 1024 * 1024:
            raise ValueError
        if any(ord(c) < 32 and c not in "\r\n\t" for c in config_text):
            raise ValueError
        parser = configparser.ConfigParser(interpolation=None, delimiters=("=",), strict=True)
        parser.optionxform = str
        parser.read_string(config_text)
        if parser.defaults() or parser.sections() != ["Interface", "Peer"]:
            raise ValueError
        interface, peer = dict(parser["Interface"]), dict(parser["Peer"])
        if set(interface) - _INTERFACE or set(peer) - _PEER:
            raise ValueError
        if not {"PrivateKey", "Address", "DNS", "Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"} <= interface.keys():
            raise ValueError
        if not {"PublicKey", "Endpoint", "AllowedIPs"} <= peer.keys():
            raise ValueError
        if {"PresharedKey", "PreSharedKey"} <= peer.keys():
            raise ValueError
        if any(not value or "\n" in value or "\r" in value for value in (*interface.values(), *peer.values())):
            raise ValueError
        return interface, peer
    except (ValueError, TypeError, configparser.Error):
        raise ValueError("unsupported_or_ambiguous_config") from None


def _native_document(config_text: str, interface: dict[str, str], peer: dict[str, str]) -> dict:
    try:
        endpoint = urlsplit("//" + peer["Endpoint"])
        host, port = endpoint.hostname, endpoint.port
        if (not host or not port or endpoint.username is not None or endpoint.password is not None
                or endpoint.path or endpoint.query or endpoint.fragment):
            raise ValueError
        if ":" in host:
            ipaddress.IPv6Address(host)
        elif re.fullmatch(r"[A-Za-z0-9.-]+", host) is None:
            raise ValueError
        dns = [str(ipaddress.ip_address(value.strip())) for value in interface["DNS"].split(",")]
        if not 1 <= len(dns) <= 2:
            raise ValueError
        allowed = [value.strip() for value in peer["AllowedIPs"].split(",")]
        for value in allowed:
            ipaddress.ip_network(value, strict=False)
        for value in interface["Address"].split(","):
            ipaddress.ip_interface(value.strip())
    except (ValueError, KeyError):
        raise ValueError("unsupported_endpoint_or_addresses") from None
    last = {
        "config": config_text, "hostName": host, "port": port,
        "client_priv_key": interface["PrivateKey"], "client_ip": interface["Address"],
        "server_pub_key": peer["PublicKey"], "allowed_ips": allowed,
        **{key: value for key, value in interface.items() if key in AWG_FIELDS},
    }
    if "MTU" in interface:
        last["mtu"] = interface["MTU"]
    if "PersistentKeepalive" in peer:
        last["persistent_keep_alive"] = peer["PersistentKeepalive"]
    if "PresharedKey" in peer or "PreSharedKey" in peer:
        last["psk_key"] = peer.get("PresharedKey", peer.get("PreSharedKey"))
    return {
        "description": DISPLAY_NAME, "hostName": host,
        "dns1": dns[0], "dns2": dns[-1], "defaultContainer": "amnezia-awg",
        "containers": [{"container": "amnezia-awg", "awg": {
            "last_config": json.dumps(last, ensure_ascii=False, separators=(",", ":")),
            "isThirdPartyConfig": True, "port": str(port), "transport_proto": "udp",
        }}],
    }


def build_client_import_artifact(
    config_text: str, *, target_client: str, existing_names: Iterable[str] = (),
) -> ClientImportArtifact:
    """Build an explicit export candidate; the caller retains ownership/issuance gates.

    existing_names is an operator/caller-supplied inventory, not a device lookup.
    No file is written and no existing tunnel can be replaced by this function.
    """
    if target_client not in {"amneziavpn", "amneziawg", "defaultvpn"}:
        raise ValueError("unsupported_client")
    if isinstance(existing_names, (str, bytes)):
        raise ValueError("invalid_name_inventory")
    for name in existing_names:
        if not isinstance(name, str):
            raise ValueError("invalid_name_inventory")
        if name.strip().casefold() == DISPLAY_NAME.casefold():
            raise ValueError("name_conflict")
    interface, peer = _parse(config_text)
    document = _native_document(config_text, interface, peer)
    if target_client == "amneziawg":
        return ClientImportArtifact(target_client, DISPLAY_NAME + ".conf", config_text.encode("utf-8"), None)
    raw = json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    compressed = len(raw).to_bytes(4, "big") + zlib.compress(raw, 8)
    link = "vpn://" + base64.urlsafe_b64encode(compressed).decode("ascii").rstrip("=")
    note = "Requires import verification in AmneziaVPN; no connectivity claim."
    if target_client == "defaultvpn":
        note = "DefaultVPN published source may replace MTU; verify installed build and all AWG fields before use."
    return ClientImportArtifact(target_client, DISPLAY_NAME + ".vpn", link.encode("ascii"), link, compatibility_note=note)
