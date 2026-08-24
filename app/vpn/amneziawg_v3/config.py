from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Protocol

from app.vpn.amneziawg_v2.config import (
    ClientConfigInput,
    render_client_config as render_awg2_client_config,
)


_FINGERPRINT_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")


def _bounded_one_line(value: object, field: str, *, maximum: int = 1024) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(field)
    if len(value) > maximum or any(ord(char) < 32 for char in value):
        raise ValueError(field)
    return value


@dataclass(frozen=True)
class HeaderProtectionSecretRef:
    reference: str
    fingerprint: str

    def __post_init__(self) -> None:
        _bounded_one_line(self.reference, "header_protection_key reference")
        if not isinstance(self.fingerprint, str) or not _FINGERPRINT_RE.fullmatch(
            self.fingerprint
        ):
            raise ValueError("header_protection_key fingerprint")


class SecretResolver(Protocol):
    def resolve(self, reference: str) -> str: ...


@dataclass(frozen=True)
class Awg3ClientConfigInput:
    awg2: ClientConfigInput
    header_protection_key: HeaderProtectionSecretRef
    content_padding_addition: str
    rekey_after_time: str
    rekey_timeout: str
    reject_after_time: str
    keepalive_timeout: str
    max_handshake_attempts: str
    random_trailers: bool
    disable_cookies: bool

    def __post_init__(self) -> None:
        if not isinstance(self.awg2, ClientConfigInput):
            raise ValueError("awg2")
        if not isinstance(self.header_protection_key, HeaderProtectionSecretRef):
            raise ValueError("header_protection_key")
        nonce_values = (self.awg2.s1, self.awg2.s2, self.awg2.s3, self.awg2.s4)
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 12
            for value in nonce_values
        ):
            raise ValueError("AWG3 HeaderProtectionKey requires S1-S4 values >= 12")
        for field in (
            "content_padding_addition",
            "rekey_after_time",
            "rekey_timeout",
            "reject_after_time",
            "keepalive_timeout",
            "max_handshake_attempts",
        ):
            _bounded_one_line(getattr(self, field), field, maximum=64)
        for field in ("random_trailers", "disable_cookies"):
            if not isinstance(getattr(self, field), bool):
                raise ValueError(field)

    def safe_metadata(self) -> dict[str, str]:
        return {
            "header_protection_key_fingerprint": self.header_protection_key.fingerprint,
            "protocol_version": "awg3",
        }


def render_awg3_client_config(
    config: Awg3ClientConfigInput,
    *,
    resolver: SecretResolver,
    include_awg31: bool = False,
) -> str:
    if not isinstance(config, Awg3ClientConfigInput):
        raise TypeError("config must be Awg3ClientConfigInput")
    try:
        header_key = resolver.resolve(config.header_protection_key.reference)
    except Exception:
        raise ValueError("header_protection_key could not be resolved") from None
    try:
        _bounded_one_line(header_key, "resolved header_protection_key", maximum=4096)
    except ValueError as exc:
        raise ValueError("resolved header_protection_key is invalid") from exc

    base = render_awg2_client_config(config.awg2)
    marker = "\n\n[Peer]\n"
    if base.count(marker) != 1:
        raise ValueError("AWG2 base config has no unique Peer boundary")
    interface, peer = base.split(marker, 1)
    awg3_lines = (
        f"HeaderProtectionKey = {header_key}",
        f"ContentPaddingAddition = {config.content_padding_addition}",
        f"RekeyAfterTime = {config.rekey_after_time}",
        f"RekeyTimeout = {config.rekey_timeout}",
        f"RejectAfterTime = {config.reject_after_time}",
        f"KeepaliveTimeout = {config.keepalive_timeout}",
        f"MaxHandshakeAttempts = {config.max_handshake_attempts}",
    )
    if include_awg31:
        awg3_lines += (
            f"RandomTrailers = {'on' if config.random_trailers else 'off'}",
            f"DisableCookies = {'on' if config.disable_cookies else 'off'}",
        )
    return interface + "\n" + "\n".join(awg3_lines) + marker + peer
