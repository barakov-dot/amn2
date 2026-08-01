from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from app.vpn.protocol_versions import ProtocolVersion


_APPLICATION_ALIASES = {
    "amneziavpn": "amnezia_vpn",
    "amnezia_vpn": "amnezia_vpn",
    "defaultvpn": "default_vpn",
    "default_vpn": "default_vpn",
}
_PLATFORM_ALIASES = {
    "android": "android",
    "ios": "ios",
    "linux": "linux",
    "macos": "macos",
    "windows": "windows",
}


def _exact_text(value: object, field: str, *, maximum: int = 64) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"exact {field} is required")
    if len(value) > maximum or any(ord(char) < 32 for char in value):
        raise ValueError(f"invalid exact {field}")
    return value


def _safe_text(value: object, field: str, *, maximum: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(field)
    if len(value) > maximum or any(ord(char) < 32 for char in value):
        raise ValueError(field)
    return value


class CompatibilityEvidenceStatus(StrEnum):
    CLAIMED = "claimed"
    PASSED = "passed"
    FAILED = "failed"
    SUPERSEDED = "superseded"


@dataclass(frozen=True)
class ClientIdentity:
    application: str
    platform: str
    version: str

    def __post_init__(self) -> None:
        application = _exact_text(self.application, "client_application")
        platform = _exact_text(self.platform, "client_platform")
        version = _exact_text(self.version, "client_version")
        if version.casefold() in {"latest", "current", "unknown"}:
            raise ValueError("exact client_version is required")
        object.__setattr__(
            self,
            "application",
            _APPLICATION_ALIASES.get(application.casefold(), application.casefold()),
        )
        object.__setattr__(
            self,
            "platform",
            _PLATFORM_ALIASES.get(platform.casefold(), platform.casefold()),
        )


@dataclass(frozen=True)
class ClientCompatibilityEvidence:
    evidence_id: str
    client: ClientIdentity
    protocol_version: ProtocolVersion
    source_kind: str
    status: CompatibilityEvidenceStatus
    observed_at: datetime
    safe_reference: str
    scope: str

    def __post_init__(self) -> None:
        _safe_text(self.evidence_id, "evidence_id", maximum=255)
        if not isinstance(self.client, ClientIdentity):
            raise ValueError("client")
        if not isinstance(self.protocol_version, ProtocolVersion):
            raise ValueError("protocol_version")
        _safe_text(self.source_kind, "source_kind", maximum=64)
        if not isinstance(self.status, CompatibilityEvidenceStatus):
            raise ValueError("status")
        if not isinstance(self.observed_at, datetime) or self.observed_at.utcoffset() is None:
            raise ValueError("observed_at")
        _safe_text(self.safe_reference, "safe_reference", maximum=1024)
        _safe_text(self.scope, "scope", maximum=1024)
