from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
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


class SourceReleaseKind(StrEnum):
    STABLE = "stable"
    PRERELEASE = "prerelease"
    UNRELEASED = "unreleased"


class CompatibilityAdmissionState(StrEnum):
    ACCEPTED = "accepted"
    CANDIDATE = "candidate"
    REJECTED = "rejected"


@dataclass(frozen=True)
class ClientIdentity:
    application: str
    platform: str
    version: str
    build_id: str | None = None

    def __post_init__(self) -> None:
        application = _exact_text(self.application, "client_application")
        platform = _exact_text(self.platform, "client_platform")
        version = _exact_text(self.version, "client_version")
        if version.casefold() in {"latest", "current", "unknown"}:
            raise ValueError("exact client_version is required")
        if self.build_id is not None:
            build_id = _exact_text(self.build_id, "client_build")
            if build_id.casefold() in {"latest", "current", "unknown"}:
                raise ValueError("exact client_build is required")
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
    release_kind: SourceReleaseKind | None = None

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
        if self.release_kind is not None and not isinstance(
            self.release_kind, SourceReleaseKind
        ):
            raise ValueError("release_kind")


def current_awg3_compatibility_evidence(
    evidence: tuple[ClientCompatibilityEvidence, ...],
    *,
    client: ClientIdentity,
) -> tuple[ClientCompatibilityEvidence, ...]:
    exact = tuple(
        item
        for item in evidence
        if item.client == client and item.protocol_version is ProtocolVersion.AWG3
    )
    current: list[ClientCompatibilityEvidence] = []
    for source_kind in ("official_release", "local_import", "full_data"):
        source_evidence = tuple(
            item for item in exact if item.source_kind == source_kind
        )
        if not source_evidence:
            continue
        latest_observed_at = max(item.observed_at for item in source_evidence)
        current.extend(
            item
            for item in source_evidence
            if item.observed_at == latest_observed_at
        )
    return tuple(current)


def classify_awg3_compatibility(
    evidence: tuple[ClientCompatibilityEvidence, ...],
    *,
    client: ClientIdentity,
    now: datetime,
    max_evidence_age: timedelta = timedelta(days=90),
) -> CompatibilityAdmissionState:
    if not isinstance(client, ClientIdentity):
        raise ValueError("client")
    if not isinstance(now, datetime) or now.utcoffset() is None:
        raise ValueError("now")
    if max_evidence_age < timedelta(0):
        raise ValueError("max_evidence_age")
    if client.build_id is None:
        return CompatibilityAdmissionState.REJECTED

    current = current_awg3_compatibility_evidence(
        evidence,
        client=client,
    )
    release_evidence = tuple(
        item for item in current if item.source_kind == "official_release"
    )
    if not release_evidence or any(
        item.status
        not in {
            CompatibilityEvidenceStatus.CLAIMED,
            CompatibilityEvidenceStatus.PASSED,
        }
        or not timedelta(0) <= now - item.observed_at <= max_evidence_age
        for item in release_evidence
    ):
        return CompatibilityAdmissionState.REJECTED

    release_kinds = {item.release_kind for item in release_evidence}
    if SourceReleaseKind.UNRELEASED in release_kinds:
        return CompatibilityAdmissionState.REJECTED
    if SourceReleaseKind.PRERELEASE in release_kinds:
        return CompatibilityAdmissionState.CANDIDATE
    if release_kinds != {SourceReleaseKind.STABLE}:
        return CompatibilityAdmissionState.REJECTED

    latest_local: dict[str, tuple[ClientCompatibilityEvidence, ...]] = {}
    for source_kind in ("local_import", "full_data"):
        source_evidence = tuple(
            item for item in current if item.source_kind == source_kind
        )
        if not source_evidence:
            latest_local[source_kind] = ()
            continue
        latest_observed_at = max(item.observed_at for item in source_evidence)
        latest_local[source_kind] = tuple(
            item
            for item in source_evidence
            if item.observed_at == latest_observed_at
        )
    if all(
        items
        and all(
            item.release_kind is SourceReleaseKind.STABLE
            and item.status is CompatibilityEvidenceStatus.PASSED
            and timedelta(0) <= now - item.observed_at <= max_evidence_age
            for item in items
        )
        for items in latest_local.values()
    ):
        return CompatibilityAdmissionState.ACCEPTED
    if any(
        any(
            item.status
            in {
                CompatibilityEvidenceStatus.FAILED,
                CompatibilityEvidenceStatus.SUPERSEDED,
            }
            for item in items
        )
        for items in latest_local.values()
    ):
        return CompatibilityAdmissionState.REJECTED
    return CompatibilityAdmissionState.CANDIDATE
