from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from app.db.repositories import Repository
from app.services.device_passports import (
    CONFIG_FINGERPRINT_PATTERN,
    DEVICE_IMPORT_METHODS,
    DEVICE_PLATFORMS,
    OFFICIAL_CLIENT_TYPES,
    DeviceAcceptanceEvidence,
    DevicePassport,
    get_device_passport,
)
from app.services.device_lifecycle import (
    LifecycleEvidence,
    list_device_lifecycle_events,
    record_device_lifecycle_stage,
)
from app.vpn.config_versions import SUPPORTED_CONFIG_VERSIONS


DEFAULT_ENROLLMENT_TTL = timedelta(minutes=30)
MAX_ENROLLMENT_TTL = timedelta(hours=24)
UNAVAILABLE_MESSAGE = "Device enrollment ticket is unavailable"


class EnrollmentTicketUnavailable(ValueError):
    def __init__(self) -> None:
        super().__init__(UNAVAILABLE_MESSAGE)


@dataclass(frozen=True)
class EnrollmentTicketMetadata:
    ticket_id: str
    user_id: int
    token_prefix: str
    platform: str
    config_schema_version: str
    single_use: bool
    expires_at: datetime
    revoked_at: datetime | None
    revoke_reason: str | None
    claimed_at: datetime | None
    claimed_device_id: str | None
    created_at: datetime

    def status(self, *, now: datetime | None = None) -> str:
        current_time = _as_utc(now or datetime.now(timezone.utc))
        if self.revoked_at is not None:
            return "revoked"
        if self.claimed_at is not None:
            return "claimed"
        if self.expires_at <= current_time:
            return "expired"
        return "active"

    def safe_metadata(self, *, now: datetime | None = None) -> dict[str, object]:
        return {
            "ticket_id": self.ticket_id,
            "user_id": self.user_id,
            "token_prefix": self.token_prefix,
            "platform": self.platform,
            "config_schema_version": self.config_schema_version,
            "single_use": self.single_use,
            "expires_at": _format_datetime(self.expires_at),
            "revoked_at": _format_optional_datetime(self.revoked_at),
            "revoke_reason": self.revoke_reason,
            "claimed_at": _format_optional_datetime(self.claimed_at),
            "claimed_device_id": self.claimed_device_id,
            "created_at": _format_datetime(self.created_at),
            "status": self.status(now=now),
        }


@dataclass(frozen=True)
class EnrollmentTicketIssue:
    metadata: EnrollmentTicketMetadata
    raw_token: str = field(repr=False)

    def safe_metadata(self, *, now: datetime | None = None) -> dict[str, object]:
        return {
            **self.metadata.safe_metadata(now=now),
            "raw_token_display": "one-time",
            "stored_secret_material": "sha256-token-hash-only",
        }

    def safe_audit_metadata(self) -> dict[str, object]:
        return {
            "action": "device_enrollment_ticket.issued",
            "ticket_id": self.metadata.ticket_id,
            "user_id": self.metadata.user_id,
            "token_prefix": self.metadata.token_prefix,
            "platform": self.metadata.platform,
            "config_schema_version": self.metadata.config_schema_version,
            "expires_at": _format_datetime(self.metadata.expires_at),
            "single_use": True,
        }


@dataclass(frozen=True)
class EnrollmentClaim:
    ticket: EnrollmentTicketMetadata
    passport: DevicePassport
    idempotent_replay: bool

    def safe_metadata(self) -> dict[str, object]:
        return {
            "action": "device_enrollment_ticket.claimed",
            "ticket_id": self.ticket.ticket_id,
            "user_id": self.ticket.user_id,
            "claimed_at": _format_optional_datetime(self.ticket.claimed_at),
            "claimed_device_id": self.passport.device_id,
            "platform": self.passport.platform,
            "config_schema_version": self.passport.config_schema_version,
            "idempotent_replay": self.idempotent_replay,
        }


@dataclass(frozen=True)
class EnrollmentTicketRevokeResult:
    ticket_id: str
    status: str
    revoked_at: datetime
    reason: str

    def safe_metadata(self) -> dict[str, str]:
        return {
            "action": "device_enrollment_ticket.revoked",
            "ticket_id": self.ticket_id,
            "status": self.status,
            "revoked_at": _format_datetime(self.revoked_at),
            "reason": self.reason,
        }


def issue_device_enrollment_ticket(
    repo: Repository,
    *,
    user_id: int,
    platform: str,
    config_schema_version: str,
    now: datetime | None = None,
    ttl: timedelta = DEFAULT_ENROLLMENT_TTL,
    ticket_id: str | None = None,
    raw_token: str | None = None,
) -> EnrollmentTicketIssue:
    current_time = _as_utc(now or datetime.now(timezone.utc))
    normalized_platform = platform.strip().lower()
    normalized_schema_version = config_schema_version.strip()
    if normalized_platform not in DEVICE_PLATFORMS:
        raise ValueError("unsupported device platform")
    if normalized_schema_version not in SUPPORTED_CONFIG_VERSIONS:
        raise ValueError("unsupported config schema version")
    if ttl <= timedelta(0) or ttl > MAX_ENROLLMENT_TTL:
        raise ValueError("enrollment ticket ttl is outside the allowed range")

    actual_ticket_id = ticket_id or f"ent_{uuid.uuid4().hex}"
    if not actual_ticket_id.startswith("ent_"):
        raise ValueError("ticket_id must use the ent_ prefix")
    actual_raw_token = raw_token or f"amn2_enroll_{secrets.token_urlsafe(32)}"
    if not actual_raw_token.startswith("amn2_enroll_") or len(actual_raw_token) < 32:
        raise ValueError("raw enrollment token format is invalid")
    expires_at = current_time + ttl

    with repo.transaction():
        repo.create_device_enrollment_ticket(
            ticket_id=actual_ticket_id,
            user_id=user_id,
            token_hash=hash_enrollment_secret(actual_raw_token),
            token_prefix=actual_raw_token[:20],
            platform=normalized_platform,
            config_schema_version=normalized_schema_version,
            expires_at=_format_datetime(expires_at),
        )
        record_device_lifecycle_stage(
            repo,
            ticket_id=actual_ticket_id,
            stage="issued",
            status="completed",
            started_at=current_time,
            occurred_at=current_time,
            evidence=LifecycleEvidence(
                source="device_enrollment",
                reference="ticket-issued",
            ),
        )
    metadata = get_device_enrollment_ticket(repo, actual_ticket_id)
    return EnrollmentTicketIssue(metadata=metadata, raw_token=actual_raw_token)


def claim_device_enrollment_ticket(
    repo: Repository,
    *,
    raw_token: str,
    idempotency_key: str,
    official_client_type: str,
    client_version: str | None,
    import_method: str,
    config_fingerprint: str,
    now: datetime | None = None,
    device_id: str | None = None,
) -> EnrollmentClaim:
    if not idempotency_key.strip():
        raise ValueError("idempotency_key is required")
    if not raw_token:
        raise EnrollmentTicketUnavailable()
    normalized_client_type = official_client_type.strip().lower()
    normalized_import_method = import_method.strip().lower()
    normalized_client_version = (
        client_version.strip() if client_version and client_version.strip() else None
    )
    if normalized_client_type not in OFFICIAL_CLIENT_TYPES:
        raise ValueError("unsupported official client type")
    if normalized_import_method not in DEVICE_IMPORT_METHODS:
        raise ValueError("unsupported import method")
    if normalized_client_version is not None and len(normalized_client_version) > 64:
        raise ValueError("client_version is too long")
    if CONFIG_FINGERPRINT_PATTERN.fullmatch(config_fingerprint) is None:
        raise ValueError("invalid config fingerprint")

    claimed_at = _as_utc(now or datetime.now(timezone.utc))
    actual_device_id = device_id or f"dev_{uuid.uuid4().hex}"
    token_hash = hash_enrollment_secret(raw_token)
    idempotency_hash = hash_enrollment_idempotency(idempotency_key)
    existing = _claimed_ticket_for_replay(
        repo,
        token_hash=token_hash,
        idempotency_hash=idempotency_hash,
    )
    with repo.transaction():
        row = repo.claim_device_enrollment_ticket(
            token_hash=token_hash,
            idempotency_hash=idempotency_hash,
            now=_format_datetime(claimed_at),
            claimed_at=_format_datetime(claimed_at),
            claimed_device_id=actual_device_id,
            official_client_type=normalized_client_type,
            client_version=normalized_client_version,
            import_method=normalized_import_method,
            config_fingerprint=config_fingerprint,
            acceptance_evidence=DeviceAcceptanceEvidence(
                status="pending",
                source="ticket_claim",
                observed_at=claimed_at,
                reference="enrollment-claim",
            ).safe_metadata(),
        )
        if row is None:
            raise EnrollmentTicketUnavailable()
        ticket = _ticket_from_row(row)
        if ticket.claimed_device_id is None:
            raise RuntimeError("claimed ticket has no device id")
        lifecycle = list_device_lifecycle_events(repo, ticket_id=ticket.ticket_id)
        issued_at = next(
            event.occurred_at
            for event in lifecycle
            if event.stage == "issued" and event.status == "completed"
        )
        record_device_lifecycle_stage(
            repo,
            ticket_id=ticket.ticket_id,
            passport_device_id=ticket.claimed_device_id,
            stage="claimed",
            status="completed",
            started_at=issued_at,
            occurred_at=claimed_at,
            evidence=LifecycleEvidence(
                source="device_enrollment",
                reference="ticket-claimed",
            ),
        )
    return EnrollmentClaim(
        ticket=ticket,
        passport=get_device_passport(repo, ticket.claimed_device_id),
        idempotent_replay=(
            existing or ticket.claimed_device_id != actual_device_id
        ),
    )


def revoke_device_enrollment_ticket(
    repo: Repository,
    *,
    ticket_id: str,
    reason: str,
    revoked_at: datetime | None = None,
) -> EnrollmentTicketRevokeResult:
    normalized_reason = " ".join(reason.split())
    if not normalized_reason or len(normalized_reason) > 200:
        raise ValueError("revoke reason is invalid")
    actual_revoked_at = _as_utc(revoked_at or datetime.now(timezone.utc))
    revoked = repo.revoke_device_enrollment_ticket(
        ticket_id=ticket_id,
        revoked_at=_format_datetime(actual_revoked_at),
        reason=normalized_reason,
    )
    return EnrollmentTicketRevokeResult(
        ticket_id=ticket_id,
        status="revoked" if revoked else "already-revoked-or-unavailable",
        revoked_at=actual_revoked_at,
        reason=normalized_reason,
    )


def get_device_enrollment_ticket(
    repo: Repository,
    ticket_id: str,
) -> EnrollmentTicketMetadata:
    row = repo.get_device_enrollment_ticket(ticket_id)
    if row is None:
        raise LookupError("device enrollment ticket not found")
    return _ticket_from_row(row)


def list_device_enrollment_tickets(
    repo: Repository,
    *,
    user_id: int | None = None,
    limit: int = 100,
) -> tuple[EnrollmentTicketMetadata, ...]:
    return tuple(
        _ticket_from_row(row)
        for row in repo.list_device_enrollment_tickets(user_id=user_id, limit=limit)
    )


def build_device_enrollment_launch_boundary() -> dict[str, object]:
    return {
        "implementation_mode": "local-service-only",
        "public_self_service_route": False,
        "launch_blocking": False,
        "live_vps_mutation": False,
        "telegram_config_delivery": False,
        "drift_auto_remediation": False,
        "required_before_route_enablement": [
            "SurfacePolicy binding",
            "separate self-service authentication",
            "rate limiting",
            "production route gate",
        ],
    }


def hash_enrollment_secret(value: str) -> str:
    return _domain_hash("device-enrollment-ticket", value)


def hash_enrollment_idempotency(value: str) -> str:
    return _domain_hash("device-enrollment-idempotency", value)


def _claimed_ticket_for_replay(
    repo: Repository,
    *,
    token_hash: str,
    idempotency_hash: str,
) -> bool:
    return repo.is_device_enrollment_claim_replay(
        token_hash=token_hash,
        idempotency_hash=idempotency_hash,
    )


def _ticket_from_row(row) -> EnrollmentTicketMetadata:
    return EnrollmentTicketMetadata(
        ticket_id=str(row["id"]),
        user_id=int(row["user_id"]),
        token_prefix=str(row["token_prefix"]),
        platform=str(row["platform"]),
        config_schema_version=str(row["config_schema_version"]),
        single_use=bool(row["single_use"]),
        expires_at=_parse_datetime(str(row["expires_at"])),
        revoked_at=_parse_optional_datetime(row["revoked_at"]),
        revoke_reason=(
            str(row["revoke_reason"]) if row["revoke_reason"] is not None else None
        ),
        claimed_at=_parse_optional_datetime(row["claimed_at"]),
        claimed_device_id=(
            str(row["claimed_device_id"])
            if row["claimed_device_id"] is not None
            else None
        ),
        created_at=_parse_datetime(str(row["created_at"])),
    )


def _domain_hash(domain: str, value: str) -> str:
    digest = hashlib.sha256(f"{domain}\0{value}".encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def _parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return _as_utc(parsed)


def _parse_optional_datetime(value: str | None) -> datetime | None:
    return _parse_datetime(str(value)) if value is not None else None


def _format_datetime(value: datetime) -> str:
    return _as_utc(value).isoformat().replace("+00:00", "Z")


def _format_optional_datetime(value: datetime | None) -> str | None:
    return _format_datetime(value) if value is not None else None


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
