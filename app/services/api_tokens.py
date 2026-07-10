from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Literal, Protocol


API_TOKEN_FIRST_SLICE_SCOPES = frozenset({"server:read", "metrics:read"})
API_TOKEN_P7_WRITE_SCOPES = frozenset({"install:write"})
API_TOKEN_ALLOWED_SCOPES = API_TOKEN_FIRST_SLICE_SCOPES | API_TOKEN_P7_WRITE_SCOPES
API_TOKEN_BLOCKED_PRODUCTION_SCOPES = frozenset(
    {
        "backup:read",
        "backup:restore",
        "clients:write",
        "config:read",
        "local-agent:write",
        "server:write",
    }
)
API_TOKEN_PRODUCTION_MAX_TTL_DAYS = 30
API_TOKEN_PRODUCTION_ROTATION_NOTICE_DAYS = 7
API_TOKEN_INTEGRATION_KINDS = frozenset(
    {"monitoring", "operator_automation", "telegram_bot", "web_panel"}
)
API_TOKEN_PURPOSE_MAX_LENGTH = 200

ApiTokenAuthReason = Literal[
    "invalid_token",
    "revoked_token",
    "expired_token",
    "missing_scope",
    "inactive_owner",
]


class ApiTokenAuthError(ValueError):
    def __init__(self, message: str, *, reason: ApiTokenAuthReason) -> None:
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True)
class ApiTokenProductionPolicy:
    allowed_scopes: frozenset[str]
    blocked_scopes: frozenset[str]
    max_ttl_days: int
    rotation_notice_days: int
    raw_token_display: str = "one-time"
    stored_secret_material: str = "sha256-token-hash-only"
    safe_backup_behavior: str = "credential_digest_excluded_from_safe_exports"
    audit_metadata: str = "safe-metadata-only"

    def safe_metadata(self) -> dict[str, object]:
        return {
            "allowed_scopes": sorted(self.allowed_scopes),
            "blocked_scopes": sorted(self.blocked_scopes),
            "max_ttl_days": self.max_ttl_days,
            "rotation_notice_days": self.rotation_notice_days,
            "raw_token_display": self.raw_token_display,
            "stored_secret_material": self.stored_secret_material,
            "safe_backup_behavior": self.safe_backup_behavior,
            "audit_metadata": self.audit_metadata,
        }


class ApiTokenStore(Protocol):
    def create_api_token(
        self,
        *,
        token_id: str,
        name: str,
        owner_user_id: int | None,
        owner_label: str,
        integration_kind: str,
        purpose: str,
        token_hash: str,
        scopes: list[str],
        expires_at: str | None,
        rotated_from_token_id: str | None = None,
    ) -> None: ...

    def revoke_api_token(
        self,
        token_id: str,
        revoked_at: str,
        reason: str | None = None,
    ) -> bool: ...


@dataclass(frozen=True)
class ApiTokenRecord:
    token_id: str
    token_hash: str
    name: str
    owner_label: str
    scopes: frozenset[str]
    integration_kind: str = "operator_automation"
    purpose: str = "legacy-api-access"
    owner_user_id: int | None = None
    owner_status: str | None = None
    expires_at: datetime | None = None
    revoked_at: datetime | None = None

    def safe_audit_metadata(self) -> dict[str, object]:
        return {
            "token_id": self.token_id,
            "name": self.name,
            "owner_label": self.owner_label,
            "owner_user_id": self.owner_user_id,
            "integration_kind": self.integration_kind,
            "purpose": self.purpose,
            "scopes": sorted(self.scopes),
        }


@dataclass(frozen=True)
class ApiTokenIssue:
    token_id: str
    raw_token: str
    token_hash: str
    name: str
    owner_label: str
    integration_kind: str
    purpose: str
    scopes: frozenset[str]
    expires_at: datetime | None

    def safe_metadata(self) -> dict[str, object]:
        return {
            "token_id": self.token_id,
            "name": self.name,
            "owner_label": self.owner_label,
            "integration_kind": self.integration_kind,
            "purpose": self.purpose,
            "scopes": sorted(self.scopes),
            "expires_at": _format_datetime(self.expires_at),
            "raw_token_display": "one-time",
        }


@dataclass(frozen=True)
class ApiTokenLifecycleEvent:
    action: str
    token_id: str
    status: str
    reason: str | None = None
    revoked_at: datetime | None = None
    rotated_from_token_id: str | None = None

    def safe_metadata(self) -> dict[str, object]:
        return {
            "action": self.action,
            "token_id": self.token_id,
            "status": self.status,
            "reason": self.reason,
            "revoked_at": _format_datetime(self.revoked_at),
            "rotated_from_token_id": self.rotated_from_token_id,
        }


@dataclass(frozen=True)
class ApiTokenRotationIssue:
    issue: ApiTokenIssue
    revoked: ApiTokenLifecycleEvent
    old_token_id: str
    owner_user_id: int | None

    def safe_metadata(self) -> dict[str, object]:
        return {
            "action": "api_token.rotated",
            "status": "rotated",
            "old_token_id": self.old_token_id,
            "new_token_id": self.issue.token_id,
            "owner_label": self.issue.owner_label,
            "owner_user_id": self.owner_user_id,
            "integration_kind": self.issue.integration_kind,
            "purpose": self.issue.purpose,
            "scopes": sorted(self.issue.scopes),
            "expires_at": _format_datetime(self.issue.expires_at),
            "raw_token_display": "one-time",
        }


def hash_api_token(raw_token: str) -> str:
    token_digest = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    return f"sha256:{token_digest}"


def build_api_token_production_policy() -> ApiTokenProductionPolicy:
    return ApiTokenProductionPolicy(
        allowed_scopes=API_TOKEN_ALLOWED_SCOPES,
        blocked_scopes=API_TOKEN_BLOCKED_PRODUCTION_SCOPES,
        max_ttl_days=API_TOKEN_PRODUCTION_MAX_TTL_DAYS,
        rotation_notice_days=API_TOKEN_PRODUCTION_ROTATION_NOTICE_DAYS,
    )


def create_api_token(
    store: ApiTokenStore,
    *,
    name: str,
    owner_label: str,
    scopes: set[str] | frozenset[str],
    expires_at: datetime | None,
    owner_user_id: int | None = None,
    token_id: str | None = None,
    raw_token: str | None = None,
) -> ApiTokenIssue:
    return _create_api_token_with_rotation(
        store,
        token_id=token_id,
        raw_token=raw_token,
        name=name,
        owner_user_id=owner_user_id,
        owner_label=owner_label,
        integration_kind="operator_automation",
        purpose=name,
        scopes=scopes,
        expires_at=expires_at,
        rotated_from_token_id=None,
    )


def create_integration_api_token(
    store: ApiTokenStore,
    *,
    name: str,
    owner_label: str,
    integration_kind: str,
    purpose: str,
    scopes: set[str] | frozenset[str],
    expires_at: datetime | None,
    owner_user_id: int | None = None,
    token_id: str | None = None,
    raw_token: str | None = None,
    now: datetime | None = None,
) -> ApiTokenIssue:
    _validate_integration_identity(integration_kind, purpose)
    validate_route_api_token_expiry(expires_at, now=now)
    return _create_api_token_with_rotation(
        store,
        token_id=token_id,
        raw_token=raw_token,
        name=name,
        owner_user_id=owner_user_id,
        owner_label=owner_label,
        integration_kind=integration_kind,
        purpose=purpose,
        scopes=scopes,
        expires_at=expires_at,
        rotated_from_token_id=None,
    )


def create_route_api_token(
    store: ApiTokenStore,
    *,
    name: str,
    owner_label: str,
    scopes: set[str] | frozenset[str],
    expires_at: datetime | None,
    owner_user_id: int | None = None,
    token_id: str | None = None,
    raw_token: str | None = None,
    now: datetime | None = None,
) -> ApiTokenIssue:
    validate_route_api_token_expiry(expires_at, now=now)
    return create_api_token(
        store,
        name=name,
        owner_label=owner_label,
        scopes=scopes,
        expires_at=expires_at,
        owner_user_id=owner_user_id,
        token_id=token_id,
        raw_token=raw_token,
    )


def revoke_api_token(
    store: ApiTokenStore,
    *,
    token_id: str,
    revoked_at: datetime,
    reason: str,
) -> ApiTokenLifecycleEvent:
    revoked = store.revoke_api_token(
        token_id,
        _format_datetime(revoked_at) or "",
        reason=reason,
    )
    return ApiTokenLifecycleEvent(
        action="api_token.revoked",
        token_id=token_id,
        status="revoked" if revoked else "already-revoked-or-missing",
        reason=reason,
        revoked_at=revoked_at,
    )


def rotate_api_token(
    store: ApiTokenStore,
    previous: ApiTokenRecord,
    *,
    expires_at: datetime,
    rotated_at: datetime,
    new_token_id: str | None = None,
    raw_token: str | None = None,
) -> ApiTokenRotationIssue:
    issue = _create_api_token_with_rotation(
        store,
        token_id=new_token_id,
        raw_token=raw_token,
        name=previous.name,
        owner_user_id=previous.owner_user_id,
        owner_label=previous.owner_label,
        integration_kind=previous.integration_kind,
        purpose=previous.purpose,
        scopes=previous.scopes,
        expires_at=expires_at,
        rotated_from_token_id=previous.token_id,
    )
    revoked = revoke_api_token(
        store,
        token_id=previous.token_id,
        revoked_at=rotated_at,
        reason="rotated",
    )
    return ApiTokenRotationIssue(
        issue=issue,
        revoked=revoked,
        old_token_id=previous.token_id,
        owner_user_id=previous.owner_user_id,
    )


def authenticate_api_token(
    raw_token: str,
    *,
    tokens: tuple[ApiTokenRecord, ...],
    required_scope: str,
    now: datetime | None = None,
) -> ApiTokenRecord:
    if not raw_token:
        raise ApiTokenAuthError("Invalid API token", reason="invalid_token")

    raw_token_hash = hash_api_token(raw_token)
    for token in tokens:
        if not secrets.compare_digest(raw_token_hash, token.token_hash):
            continue

        if token.revoked_at is not None:
            raise ApiTokenAuthError("API token is revoked", reason="revoked_token")

        current_time = _as_utc(now or datetime.now(timezone.utc))
        if token.expires_at is not None and _as_utc(token.expires_at) <= current_time:
            raise ApiTokenAuthError("API token is expired", reason="expired_token")

        if token.owner_user_id is not None and token.owner_status != "active":
            raise ApiTokenAuthError("API token owner is inactive", reason="inactive_owner")

        if required_scope not in token.scopes:
            raise ApiTokenAuthError(
                f"Missing required scope: {required_scope}",
                reason="missing_scope",
            )

        return token

    raise ApiTokenAuthError("Invalid API token", reason="invalid_token")


def _validate_scope_set(scopes: set[str] | frozenset[str]) -> frozenset[str]:
    normalized = frozenset(scope.strip() for scope in scopes if scope.strip())
    unsupported = normalized - API_TOKEN_ALLOWED_SCOPES
    if not normalized or unsupported:
        raise ValueError(
            "unsupported API token scopes: "
            + ", ".join(sorted(unsupported or normalized))
        )
    return normalized


def _validate_integration_identity(
    integration_kind: str,
    purpose: str,
) -> tuple[str, str]:
    normalized_kind = integration_kind.strip()
    if normalized_kind not in API_TOKEN_INTEGRATION_KINDS:
        raise ValueError(f"unsupported integration kind: {normalized_kind}")
    normalized_purpose = " ".join(purpose.split())
    if not normalized_purpose:
        raise ValueError("purpose is required")
    if len(normalized_purpose) > API_TOKEN_PURPOSE_MAX_LENGTH:
        raise ValueError(
            f"purpose exceeds {API_TOKEN_PURPOSE_MAX_LENGTH} characters"
        )
    return normalized_kind, normalized_purpose


def validate_route_api_token_expiry(
    expires_at: datetime | None,
    *,
    now: datetime | None = None,
) -> None:
    if expires_at is None:
        raise ValueError("expires_at is required for route-connected API tokens")

    current_time = _as_utc(now or datetime.now(timezone.utc))
    max_expires_at = current_time + timedelta(days=API_TOKEN_PRODUCTION_MAX_TTL_DAYS)
    if _as_utc(expires_at) > max_expires_at:
        raise ValueError(
            "expires_at exceeds production API token ttl "
            f"({API_TOKEN_PRODUCTION_MAX_TTL_DAYS} days)"
        )


def _create_api_token_with_rotation(
    store: ApiTokenStore,
    *,
    name: str,
    owner_label: str,
    integration_kind: str,
    purpose: str,
    scopes: set[str] | frozenset[str],
    expires_at: datetime | None,
    owner_user_id: int | None,
    rotated_from_token_id: str | None,
    token_id: str | None,
    raw_token: str | None,
) -> ApiTokenIssue:
    normalized_scopes = _validate_scope_set(scopes)
    normalized_kind, normalized_purpose = _validate_integration_identity(
        integration_kind,
        purpose,
    )
    actual_token_id = token_id or f"api_{secrets.token_urlsafe(16)}"
    actual_raw_token = raw_token or secrets.token_urlsafe(32)
    token_hash = hash_api_token(actual_raw_token)

    store.create_api_token(
        token_id=actual_token_id,
        name=name,
        owner_user_id=owner_user_id,
        owner_label=owner_label,
        integration_kind=normalized_kind,
        purpose=normalized_purpose,
        token_hash=token_hash,
        scopes=sorted(normalized_scopes),
        expires_at=_format_datetime(expires_at),
        rotated_from_token_id=rotated_from_token_id,
    )
    return ApiTokenIssue(
        token_id=actual_token_id,
        raw_token=actual_raw_token,
        token_hash=token_hash,
        name=name,
        owner_label=owner_label,
        integration_kind=normalized_kind,
        purpose=normalized_purpose,
        scopes=normalized_scopes,
        expires_at=expires_at,
    )


def _format_datetime(value: datetime | None) -> str | None:
    if value is None:
        return None
    return _as_utc(value).isoformat()


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
