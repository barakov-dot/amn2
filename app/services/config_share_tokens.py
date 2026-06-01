from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal, Protocol

from app.services.config_export import (
    CLIENT_CONFIG_SECRET,
    SUPPORTED_ARTIFACTS,
    SUPPORTED_TARGET_CLIENTS,
)


CONFIG_SHARE_TOKEN_PURPOSE = "config_share"
CONFIG_SHARE_TOKEN_POLICY_ID = "share.config_download"
CONFIG_SHARE_TOKEN_PREFIX_LENGTH = 8
CONFIG_SHARE_PUBLIC_DENIAL = "Config link is invalid or expired."

ConfigShareDenialCategory = Literal[
    "wrong_purpose",
    "expired_token",
    "revoked_token",
    "download_limit_reached",
    "inactive_owner",
    "inactive_device",
    "inactive_server",
    "resource_not_bound",
    "artifact_not_allowed",
    "unsupported_target_client",
]


class ConfigShareTokenStore(Protocol):
    def create_config_share_token(
        self,
        *,
        token_id: str,
        token_hash: str,
        token_prefix: str,
        purpose: str,
        created_by_actor: str,
        owner_user_id: int,
        bound_device_ids: list[int],
        bound_server_ids: list[int],
        allowed_artifact_kinds: list[str],
        target_client: str,
        expires_at: str,
        created_at: str | None = None,
        one_time: bool = True,
        max_downloads: int = 1,
    ) -> None: ...


@dataclass(frozen=True)
class ConfigShareTokenIssue:
    token_id: str
    raw_token: str
    token_hash: str
    token_prefix: str
    purpose: str
    created_by_actor: str
    owner_user_id: int
    bound_device_ids: tuple[int, ...]
    bound_server_ids: tuple[int, ...]
    allowed_artifact_kinds: tuple[str, ...]
    target_client: str
    expires_at: datetime
    one_time: bool
    max_downloads: int

    def safe_metadata(self) -> dict[str, object]:
        return {
            "token_id": self.token_id,
            "token_prefix": self.token_prefix,
            "purpose": self.purpose,
            "created_by_actor": self.created_by_actor,
            "owner_user_id": self.owner_user_id,
            "bound_device_ids": list(self.bound_device_ids),
            "bound_server_ids": list(self.bound_server_ids),
            "allowed_artifact_kinds": list(self.allowed_artifact_kinds),
            "target_client": self.target_client,
            "expires_at": _format_datetime(self.expires_at),
            "one_time": self.one_time,
            "max_downloads": self.max_downloads,
            "raw_token_display": "one-time",
        }


@dataclass(frozen=True)
class ConfigShareTokenRecord:
    token_id: str
    token_hash: str
    token_prefix: str
    purpose: str
    created_by_actor: str
    owner_user_id: int
    bound_device_ids: tuple[int, ...]
    bound_server_ids: tuple[int, ...]
    allowed_artifact_kinds: tuple[str, ...]
    target_client: str
    expires_at: datetime
    revoked_at: datetime | None
    one_time: bool
    max_downloads: int
    download_count: int
    owner_user_status: str
    device_status: str
    server_status: str


@dataclass(frozen=True)
class ConfigShareDownloadDecision:
    allowed: bool
    token_id: str
    token_prefix: str
    owner_user_id: int
    requested_device_id: int
    requested_artifact_kinds: tuple[str, ...]
    target_client: str
    denial_category: ConfigShareDenialCategory | None = None

    @property
    def event_name(self) -> str:
        if self.allowed:
            return "config.share.download_allowed"
        return "config.share.download_denied"

    @property
    def consume_token(self) -> bool:
        return self.allowed

    @property
    def public_message(self) -> str | None:
        if self.allowed:
            return None
        return CONFIG_SHARE_PUBLIC_DENIAL

    def safe_audit_metadata(self) -> dict[str, object]:
        return {
            "event": self.event_name,
            "status": "allowed" if self.allowed else "denied",
            "denial_category": self.denial_category,
            "policy_id": CONFIG_SHARE_TOKEN_POLICY_ID,
            "token_id": self.token_id,
            "token_prefix": self.token_prefix,
            "owner_user_id": self.owner_user_id,
            "requested_device_id": self.requested_device_id,
            "requested_artifact_kinds": list(self.requested_artifact_kinds),
            "target_client": self.target_client,
            "secret_class": CLIENT_CONFIG_SECRET,
        }


def hash_config_share_token(raw_token: str) -> str:
    token_digest = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    return f"sha256:{token_digest}"


def create_config_share_token(
    store: ConfigShareTokenStore,
    *,
    created_by_actor: str,
    owner_user_id: int,
    bound_device_ids: tuple[int, ...],
    bound_server_ids: tuple[int, ...],
    allowed_artifact_kinds: tuple[str, ...],
    target_client: str,
    expires_at: datetime | None,
    created_at: datetime | None = None,
    one_time: bool = True,
    max_downloads: int = 1,
    token_id: str | None = None,
    raw_token: str | None = None,
) -> ConfigShareTokenIssue:
    issued_at = _as_utc(created_at or datetime.now(timezone.utc))
    _validate_share_policy(
        created_by_actor=created_by_actor,
        owner_user_id=owner_user_id,
        bound_device_ids=bound_device_ids,
        bound_server_ids=bound_server_ids,
        allowed_artifact_kinds=allowed_artifact_kinds,
        target_client=target_client,
        expires_at=expires_at,
        issued_at=issued_at,
        one_time=one_time,
        max_downloads=max_downloads,
    )
    assert expires_at is not None

    normalized_artifacts = tuple(sorted(allowed_artifact_kinds))
    actual_token_id = token_id or f"share_{secrets.token_urlsafe(16)}"
    actual_raw_token = raw_token or secrets.token_urlsafe(32)
    token_hash = hash_config_share_token(actual_raw_token)
    token_prefix = actual_raw_token[:CONFIG_SHARE_TOKEN_PREFIX_LENGTH]

    store.create_config_share_token(
        token_id=actual_token_id,
        token_hash=token_hash,
        token_prefix=token_prefix,
        purpose=CONFIG_SHARE_TOKEN_PURPOSE,
        created_by_actor=created_by_actor,
        owner_user_id=owner_user_id,
        bound_device_ids=list(bound_device_ids),
        bound_server_ids=list(bound_server_ids),
        allowed_artifact_kinds=list(normalized_artifacts),
        target_client=target_client,
        expires_at=_format_datetime(expires_at),
        created_at=_format_datetime(issued_at),
        one_time=one_time,
        max_downloads=max_downloads,
    )
    return ConfigShareTokenIssue(
        token_id=actual_token_id,
        raw_token=actual_raw_token,
        token_hash=token_hash,
        token_prefix=token_prefix,
        purpose=CONFIG_SHARE_TOKEN_PURPOSE,
        created_by_actor=created_by_actor,
        owner_user_id=owner_user_id,
        bound_device_ids=bound_device_ids,
        bound_server_ids=bound_server_ids,
        allowed_artifact_kinds=normalized_artifacts,
        target_client=target_client,
        expires_at=expires_at,
        one_time=one_time,
        max_downloads=max_downloads,
    )


def evaluate_config_share_download(
    record: ConfigShareTokenRecord,
    *,
    requested_device_id: int,
    requested_artifact_kinds: tuple[str, ...],
    target_client: str,
    now: datetime,
) -> ConfigShareDownloadDecision:
    denial_category = _config_share_denial_category(
        record,
        requested_device_id=requested_device_id,
        requested_artifact_kinds=requested_artifact_kinds,
        target_client=target_client,
        now=now,
    )
    return ConfigShareDownloadDecision(
        allowed=denial_category is None,
        token_id=record.token_id,
        token_prefix=record.token_prefix,
        owner_user_id=record.owner_user_id,
        requested_device_id=requested_device_id,
        requested_artifact_kinds=tuple(sorted(requested_artifact_kinds)),
        target_client=target_client if target_client in SUPPORTED_TARGET_CLIENTS else "unsupported",
        denial_category=denial_category,
    )


def config_share_token_redacted_backup_metadata(
    record: ConfigShareTokenRecord,
) -> dict[str, object]:
    return {
        "token_id": record.token_id,
        "token_prefix": record.token_prefix,
        "purpose": record.purpose,
        "owner_user_id": record.owner_user_id,
        "bound_device_ids": list(record.bound_device_ids),
        "bound_server_ids": list(record.bound_server_ids),
        "allowed_artifact_kinds": list(record.allowed_artifact_kinds),
        "target_client": record.target_client,
        "restore_status": "restore-disabled",
        "token_hash_included": False,
    }


def _config_share_denial_category(
    record: ConfigShareTokenRecord,
    *,
    requested_device_id: int,
    requested_artifact_kinds: tuple[str, ...],
    target_client: str,
    now: datetime,
) -> ConfigShareDenialCategory | None:
    current_time = _as_utc(now)
    if record.purpose != CONFIG_SHARE_TOKEN_PURPOSE:
        return "wrong_purpose"
    if _as_utc(record.expires_at) <= current_time:
        return "expired_token"
    if record.revoked_at is not None:
        return "revoked_token"
    if record.download_count >= record.max_downloads:
        return "download_limit_reached"
    if record.one_time and record.download_count > 0:
        return "download_limit_reached"
    if record.owner_user_status != "active":
        return "inactive_owner"
    if record.device_status != "active":
        return "inactive_device"
    if record.server_status != "active":
        return "inactive_server"
    if requested_device_id not in record.bound_device_ids:
        return "resource_not_bound"
    if not requested_artifact_kinds:
        return "artifact_not_allowed"
    if any(artifact not in record.allowed_artifact_kinds for artifact in requested_artifact_kinds):
        return "artifact_not_allowed"
    if target_client not in SUPPORTED_TARGET_CLIENTS or target_client != record.target_client:
        return "unsupported_target_client"
    return None


def _validate_share_policy(
    *,
    created_by_actor: str,
    owner_user_id: int,
    bound_device_ids: tuple[int, ...],
    bound_server_ids: tuple[int, ...],
    allowed_artifact_kinds: tuple[str, ...],
    target_client: str,
    expires_at: datetime | None,
    issued_at: datetime,
    one_time: bool,
    max_downloads: int,
) -> None:
    if expires_at is None:
        raise ValueError("expires_at is required")
    if _as_utc(expires_at) <= issued_at:
        raise ValueError("future expiry is required")
    if not created_by_actor.strip():
        raise ValueError("created_by_actor is required")
    if owner_user_id <= 0:
        raise ValueError("owner_user_id is required")
    if not bound_device_ids:
        raise ValueError("bound_device_ids are required")
    if not bound_server_ids:
        raise ValueError("bound_server_ids are required")
    if any(device_id <= 0 for device_id in bound_device_ids):
        raise ValueError("bound_device_ids must be positive")
    if any(server_id <= 0 for server_id in bound_server_ids):
        raise ValueError("bound_server_ids must be positive")
    unsupported_artifacts = set(allowed_artifact_kinds) - SUPPORTED_ARTIFACTS
    if not allowed_artifact_kinds or unsupported_artifacts:
        raise ValueError(
            "unsupported artifact kinds: "
            + ", ".join(sorted(unsupported_artifacts or set(allowed_artifact_kinds)))
        )
    if target_client not in SUPPORTED_TARGET_CLIENTS:
        raise ValueError("unsupported target client")
    if max_downloads <= 0:
        raise ValueError("max_downloads must be positive")
    if one_time and max_downloads != 1:
        raise ValueError("max_downloads must be 1 for one-time shares")


def _format_datetime(value: datetime | None) -> str | None:
    if value is None:
        return None
    return _as_utc(value).isoformat()


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
