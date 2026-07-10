from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Mapping, Protocol, Sequence

from app.services.api_tokens import API_TOKEN_PRODUCTION_ROTATION_NOTICE_DAYS


class OperatorCredentialStatusStore(Protocol):
    def list_api_tokens_for_admin(
        self,
        *,
        limit: int,
    ) -> Sequence[Mapping[str, object]]: ...


@dataclass(frozen=True)
class OperatorCredentialStatusView:
    name: str
    owner_label: str
    integration_kind: str
    purpose: str
    scopes: tuple[str, ...]
    status: str
    expires_at: str | None
    last_used_at: str | None
    created_at: str


def build_operator_credential_statuses(
    store: OperatorCredentialStatusStore,
    *,
    now: datetime | str | None = None,
    limit: int = 20,
) -> list[OperatorCredentialStatusView]:
    if not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")
    current = _as_datetime(now)
    rotation_notice_at = current + timedelta(
        days=API_TOKEN_PRODUCTION_ROTATION_NOTICE_DAYS
    )

    statuses = []
    for row in store.list_api_tokens_for_admin(limit=limit):
        expires_at = _optional_datetime(row["expires_at"])
        if row["revoked_at"]:
            status = "revoked"
        elif expires_at is not None and expires_at <= current:
            status = "expired"
        elif expires_at is not None and expires_at <= rotation_notice_at:
            status = "rotation-due"
        else:
            status = "active"
        statuses.append(
            OperatorCredentialStatusView(
                name=str(row["name"]),
                owner_label=str(row["owner_label"]),
                integration_kind=str(row["integration_kind"]),
                purpose=str(row["purpose"]),
                scopes=_parse_scopes(row["scopes_json"]),
                status=status,
                expires_at=_optional_text(row["expires_at"]),
                last_used_at=_optional_text(row["last_used_at"]),
                created_at=str(row["created_at"]),
            )
        )
    return statuses


def _parse_scopes(value: object) -> tuple[str, ...]:
    parsed = json.loads(str(value))
    if not isinstance(parsed, list) or not all(
        isinstance(item, str) for item in parsed
    ):
        raise ValueError("credential scopes must be a JSON list of strings")
    return tuple(parsed)


def _as_datetime(value: datetime | str | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    return _parse_datetime(value)


def _optional_datetime(value: object) -> datetime | None:
    return None if value is None else _parse_datetime(str(value))


def _parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _optional_text(value: object) -> str | None:
    return None if value is None else str(value)
