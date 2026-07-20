from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Mapping


DURATION = "duration"
ABSOLUTE = "absolute"
INDEFINITE = "indefinite"
ACCESS_EXPIRY_POLICIES = frozenset({DURATION, ABSOLUTE, INDEFINITE})


@dataclass(frozen=True)
class AccessExpiry:
    policy: str
    duration_days: int | None
    expires_at: str | None

    def __post_init__(self) -> None:
        if self.policy not in ACCESS_EXPIRY_POLICIES:
            raise ValueError("unsupported access expiry policy")
        if self.policy == DURATION:
            if (
                isinstance(self.duration_days, bool)
                or not isinstance(self.duration_days, int)
                or self.duration_days <= 0
                or self.expires_at is not None
            ):
                raise ValueError("duration expiry requires positive duration_days")
        elif self.policy == ABSOLUTE:
            if self.duration_days is not None or not self.expires_at:
                raise ValueError("absolute expiry requires expires_at")
        elif self.duration_days is not None or self.expires_at is not None:
            raise ValueError("indefinite expiry cannot contain a deadline")


def parse_access_expiry(
    value: object | None,
    *,
    now: datetime | None = None,
) -> AccessExpiry:
    if value is None:
        return AccessExpiry(INDEFINITE, None, None)
    if not isinstance(value, Mapping):
        raise ValueError("expiry must be an object")
    kind = value.get("kind")
    if kind == INDEFINITE:
        _require_exact_keys(value, {"kind"})
        return AccessExpiry(INDEFINITE, None, None)
    if kind == DURATION:
        _require_exact_keys(value, {"kind", "days"})
        days = value.get("days")
        if isinstance(days, bool) or not isinstance(days, int) or days <= 0:
            raise ValueError("duration days must be positive")
        return AccessExpiry(DURATION, days, None)
    if kind == ABSOLUTE:
        _require_exact_keys(value, {"kind", "expires_at"})
        raw = value.get("expires_at")
        if not isinstance(raw, str) or not raw.strip():
            raise ValueError("absolute expires_at must be a datetime")
        expires_at = _parse_datetime(raw)
        current = _as_utc(now or datetime.now(timezone.utc))
        if expires_at <= current:
            raise ValueError("absolute expires_at must be in the future")
        return AccessExpiry(ABSOLUTE, None, _format_datetime(expires_at))
    raise ValueError("unsupported access expiry kind")


def _require_exact_keys(value: Mapping[object, object], expected: set[str]) -> None:
    actual = set(value)
    unsupported = actual - expected
    missing = expected - actual
    if unsupported:
        raise ValueError(f"expiry has unsupported fields: {sorted(unsupported)}")
    if missing:
        raise ValueError(f"expiry is missing fields: {sorted(missing)}")


def _parse_datetime(value: str) -> datetime:
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = f"{normalized[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError("absolute expires_at must be an ISO-8601 datetime") from exc
    if parsed.tzinfo is None:
        raise ValueError("absolute expires_at must include a timezone")
    return _as_utc(parsed)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("datetime must include a timezone")
    return value.astimezone(timezone.utc)


def _format_datetime(value: datetime) -> str:
    return _as_utc(value).isoformat().replace("+00:00", "Z")
