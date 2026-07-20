from datetime import datetime, timezone

import pytest

from app.access_expiry import (
    ABSOLUTE,
    DURATION,
    INDEFINITE,
    AccessExpiry,
    parse_access_expiry,
)


NOW = datetime(2026, 7, 20, 10, 0, tzinfo=timezone.utc)


def test_omitted_expiry_is_indefinite():
    assert parse_access_expiry(None, now=NOW) == AccessExpiry(
        policy=INDEFINITE,
        duration_days=None,
        expires_at=None,
    )


def test_explicit_duration_is_positive_and_canonical():
    assert parse_access_expiry({"kind": "duration", "days": 90}, now=NOW) == (
        AccessExpiry(policy=DURATION, duration_days=90, expires_at=None)
    )
    with pytest.raises(ValueError, match="positive"):
        parse_access_expiry({"kind": "duration", "days": 0}, now=NOW)


def test_explicit_absolute_requires_future_utc_datetime():
    assert parse_access_expiry(
        {"kind": "absolute", "expires_at": "2026-08-01T12:30:00+03:00"},
        now=NOW,
    ) == AccessExpiry(
        policy=ABSOLUTE,
        duration_days=None,
        expires_at="2026-08-01T09:30:00Z",
    )
    with pytest.raises(ValueError, match="future"):
        parse_access_expiry(
            {"kind": "absolute", "expires_at": "2026-07-20T09:59:59Z"},
            now=NOW,
        )


def test_expiry_rejects_extra_or_conflicting_fields():
    with pytest.raises(ValueError, match="unsupported"):
        parse_access_expiry(
            {"kind": "indefinite", "duration_days": 30},
            now=NOW,
        )
    with pytest.raises(ValueError, match="unsupported"):
        parse_access_expiry(
            {
                "kind": "duration",
                "days": 30,
                "expires_at": "2026-08-01T00:00:00Z",
            },
            now=NOW,
        )
