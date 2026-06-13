from datetime import datetime, timedelta, timezone

import pytest

from app.services.api_tokens import (
    API_TOKEN_FIRST_SLICE_SCOPES,
    API_TOKEN_PRODUCTION_MAX_TTL_DAYS,
    ApiTokenAuthError,
    ApiTokenRecord,
    authenticate_api_token,
    build_api_token_production_policy,
    create_api_token,
    create_route_api_token,
    hash_api_token,
    revoke_api_token,
    rotate_api_token,
)


def test_hash_api_token_is_stable_prefixed_and_does_not_expose_raw_token():
    token_hash = hash_api_token("raw-api-token")

    assert token_hash == hash_api_token("raw-api-token")
    assert token_hash.startswith("sha256:")
    assert "raw-api-token" not in token_hash


def test_create_api_token_stores_hash_and_returns_raw_token_only_in_issue():
    stored: dict[str, object] = {}

    class TokenStore:
        def create_api_token(self, **kwargs):
            stored.update(kwargs)

    issue = create_api_token(
        TokenStore(),
        token_id="api-token-1",
        raw_token="raw-api-token",
        name="Monitoring",
        owner_label="ops",
        scopes={"server:read", "metrics:read"},
        expires_at=datetime(2026, 6, 8, 10, 0, tzinfo=timezone.utc),
    )

    assert issue.raw_token == "raw-api-token"
    assert issue.safe_metadata() == {
        "token_id": "api-token-1",
        "name": "Monitoring",
        "owner_label": "ops",
        "scopes": ["metrics:read", "server:read"],
        "expires_at": "2026-06-08T10:00:00+00:00",
        "raw_token_display": "one-time",
    }
    assert stored["token_hash"] == hash_api_token("raw-api-token")
    assert stored["scopes"] == ["metrics:read", "server:read"]
    assert "raw-api-token" not in str(stored)


def test_create_api_token_rejects_secret_read_or_write_scopes():
    class TokenStore:
        def create_api_token(self, **kwargs):  # pragma: no cover - must not be called
            raise AssertionError("token should not be stored")

    assert API_TOKEN_FIRST_SLICE_SCOPES == frozenset({"server:read", "metrics:read"})
    with pytest.raises(ValueError, match="unsupported API token scopes"):
        create_api_token(
            TokenStore(),
            token_id="api-token-1",
            raw_token="raw-api-token",
            name="Config reader",
            owner_label="ops",
            scopes={"config:read"},
            expires_at=None,
        )
    with pytest.raises(ValueError, match="unsupported API token scopes"):
        create_api_token(
            TokenStore(),
            token_id="api-token-2",
            raw_token="raw-api-token-2",
            name="Writer",
            owner_label="ops",
            scopes={"server:write"},
            expires_at=None,
        )


def test_api_token_production_policy_is_secret_free_and_blocks_future_surfaces():
    policy = build_api_token_production_policy()
    metadata = policy.safe_metadata()

    assert metadata == {
        "allowed_scopes": ["metrics:read", "server:read"],
        "blocked_scopes": [
            "backup:read",
            "backup:restore",
            "clients:write",
            "config:read",
            "local-agent:write",
            "server:write",
        ],
        "max_ttl_days": 30,
        "rotation_notice_days": 7,
        "raw_token_display": "one-time",
        "stored_secret_material": "sha256-token-hash-only",
        "safe_backup_behavior": "credential_digest_excluded_from_safe_exports",
        "audit_metadata": "safe-metadata-only",
    }
    assert "raw-api-token" not in str(metadata)
    assert "token_hash" not in str(metadata)


def test_create_route_api_token_requires_explicit_expiry():
    class TokenStore:
        def create_api_token(self, **kwargs):  # pragma: no cover - must not be called
            raise AssertionError("route-connected token without expiry must not be stored")

    with pytest.raises(ValueError, match="expires_at is required"):
        create_route_api_token(
            TokenStore(),
            token_id="api-token-1",
            raw_token="raw-api-token",
            name="Monitoring",
            owner_label="ops",
            scopes={"metrics:read"},
            expires_at=None,
        )


def test_create_route_api_token_rejects_expiry_beyond_production_ttl():
    class TokenStore:
        def create_api_token(self, **kwargs):  # pragma: no cover - must not be called
            raise AssertionError("overlong route-connected token must not be stored")

    now = datetime(2026, 6, 1, 10, 0, tzinfo=timezone.utc)
    with pytest.raises(ValueError, match="expires_at exceeds production API token ttl"):
        create_route_api_token(
            TokenStore(),
            token_id="api-token-1",
            raw_token="raw-api-token",
            name="Monitoring",
            owner_label="ops",
            scopes={"metrics:read"},
            expires_at=now + timedelta(days=API_TOKEN_PRODUCTION_MAX_TTL_DAYS, seconds=1),
            now=now,
        )


def test_create_route_api_token_accepts_expiry_within_production_ttl():
    stored: dict[str, object] = {}

    class TokenStore:
        def create_api_token(self, **kwargs):
            stored.update(kwargs)

    now = datetime(2026, 6, 1, 10, 0, tzinfo=timezone.utc)
    issue = create_route_api_token(
        TokenStore(),
        token_id="api-token-1",
        raw_token="raw-api-token",
        name="Monitoring",
        owner_label="ops",
        scopes={"metrics:read"},
        expires_at=now + timedelta(days=API_TOKEN_PRODUCTION_MAX_TTL_DAYS),
        now=now,
    )

    assert issue.safe_metadata()["expires_at"] == "2026-07-01T10:00:00+00:00"
    assert stored["expires_at"] == "2026-07-01T10:00:00+00:00"


def test_authenticate_api_token_accepts_matching_unexpired_scope():
    now = datetime(2026, 6, 1, 10, 0, tzinfo=timezone.utc)
    record = ApiTokenRecord(
        token_id="api-token-1",
        token_hash=hash_api_token("raw-api-token"),
        name="Monitoring",
        owner_label="ops",
        scopes=frozenset({"server:read"}),
        expires_at=now + timedelta(minutes=5),
    )

    authenticated = authenticate_api_token(
        "raw-api-token",
        tokens=(record,),
        required_scope="server:read",
        now=now,
    )

    assert authenticated.token_id == "api-token-1"
    assert authenticated.safe_audit_metadata() == {
        "token_id": "api-token-1",
        "name": "Monitoring",
        "owner_label": "ops",
        "owner_user_id": None,
        "scopes": ["server:read"],
    }


def test_authenticate_api_token_rejects_expired_revoked_and_missing_scope():
    now = datetime(2026, 6, 1, 10, 0, tzinfo=timezone.utc)
    expired = ApiTokenRecord(
        token_id="expired",
        token_hash=hash_api_token("expired-token"),
        name="Expired",
        owner_label="ops",
        scopes=frozenset({"server:read"}),
        expires_at=now,
    )
    revoked = ApiTokenRecord(
        token_id="revoked",
        token_hash=hash_api_token("revoked-token"),
        name="Revoked",
        owner_label="ops",
        scopes=frozenset({"server:read"}),
        revoked_at=now - timedelta(minutes=1),
    )
    limited = ApiTokenRecord(
        token_id="limited",
        token_hash=hash_api_token("limited-token"),
        name="Limited",
        owner_label="ops",
        scopes=frozenset({"metrics:read"}),
    )

    with pytest.raises(ApiTokenAuthError) as expired_error:
        authenticate_api_token(
            "expired-token",
            tokens=(expired,),
            required_scope="server:read",
            now=now,
        )
    assert expired_error.value.reason == "expired_token"

    with pytest.raises(ApiTokenAuthError) as revoked_error:
        authenticate_api_token(
            "revoked-token",
            tokens=(revoked,),
            required_scope="server:read",
            now=now,
        )
    assert revoked_error.value.reason == "revoked_token"

    with pytest.raises(ApiTokenAuthError) as scope_error:
        authenticate_api_token(
            "limited-token",
            tokens=(limited,),
            required_scope="server:read",
            now=now,
        )
    assert scope_error.value.reason == "missing_scope"


def test_authenticate_api_token_rejects_inactive_owner():
    now = datetime(2026, 6, 1, 10, 0, tzinfo=timezone.utc)
    record = ApiTokenRecord(
        token_id="api-token-1",
        token_hash=hash_api_token("raw-api-token"),
        name="Monitoring",
        owner_label="ops",
        owner_user_id=7,
        owner_status="blocked",
        scopes=frozenset({"server:read"}),
        expires_at=now + timedelta(minutes=5),
    )

    with pytest.raises(ApiTokenAuthError) as owner_error:
        authenticate_api_token(
            "raw-api-token",
            tokens=(record,),
            required_scope="server:read",
            now=now,
        )

    assert owner_error.value.reason == "inactive_owner"


def test_authenticate_api_token_checks_inactive_owner_before_scope():
    now = datetime(2026, 6, 1, 10, 0, tzinfo=timezone.utc)
    record = ApiTokenRecord(
        token_id="api-token-1",
        token_hash=hash_api_token("raw-api-token"),
        name="Monitoring",
        owner_label="ops",
        owner_user_id=7,
        owner_status="deleted",
        scopes=frozenset({"metrics:read"}),
        expires_at=now + timedelta(minutes=5),
    )

    with pytest.raises(ApiTokenAuthError) as owner_error:
        authenticate_api_token(
            "raw-api-token",
            tokens=(record,),
            required_scope="server:read",
            now=now,
        )

    assert owner_error.value.reason == "inactive_owner"


def test_revoke_api_token_is_idempotent_and_returns_safe_metadata():
    calls = []

    class TokenStore:
        def revoke_api_token(self, token_id, revoked_at, reason=None):
            calls.append((token_id, revoked_at, reason))
            return len(calls) == 1

    revoked_at = datetime(2026, 6, 1, 10, 5, tzinfo=timezone.utc)
    first = revoke_api_token(
        TokenStore(),
        token_id="api-token-1",
        revoked_at=revoked_at,
        reason="operator-requested",
    )
    second = revoke_api_token(
        TokenStore(),
        token_id="api-token-1",
        revoked_at=revoked_at,
        reason="operator-requested",
    )

    assert first.safe_metadata() == {
        "action": "api_token.revoked",
        "token_id": "api-token-1",
        "status": "revoked",
        "reason": "operator-requested",
        "revoked_at": "2026-06-01T10:05:00+00:00",
        "rotated_from_token_id": None,
    }
    assert second.safe_metadata()["status"] == "already-revoked-or-missing"
    assert "raw-api-token" not in str(first.safe_metadata())


def test_rotate_api_token_creates_new_token_then_revokes_old_without_secret_metadata():
    calls = []

    class TokenStore:
        def create_api_token(self, **kwargs):
            calls.append(("create", kwargs))

        def revoke_api_token(self, token_id, revoked_at, reason=None):
            calls.append(("revoke", token_id, revoked_at, reason))
            return True

    now = datetime(2026, 6, 1, 10, 0, tzinfo=timezone.utc)
    previous = ApiTokenRecord(
        token_id="old-token",
        token_hash=hash_api_token("old-raw-token"),
        name="Monitoring",
        owner_label="ops",
        owner_user_id=7,
        owner_status="active",
        scopes=frozenset({"server:read", "metrics:read"}),
        expires_at=now + timedelta(days=1),
    )

    rotation = rotate_api_token(
        TokenStore(),
        previous,
        new_token_id="new-token",
        raw_token="new-raw-token",
        expires_at=now + timedelta(days=30),
        rotated_at=now,
    )

    assert calls[0][0] == "create"
    assert calls[0][1]["owner_user_id"] == 7
    assert calls[0][1]["owner_label"] == "ops"
    assert calls[0][1]["scopes"] == ["metrics:read", "server:read"]
    assert calls[0][1]["rotated_from_token_id"] == "old-token"
    assert calls[1] == (
        "revoke",
        "old-token",
        "2026-06-01T10:00:00+00:00",
        "rotated",
    )
    assert rotation.issue.raw_token == "new-raw-token"
    assert rotation.safe_metadata() == {
        "action": "api_token.rotated",
        "status": "rotated",
        "old_token_id": "old-token",
        "new_token_id": "new-token",
        "owner_label": "ops",
        "owner_user_id": 7,
        "scopes": ["metrics:read", "server:read"],
        "expires_at": "2026-07-01T10:00:00+00:00",
        "raw_token_display": "one-time",
    }
    assert "old-raw-token" not in str(rotation.safe_metadata())
    assert "new-raw-token" not in str(rotation.safe_metadata())
    assert hash_api_token("new-raw-token") not in str(rotation.safe_metadata())
