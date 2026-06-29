from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from app.services.config_share_tokens import (
    CONFIG_SHARE_TOKEN_PURPOSE,
    ConfigShareTokenRecord,
    config_share_token_redacted_backup_metadata,
    create_config_share_token,
    evaluate_config_share_download,
    hash_config_share_token,
    redeem_config_share_download,
)


NOW = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)
EXPIRY = NOW + timedelta(minutes=30)


def test_create_config_share_token_requires_expiry_and_stores_hash_only():
    stored: dict[str, object] = {}

    class ShareStore:
        def create_config_share_token(self, **kwargs):
            stored.update(kwargs)

    issue = create_config_share_token(
        ShareStore(),
        token_id="share-token-1",
        raw_token="raw-share-token",
        created_by_actor="web-admin:7",
        owner_user_id=42,
        bound_device_ids=(10,),
        bound_server_ids=(3,),
        allowed_artifact_kinds=("wireguard_conf", "amnezia_import_uri"),
        target_client="amnezia_generic",
        expires_at=EXPIRY,
        created_at=NOW,
        one_time=True,
        max_downloads=1,
    )

    assert issue.raw_token == "raw-share-token"
    assert issue.token_hash == hash_config_share_token("raw-share-token")
    assert issue.token_prefix == "raw-shar"
    assert stored["token_hash"] == hash_config_share_token("raw-share-token")
    assert stored["token_prefix"] == "raw-shar"
    assert stored["purpose"] == CONFIG_SHARE_TOKEN_PURPOSE
    assert stored["allowed_artifact_kinds"] == ["amnezia_import_uri", "wireguard_conf"]
    assert "raw-share-token" not in str(stored)
    assert issue.safe_metadata() == {
        "token_id": "share-token-1",
        "token_prefix": "raw-shar",
        "purpose": "config_share",
        "created_by_actor": "web-admin:7",
        "owner_user_id": 42,
        "bound_device_ids": [10],
        "bound_server_ids": [3],
        "allowed_artifact_kinds": ["amnezia_import_uri", "wireguard_conf"],
        "target_client": "amnezia_generic",
        "expires_at": "2026-06-01T12:30:00+00:00",
        "one_time": True,
        "max_downloads": 1,
        "raw_token_display": "one-time",
    }
    assert "raw-share-token" not in str(issue.safe_metadata())
    assert issue.token_hash not in str(issue.safe_metadata())


def test_create_config_share_token_rejects_unsafe_policy_inputs():
    class ShareStore:
        def create_config_share_token(self, **kwargs):  # pragma: no cover
            raise AssertionError("invalid share token must not be stored")

    kwargs = dict(
        token_id="share-token-1",
        raw_token="raw-share-token",
        created_by_actor="web-admin:7",
        owner_user_id=42,
        bound_device_ids=(10,),
        bound_server_ids=(3,),
        allowed_artifact_kinds=("wireguard_conf",),
        target_client="amnezia_generic",
        expires_at=EXPIRY,
        created_at=NOW,
    )

    with pytest.raises(ValueError, match="expires_at is required"):
        create_config_share_token(ShareStore(), **{**kwargs, "expires_at": None})
    with pytest.raises(ValueError, match="future expiry"):
        create_config_share_token(ShareStore(), **{**kwargs, "expires_at": NOW})
    with pytest.raises(ValueError, match="bound_device_ids"):
        create_config_share_token(ShareStore(), **{**kwargs, "bound_device_ids": ()})
    with pytest.raises(ValueError, match="unsupported artifact"):
        create_config_share_token(
            ShareStore(),
            **{**kwargs, "allowed_artifact_kinds": ("wireguard_conf", "raw_private_key")},
        )
    with pytest.raises(ValueError, match="unsupported target client"):
        create_config_share_token(ShareStore(), **{**kwargs, "target_client": "unknown"})
    with pytest.raises(ValueError, match="max_downloads"):
        create_config_share_token(ShareStore(), **{**kwargs, "max_downloads": 0})


def test_evaluate_config_share_download_allows_only_bound_active_secret_request():
    decision = evaluate_config_share_download(
        _record(),
        requested_device_id=10,
        requested_artifact_kinds=("wireguard_conf",),
        target_client="amnezia_generic",
        now=NOW,
    )

    assert decision.allowed is True
    assert decision.event_name == "config.share.download_allowed"
    assert decision.consume_token is True
    assert decision.public_message is None
    assert decision.safe_audit_metadata() == {
        "event": "config.share.download_allowed",
        "status": "allowed",
        "denial_category": None,
        "policy_id": "share.config_download",
        "token_id": "share-token-1",
        "token_prefix": "raw-shar",
        "owner_user_id": 42,
        "requested_device_id": 10,
        "requested_artifact_kinds": ["wireguard_conf"],
        "target_client": "amnezia_generic",
        "secret_class": "client-config-secret",
    }


@pytest.mark.parametrize(
    ("record_overrides", "denial_category"),
    (
        ({"purpose": "verify_email"}, "wrong_purpose"),
        ({"expires_at": NOW}, "expired_token"),
        ({"revoked_at": NOW - timedelta(minutes=1)}, "revoked_token"),
        ({"download_count": 1}, "download_limit_reached"),
        ({"owner_user_status": "blocked"}, "inactive_owner"),
        ({"device_status": "revoked"}, "inactive_device"),
        ({"server_status": "disabled"}, "inactive_server"),
    ),
)
def test_evaluate_config_share_download_denies_invalid_share_states(
    record_overrides,
    denial_category,
):
    decision = evaluate_config_share_download(
        _record(**record_overrides),
        requested_device_id=10,
        requested_artifact_kinds=("wireguard_conf",),
        target_client="amnezia_generic",
        now=NOW,
    )

    assert decision.allowed is False
    assert decision.event_name == "config.share.download_denied"
    assert decision.denial_category == denial_category
    assert decision.public_message == "Config link is invalid or expired."
    assert decision.consume_token is False
    safe = decision.safe_audit_metadata()
    assert safe["denial_category"] == denial_category
    assert "raw-share-token" not in str(safe)
    assert "sha256:" not in str(safe)
    assert "vpn://" not in str(safe)
    assert "PrivateKey" not in str(safe)


@pytest.mark.parametrize(
    ("requested_device_id", "requested_artifact_kinds", "target_client", "denial_category"),
    (
        (11, ("wireguard_conf",), "amnezia_generic", "resource_not_bound"),
        (10, (), "amnezia_generic", "artifact_not_allowed"),
        (10, ("qr_png",), "amnezia_generic", "artifact_not_allowed"),
        (10, ("wireguard_conf",), "unknown", "unsupported_target_client"),
    ),
)
def test_evaluate_config_share_download_denies_unbound_or_unallowed_request(
    requested_device_id,
    requested_artifact_kinds,
    target_client,
    denial_category,
):
    decision = evaluate_config_share_download(
        _record(),
        requested_device_id=requested_device_id,
        requested_artifact_kinds=requested_artifact_kinds,
        target_client=target_client,
        now=NOW,
    )

    assert decision.allowed is False
    assert decision.denial_category == denial_category
    assert decision.public_message == "Config link is invalid or expired."


def test_redacted_backup_metadata_cannot_restore_usable_share_token():
    record = _record(token_hash=hash_config_share_token("raw-share-token"))

    metadata = config_share_token_redacted_backup_metadata(record)

    assert metadata == {
        "token_id": "share-token-1",
        "token_prefix": "raw-shar",
        "purpose": "config_share",
        "owner_user_id": 42,
        "bound_device_ids": [10],
        "bound_server_ids": [3],
        "allowed_artifact_kinds": ["wireguard_conf"],
        "target_client": "amnezia_generic",
        "restore_status": "restore-disabled",
        "token_hash_included": False,
    }
    assert "raw-share-token" not in str(metadata)
    assert record.token_hash not in str(metadata)


def test_redeem_config_share_download_allows_then_atomically_consumes_token():
    store = RecordingRedeemStore(record=_record())

    decision = redeem_config_share_download(
        store,
        raw_token="raw-share-token",
        requested_device_id=10,
        requested_artifact_kinds=("wireguard_conf",),
        target_client="amnezia_generic",
        now=NOW,
        used_at=NOW + timedelta(seconds=1),
        ip_hash="sha256:ip-hash",
    )

    assert decision.allowed is True
    assert store.lookups == [
        {
            "token_hash": hash_config_share_token("raw-share-token"),
            "now": "2026-06-01T12:00:00+00:00",
            "requested_device_id": 10,
        }
    ]
    assert store.redeems == [
        {
            "token_hash": hash_config_share_token("raw-share-token"),
            "now": "2026-06-01T12:00:00+00:00",
            "used_at": "2026-06-01T12:00:01+00:00",
            "ip_hash": "sha256:ip-hash",
        }
    ]
    assert "raw-share-token" not in str(decision.safe_audit_metadata())
    assert "sha256:" not in str(decision.safe_audit_metadata())


def test_redeem_config_share_download_denies_invalid_request_without_consuming_token():
    store = RecordingRedeemStore(record=_record())

    decision = redeem_config_share_download(
        store,
        raw_token="raw-share-token",
        requested_device_id=11,
        requested_artifact_kinds=("wireguard_conf",),
        target_client="amnezia_generic",
        now=NOW,
        used_at=NOW + timedelta(seconds=1),
    )

    assert decision.allowed is False
    assert decision.denial_category == "resource_not_bound"
    assert store.redeems == []
    assert decision.public_message == "Config link is invalid or expired."


def test_redeem_config_share_download_denies_when_atomic_consume_loses_race():
    store = RecordingRedeemStore(record=_record(), redeem_record=None)

    decision = redeem_config_share_download(
        store,
        raw_token="raw-share-token",
        requested_device_id=10,
        requested_artifact_kinds=("wireguard_conf",),
        target_client="amnezia_generic",
        now=NOW,
        used_at=NOW + timedelta(seconds=1),
    )

    assert decision.allowed is False
    assert decision.denial_category == "download_limit_reached"
    assert len(store.redeems) == 1


def _record(**overrides) -> ConfigShareTokenRecord:
    base = ConfigShareTokenRecord(
        token_id="share-token-1",
        token_hash=hash_config_share_token("raw-share-token"),
        token_prefix="raw-shar",
        purpose=CONFIG_SHARE_TOKEN_PURPOSE,
        created_by_actor="web-admin:7",
        owner_user_id=42,
        bound_device_ids=(10,),
        bound_server_ids=(3,),
        allowed_artifact_kinds=("wireguard_conf",),
        target_client="amnezia_generic",
        expires_at=EXPIRY,
        revoked_at=None,
        one_time=True,
        max_downloads=1,
        download_count=0,
        owner_user_status="active",
        device_status="active",
        server_status="active",
    )
    return replace(base, **overrides)


class RecordingRedeemStore:
    def __init__(self, *, record, redeem_record="same"):
        self.record = record
        self.redeem_record = record if redeem_record == "same" else redeem_record
        self.lookups = []
        self.redeems = []

    def get_config_share_token_for_auth(
        self,
        *,
        token_hash: str,
        now: str,
        requested_device_id: int | None = None,
    ):
        self.lookups.append(
            {
                "token_hash": token_hash,
                "now": now,
                "requested_device_id": requested_device_id,
            }
        )
        return self.record

    def redeem_config_share_token_for_auth(
        self,
        *,
        token_hash: str,
        now: str,
        used_at: str,
        ip_hash: str | None = None,
    ):
        self.redeems.append(
            {
                "token_hash": token_hash,
                "now": now,
                "used_at": used_at,
                "ip_hash": ip_hash,
            }
        )
        return self.redeem_record
