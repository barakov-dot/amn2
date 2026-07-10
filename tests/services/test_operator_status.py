from datetime import datetime, timezone

from app.db.connection import connect
from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.services.operator_status import build_operator_status


def test_operator_status_is_aggregate_secret_safe_and_tracks_credential_lifecycle(
    tmp_path,
):
    conn = connect(tmp_path / "test.sqlite3")
    initialize_schema(conn)
    repo = Repository(conn)
    user_id = repo.upsert_user(
        telegram_id=1001,
        username="alice",
        first_name="Alice",
        last_name=None,
    )
    repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    repo.create_order(
        user_id=user_id,
        plan_id=None,
        payment_mode="manual_admin",
        requested_config_version="amneziawg_v2",
    )
    _create_token(repo, "active", "sha256:active-secret", "2026-06-20T00:00:00Z")
    _create_token(repo, "due", "sha256:due-secret", "2026-06-05T00:00:00Z")
    _create_token(repo, "expired", "sha256:expired-secret", "2026-05-31T00:00:00Z")
    _create_token(repo, "revoked", "sha256:revoked-secret", "2026-06-20T00:00:00Z")
    repo.revoke_api_token("revoked", "2026-05-30T00:00:00Z", reason="retired")

    status = build_operator_status(
        repo,
        now=datetime(2026, 6, 1, tzinfo=timezone.utc),
    )

    assert status.safe_metadata() == {
        "mode": "read-only",
        "users_active": 1,
        "users_blocked": 0,
        "servers_active": 1,
        "servers_degraded": 0,
        "devices_active": 0,
        "devices_disabled": 0,
        "pending_orders": 1,
        "credentials_active": 1,
        "credentials_rotation_due": 1,
        "credentials_expired": 1,
        "credentials_revoked": 1,
        "vps_writes_enabled": False,
        "public_config_delivery_enabled": False,
        "public_exposure_enabled": False,
    }
    serialized = str(status.safe_metadata())
    assert "active-secret" not in serialized
    assert "token_hash" not in serialized
    assert "telegram_id" not in serialized


def _create_token(repo, token_id: str, token_hash: str, expires_at: str) -> None:
    repo.create_api_token(
        token_id=token_id,
        name=token_id,
        owner_user_id=None,
        owner_label="ops",
        integration_kind="telegram_bot",
        purpose="Operator aggregate status",
        token_hash=token_hash,
        scopes=["server:read"],
        expires_at=expires_at,
    )
