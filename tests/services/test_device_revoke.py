from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.services.config_delivery import build_device_config_delivery
from app.services.config_material import ConfigMaterialUnavailable
from app.services.device_enrollment import (
    claim_device_enrollment_ticket,
    get_device_enrollment_ticket,
    issue_device_enrollment_ticket,
)
from app.services.device_passports import (
    DeviceAcceptanceEvidence,
    attach_passport_to_local_device,
    fingerprint_config,
    get_device_passport,
    record_device_acceptance,
)
from app.services.device_revoke import (
    CascadeRevokeApplyRequired,
    build_physical_device_revoke_plan,
    cascade_revoke_physical_device,
)
from app.services.drift_diagnostics import DriftDiagnosticsService
from app.services.peer_inventory import RemotePeer


NOW = datetime(2026, 7, 12, 12, 0, tzinfo=timezone.utc)
RAW_TOKEN = "amn2_enroll_abcdefghijklmnopqrstuvwxyz0123456789"


def test_cascade_revoke_closes_remote_peer_ticket_delivery_assignment_and_passport():
    conn, repo, user_id, server_id, local_device_id = _seed_access_graph()
    issue = issue_device_enrollment_ticket(
        repo,
        user_id=user_id,
        platform="android_tv",
        config_schema_version="amneziawg_v2",
        now=NOW,
        raw_token=RAW_TOKEN,
        ticket_id="ent_revoke",
    )
    claim = claim_device_enrollment_ticket(
        repo,
        raw_token=issue.raw_token,
        idempotency_key="claim-for-revoke",
        official_client_type="amnezia_vpn",
        client_version="4.8.19.0",
        import_method="managed_ticket",
        config_fingerprint=fingerprint_config("config"),
        now=NOW + timedelta(seconds=1),
    )
    attach_passport_to_local_device(
        repo,
        passport_device_id=claim.passport.device_id,
        local_device_id=local_device_id,
    )
    delivery_token_id = repo.create_email_recovery_token(
        user_id=user_id,
        email="owner@example.test",
        token_hash="sha256:delivery-link",
        purpose="recover_config",
        device_id=local_device_id,
        expires_at="2026-07-13T12:00:00Z",
    )
    order_id = repo.create_order(
        user_id=user_id,
        plan_id=None,
        payment_mode="manual",
    )
    repo.mark_order_fulfilled(order_id, local_device_id)
    remover = RecordingPeerRemover()

    audit: list[dict[str, object]] = []
    result = cascade_revoke_physical_device(
        repo,
        local_device_id=local_device_id,
        reason="physical device lost",
        revoked_at=NOW + timedelta(minutes=1),
        peer_remover=remover,
        apply_remote=True,
        audit_recorder=audit.append,
    )

    assert remover.calls == [(server_id, "peer-public")]
    assert result.remote_peer_removed is True
    assert result.enrollment_tickets_revoked == 1
    assert result.delivery_links_closed == 1
    assert result.assignments_closed == 1
    assert audit[0]["passport_device_id"] == claim.passport.device_id
    assert audit[0]["device_rows_revoked"] == 1
    assert "peer-public" not in str(audit)
    assert "encrypted-private" not in str(audit)
    assert "encrypted-psk" not in str(audit)
    assert repo.get_device(local_device_id)["status"] == "revoked"
    passport = get_device_passport(repo, claim.passport.device_id)
    assert passport.revoked_at == NOW + timedelta(minutes=1)
    assert passport.revoke_reason == "physical device lost"
    assert get_device_enrollment_ticket(repo, issue.metadata.ticket_id).status(now=NOW) == (
        "revoked"
    )
    assert repo.get_order(order_id)["device_id"] is None
    delivery = conn.execute(
        "SELECT used_at FROM email_recovery_tokens WHERE id = ?",
        (delivery_token_id,),
    ).fetchone()
    assert delivery["used_at"] == "2026-07-12T12:01:00Z"
    with pytest.raises(ConfigMaterialUnavailable, match="inactive device"):
        build_device_config_delivery(
            repo=repo,
            secret_box=None,
            device=repo.get_device(local_device_id),
        )
    with pytest.raises(LookupError, match="passport not found"):
        record_device_acceptance(
            repo,
            device_id=claim.passport.device_id,
            last_seen_at=NOW + timedelta(minutes=2),
            evidence=DeviceAcceptanceEvidence(
                status="passed",
                source="manual_client_test",
                observed_at=NOW + timedelta(minutes=2),
                reference="late-reconnect-must-not-reactivate",
            ),
        )


def test_reconnect_and_repeated_observation_do_not_restore_revoked_access():
    _, repo, _, server_id, local_device_id = _seed_access_graph()
    remover = RecordingPeerRemover()
    cascade_revoke_physical_device(
        repo,
        local_device_id=local_device_id,
        reason="physical device lost",
        revoked_at=NOW,
        peer_remover=remover,
        apply_remote=True,
    )

    repo.mark_device_connected(
        local_device_id,
        connected_at="2026-07-12T12:05:00Z",
    )
    snapshots = DriftDiagnosticsService(repo).diagnose_inventory(
        server_id,
        [
            RemotePeer(
                peer_public_key="peer-public",
                allowed_ips="10.8.0.2/32",
                latest_handshake=1,
                rx_bytes=100,
                tx_bytes=200,
            )
        ],
        observed_at=NOW + timedelta(minutes=5),
        now=NOW + timedelta(minutes=5),
    )
    repeated = DriftDiagnosticsService(repo).diagnose_inventory(
        server_id,
        list(
            [
                RemotePeer(
                    peer_public_key="peer-public",
                    allowed_ips="10.8.0.2/32",
                    latest_handshake=2,
                    rx_bytes=300,
                    tx_bytes=400,
                )
            ]
        ),
        observed_at=NOW + timedelta(minutes=6),
        now=NOW + timedelta(minutes=6),
    )

    device = repo.get_device(local_device_id)
    assert device["status"] == "revoked"
    assert device["last_connected_at"] is None
    assert [snapshot.drift_state for snapshot in snapshots] == ["unexpected_remote"]
    assert [snapshot.drift_state for snapshot in repeated] == ["unexpected_remote"]
    assert all(
        snapshot.recommended_next_action == "review_unexpected_remote_before_apply"
        for snapshot in (*snapshots, *repeated)
    )


def test_cascade_revoke_refuses_local_only_and_keeps_access_active_on_remote_failure():
    _, repo, _, _, local_device_id = _seed_access_graph()
    plan = build_physical_device_revoke_plan(repo, local_device_id=local_device_id)

    with pytest.raises(CascadeRevokeApplyRequired) as blocked:
        cascade_revoke_physical_device(
            repo,
            local_device_id=local_device_id,
            reason="physical device lost",
            revoked_at=NOW,
            peer_remover=None,
            apply_remote=False,
        )

    assert blocked.value.plan == plan
    assert repo.get_device(local_device_id)["status"] == "active"
    assert "peer-public" not in str(plan.to_safe_metadata())

    with pytest.raises(RuntimeError, match="remote remove failed"):
        cascade_revoke_physical_device(
            repo,
            local_device_id=local_device_id,
            reason="physical device lost",
            revoked_at=NOW,
            peer_remover=RecordingPeerRemover(error=RuntimeError("remote remove failed")),
            apply_remote=True,
        )
    assert repo.get_device(local_device_id)["status"] == "active"


class RecordingPeerRemover:
    def __init__(self, *, error: Exception | None = None) -> None:
        self.error = error
        self.calls: list[tuple[int, str]] = []

    def remove_peer(self, *, server, peer_public_key: str) -> None:
        if self.error is not None:
            raise self.error
        self.calls.append((int(server["id"]), peer_public_key))


def _seed_access_graph() -> tuple[sqlite3.Connection, Repository, int, int, int]:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    initialize_schema(conn)
    repo = Repository(conn)
    user_id = repo.upsert_user(
        telegram_id=13001,
        username="revoke-user",
        first_name="Revoke",
        last_name="User",
    )
    server_id = repo.ensure_default_server(
        name="server-1",
        network_cidr="10.8.0.0/24",
    )
    device_id = repo.create_device(
        user_id=user_id,
        server_id=server_id,
        name="physical-device",
        duration_days=30,
        vpn_ip="10.8.0.2",
        peer_public_key="peer-public",
        peer_private_key_encrypted="encrypted-private",
        preshared_key_encrypted="encrypted-psk",
        config_version="amneziawg_v2",
    )
    return conn, repo, user_id, server_id, device_id
