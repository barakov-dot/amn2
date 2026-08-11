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
    cascade_revoke_protocol_config,
    cascade_revoke_physical_device,
)
from app.services.dual_protocol_profiles import DualProtocolProfileService
from app.services.access import RemoteOperationPartialFailure
from app.services.drift_diagnostics import DriftDiagnosticsService
from app.services.peer_inventory import RemotePeer
from app.vpn.protocol_versions import ProtocolVersion


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


def test_protocol_config_revoke_is_remote_first_and_preserves_sibling_profile():
    conn, repo, _, server_id, awg2_device_id, awg3_device_id, passport_id = (
        _seed_dual_profile_graph()
    )
    remover = RecordingPeerRemover()

    result = cascade_revoke_protocol_config(
        repo,
        local_device_id=awg3_device_id,
        reason="revoke selected awg3 config",
        revoked_at=NOW,
        peer_remover=remover,
        apply_remote=True,
    )

    assert remover.calls == [(server_id, "peer-public-awg3")]
    assert result.local_device_id == awg3_device_id
    assert result.protocol_version is ProtocolVersion.AWG3
    assert repo.get_device(awg3_device_id)["status"] == "revoked"
    assert repo.get_device(awg2_device_id)["status"] == "active"
    profiles = DualProtocolProfileService(repo)
    assert profiles.by_local_device_id(awg3_device_id).lifecycle_state == "revoked"
    assert profiles.by_local_device_id(awg2_device_id).lifecycle_state == "active"
    assert repo.get_device_passport(passport_id)["revoked_at"] is None
    assert conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 2
    assert "peer-public-awg3" not in str(result.safe_metadata())
    assert "private-awg3" not in str(result.safe_metadata())
    assert "psk-awg3" not in str(result.safe_metadata())


def test_protocol_config_revoke_reports_remote_changed_local_failed(
    monkeypatch: pytest.MonkeyPatch,
):
    _, repo, _, server_id, _, awg3_device_id, _ = _seed_dual_profile_graph()
    remover = RecordingPeerRemover()
    monkeypatch.setattr(
        repo,
        "transition_device_protocol_profile",
        lambda **_kwargs: False,
    )

    with pytest.raises(RemoteOperationPartialFailure) as failure:
        cascade_revoke_protocol_config(
            repo,
            local_device_id=awg3_device_id,
            reason="revoke selected awg3 config",
            revoked_at=NOW,
            peer_remover=remover,
            apply_remote=True,
        )

    assert remover.calls == [(server_id, "peer-public-awg3")]
    assert failure.value.result.consistency_status == "remote-changed-local-failed"
    assert failure.value.result.remote_applied is True
    assert failure.value.result.local_applied is False
    assert repo.get_device(awg3_device_id)["status"] == "active"


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


def _seed_dual_profile_graph() -> tuple[
    sqlite3.Connection, Repository, int, int, int, int, str
]:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    initialize_schema(conn)
    repo = Repository(conn)
    user_id = repo.upsert_user(
        telegram_id=13002,
        username="dual-revoke-user",
        first_name="Dual",
        last_name="Revoke",
    )
    server_id = repo.ensure_default_server(
        name="server-1",
        network_cidr="10.8.0.0/24",
    )
    awg2_device_id = repo.create_device(
        user_id=user_id,
        server_id=server_id,
        name="physical-device-awg2",
        duration_days=30,
        vpn_ip="10.8.0.2",
        peer_public_key="peer-public-awg2",
        peer_private_key_encrypted="private-awg2",
        preshared_key_encrypted="psk-awg2",
        config_version="amneziawg_v2",
        protocol_version="awg2",
    )
    awg3_device_id = repo.create_device(
        user_id=user_id,
        server_id=server_id,
        name="physical-device-awg3",
        duration_days=30,
        vpn_ip="10.8.0.3",
        peer_public_key="peer-public-awg3",
        peer_private_key_encrypted="private-awg3",
        preshared_key_encrypted="psk-awg3",
        config_version="amneziawg_v3",
        protocol_version="awg3",
    )
    passport_id = "device-dual-revoke"
    repo.create_device_passport(
        device_id=passport_id,
        owner_user_id=user_id,
        local_device_id=awg2_device_id,
        platform="windows",
        official_client_type="amnezia_vpn",
        client_version="5.0.0.5",
        import_method="conf_file",
        config_schema_version="amneziawg_v2",
        config_fingerprint="sha256:" + "2" * 64,
        last_seen_at=None,
        acceptance_evidence=None,
        protocol_version="awg2",
    )
    profiles = DualProtocolProfileService(repo)
    profiles.attach_active(passport_id, ProtocolVersion.AWG2, awg2_device_id)
    profiles.attach_active(passport_id, ProtocolVersion.AWG3, awg3_device_id)
    return (
        conn,
        repo,
        user_id,
        server_id,
        awg2_device_id,
        awg3_device_id,
        passport_id,
    )
