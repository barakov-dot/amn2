from __future__ import annotations

import sqlite3

import pytest

from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.services.protocol_issuance_barrier import ProtocolIssuanceBarrierService


@pytest.fixture
def harness():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    initialize_schema(conn)
    repo = Repository(conn)
    user_id = repo.upsert_user(
        telegram_id=14100,
        username="barrier-user",
        first_name="Barrier",
        last_name="User",
    )
    server_id = repo.ensure_default_server(
        name="barrier-server", network_cidr="10.216.0.0/24"
    )
    device_id = repo.create_device(
        user_id=user_id,
        server_id=server_id,
        name="barrier-device",
        duration_days=30,
        vpn_ip="10.216.0.2",
        peer_public_key="barrier-public",
        peer_private_key_encrypted="encrypted-private",
        preshared_key_encrypted="encrypted-psk",
        config_version="amneziawg_v2",
        protocol_version="awg2",
    )
    repo.create_device_passport(
        device_id="barrier-passport",
        owner_user_id=user_id,
        local_device_id=device_id,
        platform="windows",
        official_client_type="amnezia_vpn",
        client_version="5.0.0.5",
        import_method="conf_file",
        config_schema_version="amneziawg_v2",
        config_fingerprint="sha256:" + "1" * 64,
        last_seen_at=None,
        acceptance_evidence=None,
    )
    try:
        yield conn, repo, user_id, device_id
    finally:
        conn.close()


def _reserve(repo: Repository, user_id: int, *, fingerprint: str):
    attempt = repo.reserve_protocol_issuance_attempt(
        owner_user_id=user_id,
        intended_passport_device_id="barrier-passport",
        passport_device_id="barrier-passport",
        protocol_version="awg3",
        request_fingerprint="sha256:" + fingerprint * 64,
        actor_kind="user",
        actor_id=14100,
        client_application="amnezia_vpn",
        client_platform="windows",
        client_version="5.0.0.5",
        client_build="exact-build",
        runtime_instance_id="barrier-runtime",
        compatibility_evidence_id="barrier-evidence",
    )
    assert attempt is not None
    return attempt


def test_begin_block_is_durable_before_snapshot_and_cancels_preissuer_reservations(
    harness,
):
    _conn, repo, user_id, device_id = harness
    attempt = _reserve(repo, user_id, fingerprint="2")

    plan = ProtocolIssuanceBarrierService(repo).begin_block(user_id)

    assert repo.get_user(user_id)["status"] == "blocked"
    assert repo.get_protocol_issuance_user_barrier(user_id)["state"] == "blocking"
    assert repo.get_protocol_issuance_attempt(int(attempt["id"]))["state"] == "cancelled"
    assert [int(row["id"]) for row in plan.devices] == [device_id]


def test_unknown_recovery_keeps_barrier_blocking_and_enable_denied(harness):
    _conn, repo, user_id, _device_id = harness
    attempt = _reserve(repo, user_id, fingerprint="3")
    repo.mark_protocol_issuance_attempt_recovery_required(
        int(attempt["id"]), local_device_id=None, reason_code="issuer_failed"
    )
    service = ProtocolIssuanceBarrierService(repo)

    service.begin_block(user_id)
    assert service.complete_block(user_id, removed_local_device_ids=set()) is False
    assert repo.get_protocol_issuance_user_barrier(user_id)["state"] == "blocking"
    with pytest.raises(ValueError, match="barrier is not blocked"):
        service.begin_enable(user_id)


def test_known_recovery_reconciles_only_after_exact_peer_removal_and_enable_releases(
    harness,
):
    _conn, repo, user_id, device_id = harness
    attempt = _reserve(repo, user_id, fingerprint="4")
    repo.mark_protocol_issuance_attempt_recovery_required(
        int(attempt["id"]), local_device_id=device_id, reason_code="finalization_failed"
    )
    service = ProtocolIssuanceBarrierService(repo)

    service.begin_block(user_id)
    assert service.complete_block(user_id, removed_local_device_ids=set()) is False
    assert repo.get_protocol_issuance_attempt(int(attempt["id"]))["state"] == "recovery_required"
    assert service.complete_block(
        user_id, removed_local_device_ids={device_id}
    ) is True
    assert repo.get_protocol_issuance_attempt(int(attempt["id"]))["state"] == "cancelled"
    assert repo.get_protocol_issuance_user_barrier(user_id)["state"] == "blocked"

    service.begin_enable(user_id)
    service.complete_enable(user_id)
    assert repo.get_protocol_issuance_user_barrier(user_id) is None
    assert repo.get_user(user_id)["status"] == "active"
