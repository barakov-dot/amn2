from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.services.drift_diagnostics import (
    DesiredPeerState,
    DriftDiagnosticsService,
    ObservedPeerState,
    classify_reconciliation,
)
from app.services.peer_inventory import PeerInventoryError, RemotePeer


NOW = datetime(2026, 7, 11, 12, 0, tzinfo=timezone.utc)


def _desired(*, expected: bool | None = True) -> DesiredPeerState:
    return DesiredPeerState(
        peer_expected=expected,
        peer_public_key="public-key" if expected else None,
        allowed_ips=("10.8.0.2/32",) if expected else (),
        device_status="active" if expected else None,
    )


def _observed(
    *,
    present: bool | None = True,
    succeeded: bool = True,
) -> ObservedPeerState:
    return ObservedPeerState(
        peer_present=present,
        peer_public_key="public-key" if present else None,
        allowed_ips=("10.8.0.2/32",) if present else (),
        observation_succeeded=succeeded,
    )


@pytest.mark.parametrize(
    ("desired", "observed", "observed_at", "expected"),
    [
        (_desired(), _observed(), NOW, "aligned"),
        (_desired(), _observed(present=False), NOW, "missing_remote"),
        (
            _desired(expected=False),
            _observed(),
            NOW,
            "unexpected_remote",
        ),
        (_desired(), _observed(), NOW - timedelta(minutes=6), "stale_observation"),
        (
            _desired(),
            _observed(succeeded=False),
            NOW,
            "observation_failed",
        ),
        (
            _desired(expected=None),
            _observed(present=None),
            NOW,
            "unknown",
        ),
    ],
)
def test_drift_classification_is_deterministic(
    desired,
    observed,
    observed_at,
    expected,
):
    kwargs = {
        "subject_id": "device:7",
        "desired": desired,
        "observed": observed,
        "observed_at": observed_at,
        "now": NOW,
        "stale_after": timedelta(minutes=5),
    }

    first = classify_reconciliation(**kwargs)
    second = classify_reconciliation(**kwargs)

    assert first == second
    assert first.safe_metadata() == second.safe_metadata()
    assert first.drift_state == expected


def test_read_only_diagnostics_does_not_mutate_database(tmp_path):
    conn = sqlite3.connect(tmp_path / "drift.sqlite3")
    conn.row_factory = sqlite3.Row
    initialize_schema(conn)
    repo = Repository(conn)
    server_id, device_id = _seed_device(repo)
    device = repo.get_device(device_id)
    collector = StaticCollector(
        [
            RemotePeer(
                peer_public_key=str(device["peer_public_key"]),
                allowed_ips=f"{device['vpn_ip']}/32",
                latest_handshake=1,
                rx_bytes=2,
                tx_bytes=3,
            )
        ]
    )
    before = "\n".join(conn.iterdump())

    snapshots = DriftDiagnosticsService(repo).diagnose_server(
        server_id,
        collector,
        observed_at=NOW,
        now=NOW,
    )

    after = "\n".join(conn.iterdump())
    assert snapshots[0].drift_state == "aligned"
    assert snapshots[0].recommended_next_action == "none"
    assert before == after


def test_failed_collection_returns_safe_observation_failed_snapshot(tmp_path):
    conn = sqlite3.connect(tmp_path / "drift-failed.sqlite3")
    conn.row_factory = sqlite3.Row
    initialize_schema(conn)
    repo = Repository(conn)
    server_id, _ = _seed_device(repo)

    snapshots = DriftDiagnosticsService(repo).diagnose_server(
        server_id,
        FailingCollector(),
        observed_at=NOW,
        now=NOW,
    )

    assert [item.drift_state for item in snapshots] == ["observation_failed"]
    metadata = snapshots[0].safe_metadata()
    assert metadata["drift_reason"] == "remote_observation_failed"
    assert "sensitive stderr" not in str(metadata)


def test_unknown_remote_peer_is_reported_without_mutation(tmp_path):
    conn = sqlite3.connect(tmp_path / "drift-unknown.sqlite3")
    conn.row_factory = sqlite3.Row
    initialize_schema(conn)
    repo = Repository(conn)
    server_id = repo.ensure_default_server(
        name="server-1",
        network_cidr="10.8.0.0/24",
    )
    before = "\n".join(conn.iterdump())

    snapshots = DriftDiagnosticsService(repo).diagnose_server(
        server_id,
        StaticCollector(
            [
                RemotePeer(
                    peer_public_key="unexpected-public-key",
                    allowed_ips="10.8.0.99/32",
                    latest_handshake=0,
                    rx_bytes=0,
                    tx_bytes=0,
                )
            ]
        ),
        observed_at=NOW,
        now=NOW,
    )

    assert len(snapshots) == 1
    assert snapshots[0].drift_state == "unexpected_remote"
    assert snapshots[0].subject_id.startswith("remote:sha256:")
    assert before == "\n".join(conn.iterdump())


@pytest.mark.parametrize(
    ("desired_extra", "observed_extra", "reason"),
    [
        (
            {"protocol_version": "awg3"},
            {"protocol_version": "awg2"},
            "protocol_version_mismatch",
        ),
        (
            {"runtime_instance_id": "rt-a"},
            {"runtime_instance_id": "rt-b"},
            "runtime_instance_mismatch",
        ),
        (
            {"compatibility_evidence_id": None},
            {},
            "compatibility_evidence_missing",
        ),
        (
            {"compatibility_status": "stale"},
            {},
            "compatibility_evidence_stale",
        ),
        (
            {"runtime_state": "candidate"},
            {},
            "runtime_not_accepted",
        ),
    ],
)
def test_protocol_drift_reasons_are_explainable_and_read_only(
    desired_extra, observed_extra, reason
):
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    initialize_schema(conn)
    before = conn.total_changes
    desired_values = {
        "peer_expected": True,
        "peer_public_key": "peer",
        "allowed_ips": ("10.212.12.8/32",),
        "device_status": "active",
        "protocol_version": "awg3",
        "runtime_instance_id": "rt-a",
        "compatibility_evidence_id": "compat-a",
        "compatibility_status": "passed",
        "runtime_state": "accepted",
    }
    desired_values.update(desired_extra)
    observed_values = {
        "peer_present": True,
        "peer_public_key": "peer",
        "allowed_ips": ("10.212.12.8/32",),
        "observation_succeeded": True,
        "protocol_version": "awg3",
        "runtime_instance_id": "rt-a",
    }
    observed_values.update(observed_extra)
    snapshot = classify_reconciliation(
        subject_id="device:7",
        desired=DesiredPeerState(**desired_values),
        observed=ObservedPeerState(**observed_values),
        observed_at=NOW,
        now=NOW,
        stale_after=timedelta(minutes=5),
    )
    assert snapshot.drift_reason == reason
    assert conn.total_changes == before


class StaticCollector:
    def __init__(self, peers: list[RemotePeer]) -> None:
        self._peers = peers

    def collect(self, server_id: int) -> list[RemotePeer]:
        return list(self._peers)


class FailingCollector:
    def collect(self, server_id: int) -> list[RemotePeer]:
        raise PeerInventoryError("sensitive stderr must not escape")


def _seed_device(repo: Repository) -> tuple[int, int]:
    user_id = repo.upsert_user(
        telegram_id=7001,
        username="drift-user",
        first_name="Drift",
        last_name="User",
    )
    server_id = repo.ensure_default_server(
        name="server-1",
        network_cidr="10.8.0.0/24",
    )
    device_id = repo.create_device(
        user_id=user_id,
        server_id=server_id,
        name="phone",
        duration_days=30,
        vpn_ip="10.8.0.2",
        peer_public_key="public-key",
        peer_private_key_encrypted="encrypted-private",
        preshared_key_encrypted="encrypted-psk",
        config_version="amneziawg_v2",
    )
    return server_id, device_id
