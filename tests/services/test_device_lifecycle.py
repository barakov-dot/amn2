from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.services.device_enrollment import (
    claim_device_enrollment_ticket,
    issue_device_enrollment_ticket,
)
from app.services.device_lifecycle import (
    LifecycleEvidence,
    list_device_lifecycle_events,
    record_device_lifecycle_stage,
)
from app.services.device_passports import (
    DeviceAcceptanceEvidence,
    fingerprint_config,
    record_device_acceptance,
)


NOW = datetime(2026, 7, 12, 10, 0, tzinfo=timezone.utc)
RAW_TOKEN = "amn2_enroll_abcdefghijklmnopqrstuvwxyz0123456789"


def test_enrollment_lifecycle_records_all_safe_stages_and_durations():
    repo, user_id = _repo()
    issue = issue_device_enrollment_ticket(
        repo,
        user_id=user_id,
        platform="android_tv",
        config_schema_version="amneziawg_v2",
        now=NOW,
        raw_token=RAW_TOKEN,
        ticket_id="ent_lifecycle",
    )
    claim = claim_device_enrollment_ticket(
        repo,
        raw_token=issue.raw_token,
        idempotency_key="lifecycle-claim",
        official_client_type="amnezia_vpn",
        client_version="4.8.19.0",
        import_method="managed_ticket",
        config_fingerprint=fingerprint_config("config"),
        now=NOW + timedelta(seconds=5),
    )
    config_ready = record_device_lifecycle_stage(
        repo,
        ticket_id=issue.metadata.ticket_id,
        passport_device_id=claim.passport.device_id,
        stage="config_ready",
        status="completed",
        started_at=NOW + timedelta(seconds=5),
        occurred_at=NOW + timedelta(seconds=8),
        evidence=LifecycleEvidence(
            source="config_renderer",
            reference="schema:amneziawg_v2",
        ),
    )
    delivered = record_device_lifecycle_stage(
        repo,
        ticket_id=issue.metadata.ticket_id,
        passport_device_id=claim.passport.device_id,
        stage="delivered",
        status="completed",
        started_at=NOW + timedelta(seconds=8),
        occurred_at=NOW + timedelta(seconds=10),
        evidence=LifecycleEvidence(
            source="config_delivery",
            reference="one-time-delivery-completed",
        ),
    )
    record_device_acceptance(
        repo,
        device_id=claim.passport.device_id,
        last_seen_at=NOW + timedelta(seconds=15),
        evidence=DeviceAcceptanceEvidence(
            status="passed",
            source="manual_client_test",
            observed_at=NOW + timedelta(seconds=15),
            reference="android-tv-connect-pass",
        ),
    )

    lifecycle = list_device_lifecycle_events(
        repo,
        ticket_id=issue.metadata.ticket_id,
    )

    assert [event.stage for event in lifecycle] == [
        "issued",
        "claimed",
        "config_ready",
        "delivered",
        "acceptance_verified",
    ]
    assert [event.duration_ms for event in lifecycle] == [0, 5000, 3000, 2000, 5000]
    assert all(event.failure_stage is None for event in lifecycle)
    assert config_ready.safe_metadata()["evidence"] == {
        "source": "config_renderer",
        "reference": "schema:amneziawg_v2",
    }
    assert delivered.status == "completed"


def test_failed_stage_records_only_safe_failure_stage():
    repo, user_id = _repo()
    issue = issue_device_enrollment_ticket(
        repo,
        user_id=user_id,
        platform="windows",
        config_schema_version="amneziawg_v2",
        now=NOW,
        raw_token=RAW_TOKEN,
        ticket_id="ent_failure",
    )
    claim = claim_device_enrollment_ticket(
        repo,
        raw_token=issue.raw_token,
        idempotency_key="failure-claim",
        official_client_type="amnezia_vpn",
        client_version=None,
        import_method="managed_ticket",
        config_fingerprint=fingerprint_config("config"),
        now=NOW + timedelta(seconds=1),
    )

    event = record_device_lifecycle_stage(
        repo,
        ticket_id=issue.metadata.ticket_id,
        passport_device_id=claim.passport.device_id,
        stage="config_ready",
        status="failed",
        started_at=NOW + timedelta(seconds=1),
        occurred_at=NOW + timedelta(seconds=2),
        evidence=LifecycleEvidence(
            source="config_renderer",
            reference="render-failed-safe-code",
        ),
    )

    assert event.status == "failed"
    assert event.failure_stage == "config_ready"
    assert "client" not in str(event.safe_metadata()).lower()


def test_lifecycle_rejects_sensitive_multiline_evidence_and_stage_skips():
    repo, user_id = _repo()
    issue = issue_device_enrollment_ticket(
        repo,
        user_id=user_id,
        platform="ios",
        config_schema_version="amneziawg_v2",
        now=NOW,
        raw_token=RAW_TOKEN,
        ticket_id="ent_guard",
    )

    with pytest.raises(ValueError, match="requires claimed"):
        record_device_lifecycle_stage(
            repo,
            ticket_id=issue.metadata.ticket_id,
            stage="config_ready",
            status="completed",
            started_at=NOW,
            occurred_at=NOW,
            evidence=LifecycleEvidence(source="config_renderer", reference="not-ready"),
        )
    with pytest.raises(ValueError, match="one line"):
        record_device_lifecycle_stage(
            repo,
            ticket_id=issue.metadata.ticket_id,
            stage="claimed",
            status="failed",
            started_at=NOW,
            occurred_at=NOW,
            evidence=LifecycleEvidence(
                source="client-log",
                reference="sensitive first line\nraw client log",
            ),
        )


def _repo() -> tuple[Repository, int]:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    initialize_schema(conn)
    repo = Repository(conn)
    user_id = repo.upsert_user(
        telegram_id=12001,
        username="lifecycle-user",
        first_name="Lifecycle",
        last_name="User",
    )
    return repo, user_id
