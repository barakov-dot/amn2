from __future__ import annotations

import json
import logging
import sqlite3
import threading
from datetime import datetime, timedelta, timezone

import pytest

from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.services.device_enrollment import (
    EnrollmentTicketUnavailable,
    build_device_enrollment_launch_boundary,
    claim_device_enrollment_ticket,
    get_device_enrollment_ticket,
    hash_enrollment_secret,
    issue_device_enrollment_ticket,
    list_device_enrollment_tickets,
    revoke_device_enrollment_ticket,
)
from app.services.device_passports import fingerprint_config


NOW = datetime(2026, 7, 11, 18, 0, tzinfo=timezone.utc)
RAW_TOKEN = "amn2_enroll_abcdefghijklmnopqrstuvwxyz0123456789"
CONFIG_FINGERPRINT = fingerprint_config("safe test config")


def test_successful_claim_creates_bound_device_passport():
    conn, repo, user_id = _repo()
    issue = _issue(repo, user_id=user_id)

    claim = claim_device_enrollment_ticket(
        repo,
        raw_token=issue.raw_token,
        idempotency_key="claim-request-1",
        official_client_type="amnezia_vpn",
        client_version="4.8.19.0",
        import_method="managed_ticket",
        config_fingerprint=CONFIG_FINGERPRINT,
        now=NOW + timedelta(minutes=1),
    )

    assert claim.ticket.status(now=NOW) == "claimed"
    assert claim.passport.owner_user_id == user_id
    assert claim.passport.platform == "android_tv"
    assert claim.passport.config_schema_version == "amneziawg_v2"
    assert claim.passport.device_id == claim.ticket.claimed_device_id
    assert claim.passport.acceptance_evidence.status == "pending"
    assert claim.idempotent_replay is False
    assert RAW_TOKEN not in "\n".join(conn.iterdump())


def test_repeated_claim_is_rejected_but_exact_retry_is_idempotent():
    _, repo, user_id = _repo()
    issue = _issue(repo, user_id=user_id)
    first = _claim(repo, issue.raw_token, idempotency_key="same-request")

    replay = _claim(repo, issue.raw_token, idempotency_key="same-request")

    assert replay.passport.device_id == first.passport.device_id
    assert replay.idempotent_replay is True
    with pytest.raises(EnrollmentTicketUnavailable, match="is unavailable"):
        _claim(repo, issue.raw_token, idempotency_key="different-request")


@pytest.mark.parametrize(
    "ticket_state",
    ["expired", "revoked", "invalid", "already_used"],
)
def test_unavailable_ticket_states_have_same_external_error(ticket_state):
    _, repo, user_id = _repo()
    issue = _issue(repo, user_id=user_id)
    if ticket_state == "revoked":
        revoke_device_enrollment_ticket(
            repo,
            ticket_id=issue.metadata.ticket_id,
            reason="operator revoked before claim",
            revoked_at=NOW + timedelta(minutes=1),
        )
        claim_time = NOW + timedelta(minutes=2)
        raw_token = issue.raw_token
    elif ticket_state == "invalid":
        claim_time = NOW + timedelta(minutes=2)
        raw_token = "amn2_enroll_invalid-but-long-enough-token-value"
    elif ticket_state == "already_used":
        _claim(repo, issue.raw_token, idempotency_key="first-use")
        claim_time = NOW + timedelta(minutes=2)
        raw_token = issue.raw_token
    else:
        claim_time = NOW + timedelta(hours=2)
        raw_token = issue.raw_token

    with pytest.raises(EnrollmentTicketUnavailable) as captured:
        _claim(repo, raw_token, idempotency_key=ticket_state, now=claim_time)

    assert str(captured.value) == "Device enrollment ticket is unavailable"


def test_concurrent_claim_allows_only_one_request(tmp_path):
    database_path = tmp_path / "enrollment.sqlite3"
    conn = sqlite3.connect(database_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    initialize_schema(conn)
    repo = Repository(conn)
    user_id = _seed_user(repo)
    issue = _issue(repo, user_id=user_id)
    conn.close()

    barrier = threading.Barrier(2)
    outcomes: list[tuple[str, str]] = []
    lock = threading.Lock()

    def worker(idempotency_key: str) -> None:
        worker_conn = sqlite3.connect(database_path, timeout=10)
        worker_conn.row_factory = sqlite3.Row
        worker_conn.execute("PRAGMA foreign_keys = ON")
        worker_repo = Repository(worker_conn)
        barrier.wait()
        try:
            claim = _claim(
                worker_repo,
                issue.raw_token,
                idempotency_key=idempotency_key,
            )
        except EnrollmentTicketUnavailable:
            result = ("rejected", idempotency_key)
        else:
            result = ("claimed", claim.passport.device_id)
        finally:
            worker_conn.close()
        with lock:
            outcomes.append(result)

    threads = [
        threading.Thread(target=worker, args=("concurrent-1",)),
        threading.Thread(target=worker, args=("concurrent-2",)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=15)

    assert sorted(outcome[0] for outcome in outcomes) == ["claimed", "rejected"]
    verify_conn = sqlite3.connect(database_path)
    passport_count = verify_conn.execute(
        "SELECT COUNT(*) FROM device_passports"
    ).fetchone()[0]
    assert passport_count == 1
    verify_conn.close()


def test_raw_token_is_absent_from_db_logs_audit_and_read_responses(caplog):
    conn, repo, user_id = _repo()
    with caplog.at_level(logging.DEBUG):
        issue = _issue(repo, user_id=user_id)
        logging.getLogger("test.enrollment").debug(
            "safe issue metadata: %s",
            issue.safe_metadata(now=NOW),
        )
    repo.record_admin_action(
        admin_telegram_id=9001,
        action="device_enrollment_ticket.issued",
        target_user_id=user_id,
        metadata=issue.safe_audit_metadata(),
    )

    database_dump = "\n".join(conn.iterdump())
    read_payload = {
        "detail": get_device_enrollment_ticket(
            repo,
            issue.metadata.ticket_id,
        ).safe_metadata(now=NOW),
        "list": [
            item.safe_metadata(now=NOW)
            for item in list_device_enrollment_tickets(repo, user_id=user_id)
        ],
    }
    audit = repo.list_admin_actions_for_target_user(user_id)[0]

    assert RAW_TOKEN not in database_dump
    assert RAW_TOKEN not in caplog.text
    assert RAW_TOKEN not in repr(issue)
    assert RAW_TOKEN not in str(audit["metadata_json"])
    assert RAW_TOKEN not in json.dumps(read_payload)
    assert "token_hash" not in json.dumps(read_payload)
    stored = conn.execute(
        "SELECT token_hash, token_prefix FROM device_enrollment_tickets"
    ).fetchone()
    assert stored["token_hash"] == hash_enrollment_secret(RAW_TOKEN)
    assert stored["token_prefix"] == RAW_TOKEN[:20]


def test_revoke_is_idempotent_and_ticket_does_not_expand_launch_gate():
    _, repo, user_id = _repo()
    issue = _issue(repo, user_id=user_id)

    first = revoke_device_enrollment_ticket(
        repo,
        ticket_id=issue.metadata.ticket_id,
        reason="operator cancellation",
        revoked_at=NOW,
    )
    second = revoke_device_enrollment_ticket(
        repo,
        ticket_id=issue.metadata.ticket_id,
        reason="operator cancellation",
        revoked_at=NOW,
    )

    assert first.status == "revoked"
    assert second.status == "already-revoked-or-unavailable"
    assert build_device_enrollment_launch_boundary() == {
        "implementation_mode": "local-service-only",
        "public_self_service_route": False,
        "launch_blocking": False,
        "live_vps_mutation": False,
        "telegram_config_delivery": False,
        "drift_auto_remediation": False,
        "required_before_route_enablement": [
            "SurfacePolicy binding",
            "separate self-service authentication",
            "rate limiting",
            "production route gate",
        ],
    }


def _repo() -> tuple[sqlite3.Connection, Repository, int]:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    initialize_schema(conn)
    repo = Repository(conn)
    return conn, repo, _seed_user(repo)


def _seed_user(repo: Repository) -> int:
    return repo.upsert_user(
        telegram_id=9001,
        username="enrollment-user",
        first_name="Enrollment",
        last_name="User",
    )


def _issue(repo: Repository, *, user_id: int):
    return issue_device_enrollment_ticket(
        repo,
        user_id=user_id,
        platform="android_tv",
        config_schema_version="amneziawg_v2",
        now=NOW,
        ttl=timedelta(minutes=30),
        ticket_id="ent_1234567890abcdef",
        raw_token=RAW_TOKEN,
    )


def _claim(
    repo: Repository,
    raw_token: str,
    *,
    idempotency_key: str,
    now: datetime = NOW + timedelta(minutes=1),
):
    return claim_device_enrollment_ticket(
        repo,
        raw_token=raw_token,
        idempotency_key=idempotency_key,
        official_client_type="amnezia_vpn",
        client_version="4.8.19.0",
        import_method="managed_ticket",
        config_fingerprint=CONFIG_FINGERPRINT,
        now=now,
    )
