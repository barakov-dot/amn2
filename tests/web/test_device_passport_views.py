from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.services.device_passports import (
    DeviceAcceptanceEvidence,
    create_device_passport,
    record_device_acceptance,
)
from app.services.dual_protocol_profiles import DualProtocolProfileService
from app.vpn.protocol_versions import ProtocolVersion
from app.web.device_passports import (
    build_device_passport_detail_view,
    build_device_passport_list_view,
)


def test_list_view_contains_safe_owner_and_status_metadata():
    conn, repo, user_id, local_device_id, passport_id = _seed_passport()

    view = build_device_passport_list_view(repo)

    assert view["limit"] == 100
    assert view["count"] == 1
    item = view["items"][0]
    assert item["device_id"] == passport_id
    assert item["owner"] == {"id": user_id, "display": "@passport-owner"}
    assert item["local_device_id"] == local_device_id
    assert item["state"] == "active"
    assert item["acceptance_status"] == "passed"
    assert item["drift_state"] == "unknown"
    assert "never-store-projector-secret" not in json.dumps(view)
    assert "encrypted-private" not in json.dumps(view)
    assert "encrypted-psk" not in json.dumps(view)
    assert conn.in_transaction is False


def test_detail_view_contains_lifecycle_and_capability_boundary():
    _, repo, user_id, awg2_device_id, passport_id = _seed_passport()

    view = build_device_passport_detail_view(repo, passport_id)

    assert view["owner"]["id"] == user_id
    assert view["passport"]["device_id"] == passport_id
    assert view["passport"]["config_fingerprint"].startswith("sha256:")
    assert view["passport"]["capability_boundary"]["hardware_fingerprint"] is False
    assert view["passport"]["recommended_next_action"] == "collect_fresh_observation"
    assert view["lifecycle"] == []
    assert [card["protocol_version"] for card in view["protocol_cards"]] == [
        "awg2",
        "awg3",
    ]
    assert view["protocol_cards"][0]["local_device_id"] == awg2_device_id
    assert view["protocol_cards"][1]["local_device_id"] != awg2_device_id
    awg3 = view["protocol_cards"][1]
    assert awg3["runtime_instance_id"] == "rt-spain-awg3"
    assert awg3["client_version"] == "5.0.0.5"
    assert awg3["client_build"] == "win-5005-stable"
    assert awg3["lifecycle_state"] == "active"
    assert awg3["compatibility_evidence_id"] == "compat-win-5005-awg3"


def test_passport_owner_uses_operator_label_without_telegram_id():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    initialize_schema(conn)
    repo = Repository(conn)
    user_id = repo.create_operator_recipient(operator_label="Alice — Pixel 8")
    passport = create_device_passport(
        repo,
        owner_user_id=user_id,
        local_device_id=None,
        platform="android",
        official_client_type="amnezia_vpn",
        client_version=None,
        import_method="standard_conf",
        config_schema_version="amneziawg_v2",
        config_text="operator-config",
    )

    view = build_device_passport_detail_view(repo, passport.device_id)

    assert view["owner"] == {"id": user_id, "display": "Alice — Pixel 8"}


def _seed_passport() -> tuple[sqlite3.Connection, Repository, int, int, str]:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    initialize_schema(conn)
    repo = Repository(conn)
    user_id = repo.upsert_user(
        telegram_id=18001,
        username="passport-owner",
        first_name="Passport",
        last_name="Owner",
    )
    server_id = repo.ensure_default_server(
        name="server-1",
        network_cidr="10.8.0.0/24",
    )
    local_device_id = repo.create_device(
        user_id=user_id,
        server_id=server_id,
        name="operator-phone",
        duration_days=30,
        vpn_ip="10.8.0.22",
        peer_public_key="projector-public-key",
        peer_private_key_encrypted="encrypted-private",
        preshared_key_encrypted="encrypted-psk",
        config_version="amneziawg_v2",
    )
    passport = create_device_passport(
        repo,
        owner_user_id=user_id,
        local_device_id=local_device_id,
        platform="android",
        official_client_type="amnezia_vpn",
        client_version="4.8.19.0",
        import_method="standard_conf",
        config_schema_version="amneziawg_v2",
        config_text="never-store-projector-secret",
    )
    profiles = DualProtocolProfileService(repo)
    profiles.attach_active(passport.device_id, ProtocolVersion.AWG2, local_device_id)
    attempt = repo.reserve_protocol_issuance_attempt(
        passport_device_id=passport.device_id,
        protocol_version="awg3",
        request_fingerprint="sha256:" + "a" * 64,
        actor_kind="user",
        actor_id=18001,
        client_application="amnezia_vpn",
        client_platform="windows",
        client_version="5.0.0.5",
        client_build="win-5005-stable",
        runtime_instance_id="rt-spain-awg3",
        compatibility_evidence_id="compat-win-5005-awg3",
    )
    assert attempt is not None
    awg3_device_id = repo.create_device(
        user_id=user_id,
        server_id=server_id,
        name="operator-phone-awg3",
        duration_days=30,
        vpn_ip="10.8.0.23",
        peer_public_key="projector-awg3-public-key",
        peer_private_key_encrypted="synthetic-encrypted-awg3-private",
        preshared_key_encrypted="synthetic-encrypted-awg3-psk",
        config_version="amneziawg_v3",
        protocol_version="awg3",
        runtime_instance_id="rt-spain-awg3",
        compatibility_evidence_id="compat-win-5005-awg3",
        client_identity_evidence_status="verified",
    )
    with repo.transaction():
        profiles.attach_active(
            passport.device_id, ProtocolVersion.AWG3, awg3_device_id
        )
        repo.complete_protocol_issuance_attempt(
            int(attempt["id"]), local_device_id=awg3_device_id
        )
    now = datetime(2026, 7, 18, 12, 0, tzinfo=timezone.utc)
    record_device_acceptance(
        repo,
        device_id=passport.device_id,
        last_seen_at=now,
        evidence=DeviceAcceptanceEvidence(
            status="passed",
            source="manual_client_test",
            observed_at=now,
            reference="device-001-projector-pass",
        ),
    )
    return conn, repo, user_id, local_device_id, passport.device_id
