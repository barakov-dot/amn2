from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone

import pytest

from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.services.device_passports import (
    DeviceAcceptanceEvidence,
    create_device_passport,
    fingerprint_config,
    get_device_passport,
    list_all_device_passports,
    list_device_passports,
    record_device_acceptance,
)


NOW = datetime(2026, 7, 11, 15, 0, tzinfo=timezone.utc)
RAW_CONFIG = "[Interface]\nPrivateKey = never-store-this\nAddress = 10.8.0.2/32\n"


def test_device_passport_uses_generated_stable_id_and_safe_config_fingerprint():
    conn, repo, user_id, local_device_id = _repo()

    passport = create_device_passport(
        repo,
        owner_user_id=user_id,
        local_device_id=local_device_id,
        platform="android_tv",
        official_client_type="amnezia_vpn",
        client_version="4.8.19.0",
        import_method="standard_conf",
        config_schema_version="amneziawg_v2",
        config_text=RAW_CONFIG,
    )

    assert passport.device_id.startswith("dev_")
    assert len(passport.device_id) == 36
    assert passport.config_fingerprint == fingerprint_config(RAW_CONFIG)
    assert passport.config_fingerprint == (
        "sha256:" + hashlib.sha256(RAW_CONFIG.encode()).hexdigest()
    )
    database_dump = "\n".join(conn.iterdump())
    assert "never-store-this" not in database_dump
    assert passport.reconciliation.drift_state == "unknown"
    assert passport.reconciliation.last_observed_at is None


def test_device_passport_safe_metadata_states_capability_boundary():
    _, repo, user_id, local_device_id = _repo()
    passport = create_device_passport(
        repo,
        owner_user_id=user_id,
        local_device_id=local_device_id,
        platform="windows",
        official_client_type="amnezia_vpn",
        import_method="standard_conf",
        config_schema_version="amneziawg_v2",
        config_text=RAW_CONFIG,
    )

    payload = passport.safe_metadata()

    assert payload["desired_state"]["peer_expected"] is True
    assert payload["observed_state"]["peer_present"] is None
    assert payload["drift_state"] == "unknown"
    assert payload["capability_boundary"] == {
        "hardware_fingerprint": False,
        "endpoint_posture": False,
        "device_impersonation_protection": False,
        "mdm": False,
        "amnezia_agent_present": False,
    }
    assert "PrivateKey" not in json.dumps(payload)


def test_acceptance_and_last_seen_can_be_recorded_without_config_material():
    _, repo, user_id, local_device_id = _repo()
    passport = create_device_passport(
        repo,
        owner_user_id=user_id,
        local_device_id=local_device_id,
        platform="ios",
        official_client_type="defaultvpn",
        import_method="standard_conf",
        config_schema_version="amneziawg_v2",
        config_text=RAW_CONFIG,
    )
    evidence = DeviceAcceptanceEvidence(
        status="passed",
        source="manual_client_test",
        observed_at=NOW,
        reference="cross-client-acceptance-20260711",
    )

    updated = record_device_acceptance(
        repo,
        device_id=passport.device_id,
        last_seen_at=NOW,
        evidence=evidence,
    )

    assert updated.last_seen_at == NOW
    assert updated.acceptance_evidence == evidence
    assert get_device_passport(repo, passport.device_id).acceptance_evidence == evidence


def test_passport_rejects_local_device_owned_by_another_user():
    _, repo, _, local_device_id = _repo()
    other_user_id = repo.upsert_user(
        telegram_id=8002,
        username="other",
        first_name="Other",
        last_name="User",
    )

    with pytest.raises(ValueError, match="does not belong"):
        create_device_passport(
            repo,
            owner_user_id=other_user_id,
            local_device_id=local_device_id,
            platform="android",
            official_client_type="amnezia_vpn",
            import_method="standard_conf",
            config_schema_version="amneziawg_v2",
            config_text=RAW_CONFIG,
        )


def test_passport_list_returns_only_owner_records():
    _, repo, user_id, local_device_id = _repo()
    passport = create_device_passport(
        repo,
        owner_user_id=user_id,
        local_device_id=local_device_id,
        platform="android_tv",
        official_client_type="amnezia_vpn",
        import_method="standard_conf",
        config_schema_version="amneziawg_v2",
        config_text=RAW_CONFIG,
    )

    assert [item.device_id for item in list_device_passports(repo, user_id)] == [
        passport.device_id
    ]
    assert list_device_passports(repo, user_id + 999) == ()


def test_global_passport_list_is_bounded_and_sorted_by_latest_update():
    conn, repo, first_owner_id, first_local_device_id = _repo()
    second_owner_id = repo.upsert_user(
        telegram_id=8002,
        username="second-passport-user",
        first_name="Second",
        last_name="Owner",
    )
    server_id = repo.ensure_default_server(
        name="server-1",
        network_cidr="10.8.0.0/24",
    )
    second_local_device_id = repo.create_device(
        user_id=second_owner_id,
        server_id=server_id,
        name="phone",
        duration_days=30,
        vpn_ip="10.8.0.3",
        peer_public_key="second-passport-public-key",
        peer_private_key_encrypted="encrypted-private-2",
        preshared_key_encrypted="encrypted-psk-2",
        config_version="amneziawg_v2",
    )
    first = create_device_passport(
        repo,
        owner_user_id=first_owner_id,
        local_device_id=first_local_device_id,
        platform="android_tv",
        official_client_type="amnezia_vpn",
        import_method="standard_conf",
        config_schema_version="amneziawg_v2",
        config_text="first-config",
    )
    second = create_device_passport(
        repo,
        owner_user_id=second_owner_id,
        local_device_id=second_local_device_id,
        platform="windows",
        official_client_type="amneziawg",
        import_method="standard_conf",
        config_schema_version="amneziawg_v2",
        config_text="second-config",
    )
    conn.execute(
        "UPDATE device_passports SET updated_at = ? WHERE device_id = ?",
        ("2026-07-18 11:00:00", first.device_id),
    )
    conn.execute(
        "UPDATE device_passports SET updated_at = ? WHERE device_id = ?",
        ("2026-07-18 12:00:00", second.device_id),
    )
    conn.commit()

    items = list_all_device_passports(repo, limit=1)

    assert [item.device_id for item in items] == [second.device_id]


@pytest.mark.parametrize("limit", [0, 101])
def test_global_passport_list_rejects_out_of_range_limit(limit: int):
    _, repo, _, _ = _repo()

    with pytest.raises(ValueError, match="limit must be between 1 and 100"):
        list_all_device_passports(repo, limit=limit)


def _repo() -> tuple[sqlite3.Connection, Repository, int, int]:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    initialize_schema(conn)
    repo = Repository(conn)
    user_id = repo.upsert_user(
        telegram_id=8001,
        username="passport-user",
        first_name="Passport",
        last_name="User",
    )
    server_id = repo.ensure_default_server(
        name="server-1",
        network_cidr="10.8.0.0/24",
    )
    device_id = repo.create_device(
        user_id=user_id,
        server_id=server_id,
        name="tv",
        duration_days=30,
        vpn_ip="10.8.0.2",
        peer_public_key="passport-public-key",
        peer_private_key_encrypted="encrypted-private",
        preshared_key_encrypted="encrypted-psk",
        config_version="amneziawg_v2",
    )
    return conn, repo, user_id, device_id
