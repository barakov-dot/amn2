import sqlite3

import pytest

from app.db.repositories import Repository
from app.db.schema import initialize_schema


@pytest.fixture
def database_path(tmp_path):
    return tmp_path / "phase15.sqlite3"


def open_connection(database_path) -> sqlite3.Connection:
    connection = sqlite3.connect(database_path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def seed_owner_and_passport(connection: sqlite3.Connection) -> int:
    initialize_schema(connection)
    repo = Repository(connection)
    owner_user_id = repo.upsert_user(
        telegram_id=15001,
        username="phase15",
        first_name="Phase",
        last_name="Fifteen",
    )
    repo.create_device_passport(
        device_id="passport-phase15",
        owner_user_id=owner_user_id,
        local_device_id=None,
        platform="windows",
        official_client_type="amnezia_vpn",
        client_version="5.0.0.5",
        import_method="file",
        config_schema_version="amneziawg_v2",
        config_fingerprint="sha256:" + "a" * 64,
        last_seen_at=None,
        acceptance_evidence=None,
    )
    return owner_user_id


def callback_values(owner_user_id: int, *, suffix: str = "a") -> dict[str, object]:
    return {
        "handle_digest": suffix * 64,
        "purpose": "select_protocol",
        "owner_user_id": owner_user_id,
        "passport_device_id": "passport-phase15",
        "client_platform": "windows",
        "client_application": "amnezia_vpn",
        "client_version": "5.0.0.5",
        "client_build": "exact-build",
        "request_fingerprint": "sha256:" + suffix * 64,
        "created_at": "2026-08-14T10:00:00+00:00",
        "expires_at": "2026-08-14T10:10:00+00:00",
    }


def confirmation_values(
    owner_user_id: int,
    *,
    suffix: str = "b",
    selection_handle_digest: str = "a" * 64,
) -> dict[str, object]:
    return {
        "token_digest": suffix * 64,
        "selection_handle_digest": selection_handle_digest,
        "owner_user_id": owner_user_id,
        "passport_device_id": "passport-phase15",
        "client_platform": "windows",
        "client_application": "amnezia_vpn",
        "client_version": "5.0.0.5",
        "client_build": "exact-build",
        "request_fingerprint": "sha256:" + suffix * 64,
        "created_at": "2026-08-14T10:01:00+00:00",
        "expires_at": "2026-08-14T10:11:00+00:00",
    }


def test_phase15_schema_is_idempotent_additive_and_indexed(database_path) -> None:
    connection = open_connection(database_path)
    try:
        owner_user_id = seed_owner_and_passport(connection)
        connection.execute(
            """
            INSERT INTO protocol_config_events (
                event_type, actor_kind, actor_id, reason, metadata_json
            ) VALUES ('phase14_preserved', 'system', 15001, 'fixture', '{}')
            """
        )
        connection.commit()

        initialize_schema(connection)

        callback_columns = [
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(telegram_callback_handles)"
            )
        ]
        assert callback_columns == [
            "handle_digest",
            "purpose",
            "owner_user_id",
            "passport_device_id",
            "client_platform",
            "client_application",
            "client_version",
            "client_build",
            "request_fingerprint",
            "created_at",
            "expires_at",
            "consumed_at",
            "terminal_reason",
        ]
        confirmation_columns = [
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(protocol_issuance_confirmations)"
            )
        ]
        assert confirmation_columns == [
            "token_digest",
            "selection_handle_digest",
            "owner_user_id",
            "passport_device_id",
            "client_platform",
            "client_application",
            "client_version",
            "client_build",
            "request_fingerprint",
            "created_at",
            "expires_at",
            "consumed_at",
            "terminal_reason",
        ]
        callback_indexes = {
            row[1]
            for row in connection.execute(
                "PRAGMA index_list(telegram_callback_handles)"
            )
        }
        assert {
            "idx_telegram_callback_handles_owner_passport",
            "idx_telegram_callback_handles_expires_at",
        } <= callback_indexes
        confirmation_indexes = {
            row[1]
            for row in connection.execute(
                "PRAGMA index_list(protocol_issuance_confirmations)"
            )
        }
        assert {
            "idx_protocol_issuance_confirmations_owner_passport",
            "idx_protocol_issuance_confirmations_selection_handle",
            "idx_protocol_issuance_confirmations_expires_at",
        } <= confirmation_indexes
        callback_foreign_keys = {
            (row[2], row[3], row[4])
            for row in connection.execute(
                "PRAGMA foreign_key_list(telegram_callback_handles)"
            )
        }
        assert {
            ("users", "owner_user_id", "id"),
            ("device_passports", "passport_device_id", "device_id"),
        } <= callback_foreign_keys
        confirmation_foreign_keys = {
            (row[2], row[3], row[4])
            for row in connection.execute(
                "PRAGMA foreign_key_list(protocol_issuance_confirmations)"
            )
        }
        assert {
            ("telegram_callback_handles", "selection_handle_digest", "handle_digest"),
            ("users", "owner_user_id", "id"),
            ("device_passports", "passport_device_id", "device_id"),
        } <= confirmation_foreign_keys
        assert connection.execute(
            "SELECT owner_user_id FROM device_passports "
            "WHERE device_id = 'passport-phase15'"
        ).fetchone()[0] == owner_user_id
        assert connection.execute(
            "SELECT event_type FROM protocol_config_events "
            "WHERE event_type = 'phase14_preserved'"
        ).fetchone()[0] == "phase14_preserved"
    finally:
        connection.close()


def test_callback_handle_is_unique_owner_bound_and_restart_visible(database_path) -> None:
    connection = open_connection(database_path)
    owner_user_id = seed_owner_and_passport(connection)
    other_owner_id = Repository(connection).upsert_user(
        telegram_id=15002,
        username="other",
        first_name="Other",
        last_name="Owner",
    )
    repo = Repository(connection)
    values = callback_values(owner_user_id)

    created = repo.create_callback_handle(**values)
    assert isinstance(created, sqlite3.Row)
    assert created["owner_user_id"] == owner_user_id
    assert created["passport_device_id"] == "passport-phase15"
    with pytest.raises(sqlite3.IntegrityError):
        repo.create_callback_handle(**values)

    connection.close()
    restarted = open_connection(database_path)
    try:
        restarted_repo = Repository(restarted)
        assert restarted_repo.claim_callback_handle(
            "a" * 64,
            other_owner_id,
            "2026-08-14T10:05:00+00:00",
        ) is None
        claimed = restarted_repo.claim_callback_handle(
            "a" * 64,
            owner_user_id,
            "2026-08-14T10:05:00+00:00",
        )
        assert isinstance(claimed, sqlite3.Row)
        assert claimed["request_fingerprint"] == "sha256:" + "a" * 64
    finally:
        restarted.close()


def test_callback_handle_terminal_consume_is_owner_bound(database_path) -> None:
    connection = open_connection(database_path)
    try:
        owner_user_id = seed_owner_and_passport(connection)
        other_owner_id = Repository(connection).upsert_user(
            telegram_id=15002,
            username="other",
            first_name="Other",
            last_name="Owner",
        )
        repo = Repository(connection)
        repo.create_callback_handle(**callback_values(owner_user_id))

        assert repo.consume_callback_handle(
            "a" * 64,
            other_owner_id,
            "2026-08-14T10:05:00+00:00",
            "protocol_selected",
        ) is None
        assert repo.claim_callback_handle(
            "a" * 64,
            owner_user_id,
            "2026-08-14T10:05:00+00:00",
        ) is not None

        consumed = repo.consume_callback_handle(
            "a" * 64,
            owner_user_id,
            "2026-08-14T10:05:00+00:00",
            "protocol_selected",
        )
        assert isinstance(consumed, sqlite3.Row)
        assert consumed["consumed_at"] == "2026-08-14T10:05:00+00:00"
        assert consumed["terminal_reason"] == "protocol_selected"
        assert repo.claim_callback_handle(
            "a" * 64,
            owner_user_id,
            "2026-08-14T10:06:00+00:00",
        ) is None
        assert repo.consume_callback_handle(
            "a" * 64,
            owner_user_id,
            "2026-08-14T10:06:00+00:00",
            "duplicate",
        ) is None
    finally:
        connection.close()


def test_issuance_confirmation_is_unique_exact_and_terminal(database_path) -> None:
    connection = open_connection(database_path)
    try:
        owner_user_id = seed_owner_and_passport(connection)
        other_owner_id = Repository(connection).upsert_user(
            telegram_id=15002,
            username="other",
            first_name="Other",
            last_name="Owner",
        )
        repo = Repository(connection)
        repo.create_callback_handle(**callback_values(owner_user_id))
        values = confirmation_values(owner_user_id)

        created = repo.create_issuance_confirmation(**values)
        assert isinstance(created, sqlite3.Row)
        assert tuple(created[key] for key in (
            "client_platform",
            "client_application",
            "client_version",
            "client_build",
        )) == ("windows", "amnezia_vpn", "5.0.0.5", "exact-build")
        with pytest.raises(sqlite3.IntegrityError):
            repo.create_issuance_confirmation(**values)

        assert repo.claim_issuance_confirmation(
            "b" * 64,
            other_owner_id,
            "2026-08-14T10:05:00+00:00",
        ) is None
        assert repo.consume_issuance_confirmation(
            "b" * 64,
            other_owner_id,
            "2026-08-14T10:05:00+00:00",
            "issued",
        ) is None
        claimed = repo.claim_issuance_confirmation(
            "b" * 64,
            owner_user_id,
            "2026-08-14T10:05:00+00:00",
        )
        assert isinstance(claimed, sqlite3.Row)
        consumed = repo.consume_issuance_confirmation(
            "b" * 64,
            owner_user_id,
            "2026-08-14T10:05:00+00:00",
            "issued",
        )
        assert isinstance(consumed, sqlite3.Row)
        assert consumed["terminal_reason"] == "issued"
        assert repo.claim_issuance_confirmation(
            "b" * 64,
            owner_user_id,
            "2026-08-14T10:06:00+00:00",
        ) is None
    finally:
        connection.close()


def test_prune_expired_callback_state_removes_only_expired_rows(database_path) -> None:
    connection = open_connection(database_path)
    try:
        owner_user_id = seed_owner_and_passport(connection)
        repo = Repository(connection)
        expired_callback = callback_values(owner_user_id, suffix="c")
        expired_callback["expires_at"] = "2026-08-14T10:02:00+00:00"
        repo.create_callback_handle(**expired_callback)
        repo.create_callback_handle(**callback_values(owner_user_id, suffix="d"))
        expired_confirmation = confirmation_values(
            owner_user_id,
            suffix="e",
            selection_handle_digest="c" * 64,
        )
        expired_confirmation["expires_at"] = "2026-08-14T10:03:00+00:00"
        repo.create_issuance_confirmation(**expired_confirmation)

        assert repo.prune_expired_phase15_callback_state(
            "2026-08-14T10:05:00+00:00"
        ) == 2
        assert connection.execute(
            "SELECT 1 FROM telegram_callback_handles WHERE handle_digest = ?",
            ("c" * 64,),
        ).fetchone() is None
        assert connection.execute(
            "SELECT 1 FROM protocol_issuance_confirmations WHERE token_digest = ?",
            ("e" * 64,),
        ).fetchone() is None
        assert repo.claim_callback_handle(
            "d" * 64,
            owner_user_id,
            "2026-08-14T10:05:00+00:00",
        ) is not None
    finally:
        connection.close()
