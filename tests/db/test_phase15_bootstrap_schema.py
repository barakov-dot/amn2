import sqlite3

import pytest

from app.db import phase15_bootstrap
from app.db.repositories import Repository
from app.db.schema import initialize_schema


EE66E108_PHASE15_SQL = """
CREATE TABLE telegram_callback_handles (
    handle_digest TEXT PRIMARY KEY,
    purpose TEXT NOT NULL,
    owner_user_id INTEGER NOT NULL,
    passport_device_id TEXT NOT NULL,
    client_platform TEXT,
    client_application TEXT,
    client_version TEXT,
    client_build TEXT,
    request_fingerprint TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    terminal_reason TEXT,
    UNIQUE(handle_digest, owner_user_id, passport_device_id),
    CHECK (
        (consumed_at IS NULL AND terminal_reason IS NULL)
        OR (consumed_at IS NOT NULL AND terminal_reason IS NOT NULL)
    ),
    FOREIGN KEY(owner_user_id) REFERENCES users(id),
    FOREIGN KEY(passport_device_id) REFERENCES device_passports(device_id)
);
CREATE INDEX idx_telegram_callback_handles_owner_passport
    ON telegram_callback_handles(owner_user_id, passport_device_id);
CREATE INDEX idx_telegram_callback_handles_expires_at
    ON telegram_callback_handles(expires_at);

CREATE TABLE protocol_issuance_confirmations (
    token_digest TEXT PRIMARY KEY,
    selection_handle_digest TEXT NOT NULL,
    owner_user_id INTEGER NOT NULL,
    passport_device_id TEXT NOT NULL,
    client_platform TEXT NOT NULL,
    client_application TEXT NOT NULL,
    client_version TEXT NOT NULL,
    client_build TEXT NOT NULL,
    request_fingerprint TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    terminal_reason TEXT,
    CHECK (
        (consumed_at IS NULL AND terminal_reason IS NULL)
        OR (consumed_at IS NOT NULL AND terminal_reason IS NOT NULL)
    ),
    FOREIGN KEY(selection_handle_digest, owner_user_id, passport_device_id)
        REFERENCES telegram_callback_handles(
            handle_digest, owner_user_id, passport_device_id
        ),
    FOREIGN KEY(owner_user_id) REFERENCES users(id),
    FOREIGN KEY(passport_device_id) REFERENCES device_passports(device_id)
);
CREATE INDEX idx_protocol_issuance_confirmations_owner_passport
    ON protocol_issuance_confirmations(owner_user_id, passport_device_id);
CREATE INDEX idx_protocol_issuance_confirmations_selection_handle
    ON protocol_issuance_confirmations(selection_handle_digest);
CREATE INDEX idx_protocol_issuance_confirmations_expires_at
    ON protocol_issuance_confirmations(expires_at);
"""

D827AFF_PHASE15_SQL = """
CREATE UNIQUE INDEX uq_device_passports_device_owner
    ON device_passports(device_id, owner_user_id);

CREATE TABLE telegram_callback_handles (
    handle_digest TEXT PRIMARY KEY
        CHECK (length(handle_digest) = 64
               AND handle_digest NOT GLOB '*[^0-9a-f]*'),
    purpose TEXT NOT NULL,
    owner_user_id INTEGER NOT NULL,
    passport_device_id TEXT NOT NULL,
    client_platform TEXT,
    client_application TEXT,
    client_version TEXT,
    client_build TEXT,
    request_fingerprint TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    claim_id_digest TEXT,
    claimed_at TEXT,
    claim_expires_at TEXT,
    consumed_at TEXT,
    terminal_reason TEXT,
    UNIQUE(handle_digest, owner_user_id, passport_device_id),
    CHECK (
        (claim_id_digest IS NULL AND claimed_at IS NULL AND claim_expires_at IS NULL)
        OR (
            length(claim_id_digest) = 64
            AND claim_id_digest NOT GLOB '*[^0-9a-f]*'
            AND claimed_at IS NOT NULL
            AND claim_expires_at IS NOT NULL
            AND claim_expires_at > claimed_at
        )
    ),
    CHECK (
        (consumed_at IS NULL AND terminal_reason IS NULL)
        OR (consumed_at IS NOT NULL AND terminal_reason IS NOT NULL)
    ),
    FOREIGN KEY(owner_user_id) REFERENCES users(id),
    FOREIGN KEY(passport_device_id, owner_user_id)
        REFERENCES device_passports(device_id, owner_user_id)
);
CREATE INDEX idx_telegram_callback_handles_owner_passport
    ON telegram_callback_handles(owner_user_id, passport_device_id);
CREATE INDEX idx_telegram_callback_handles_expires_at
    ON telegram_callback_handles(expires_at);

CREATE TABLE protocol_issuance_confirmations (
    token_digest TEXT PRIMARY KEY
        CHECK (length(token_digest) = 64
               AND token_digest NOT GLOB '*[^0-9a-f]*'),
    selection_handle_digest TEXT NOT NULL
        CHECK (length(selection_handle_digest) = 64
               AND selection_handle_digest NOT GLOB '*[^0-9a-f]*'),
    owner_user_id INTEGER NOT NULL,
    passport_device_id TEXT NOT NULL,
    client_platform TEXT NOT NULL,
    client_application TEXT NOT NULL,
    client_version TEXT NOT NULL,
    client_build TEXT NOT NULL,
    request_fingerprint TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    claim_id_digest TEXT,
    claimed_at TEXT,
    claim_expires_at TEXT,
    consumed_at TEXT,
    terminal_reason TEXT,
    CHECK (
        (claim_id_digest IS NULL AND claimed_at IS NULL AND claim_expires_at IS NULL)
        OR (
            length(claim_id_digest) = 64
            AND claim_id_digest NOT GLOB '*[^0-9a-f]*'
            AND claimed_at IS NOT NULL
            AND claim_expires_at IS NOT NULL
            AND claim_expires_at > claimed_at
        )
    ),
    CHECK (
        (consumed_at IS NULL AND terminal_reason IS NULL)
        OR (consumed_at IS NOT NULL AND terminal_reason IS NOT NULL)
    ),
    FOREIGN KEY(selection_handle_digest, owner_user_id, passport_device_id)
        REFERENCES telegram_callback_handles(
            handle_digest, owner_user_id, passport_device_id
        ),
    FOREIGN KEY(owner_user_id) REFERENCES users(id),
    FOREIGN KEY(passport_device_id, owner_user_id)
        REFERENCES device_passports(device_id, owner_user_id)
);
CREATE INDEX idx_protocol_issuance_confirmations_owner_passport
    ON protocol_issuance_confirmations(owner_user_id, passport_device_id);
CREATE INDEX idx_protocol_issuance_confirmations_selection_handle
    ON protocol_issuance_confirmations(selection_handle_digest);
CREATE INDEX idx_protocol_issuance_confirmations_expires_at
    ON protocol_issuance_confirmations(expires_at);
"""

NOW = "2026-08-14T10:05:00+00:00"
CLAIM_EXPIRES_AT = "2026-08-14T10:08:00+00:00"
CALLBACK_CLAIM_DIGEST = "1" * 64
CONFIRMATION_CLAIM_DIGEST = "2" * 64


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


def seed_exact_d827_schema(connection: sqlite3.Connection) -> int:
    owner_user_id = seed_owner_and_passport(connection)
    connection.executescript(
        """
        DROP TABLE protocol_issuance_confirmations;
        DROP TABLE telegram_callback_handles;
        CREATE INDEX idx_phase14_unrelated_owner_fixture
            ON device_passports(owner_user_id);
        """
    )
    connection.executescript(D827AFF_PHASE15_SQL)
    connection.execute(
        """
        INSERT INTO protocol_config_events (
            event_type, actor_kind, actor_id, reason, metadata_json
        ) VALUES ('d827_phase14_preserved', 'system', 15001, 'fixture', '{}')
        """
    )
    connection.executemany(
        """
        INSERT INTO telegram_callback_handles (
            handle_digest, purpose, owner_user_id, passport_device_id,
            client_platform, client_application, client_version,
            client_build, request_fingerprint, created_at, expires_at,
            claim_id_digest, claimed_at, claim_expires_at,
            consumed_at, terminal_reason
        ) VALUES (?, 'select_protocol', ?, 'passport-phase15', 'windows',
                  'amnezia_vpn', '5.0.0.5', ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            (
                "a" * 64,
                owner_user_id,
                "active-build",
                "sha256:" + "a" * 64,
                "2026-08-14T10:00:00+00:00",
                "2026-08-14T10:10:00+00:00",
                "1" * 64,
                NOW,
                CLAIM_EXPIRES_AT,
                None,
                None,
            ),
            (
                "c" * 64,
                owner_user_id,
                "consumed-build",
                "sha256:" + "c" * 64,
                "2026-08-14T09:55:00+00:00",
                "2026-08-14T10:10:00+00:00",
                "3" * 64,
                "2026-08-14T09:56:00+00:00",
                "2026-08-14T10:04:00+00:00",
                NOW,
                "protocol_selected",
            ),
        ),
    )
    connection.executemany(
        """
        INSERT INTO protocol_issuance_confirmations (
            token_digest, selection_handle_digest, owner_user_id,
            passport_device_id, client_platform, client_application,
            client_version, client_build, request_fingerprint,
            created_at, expires_at, claim_id_digest, claimed_at,
            claim_expires_at, consumed_at, terminal_reason
        ) VALUES (?, ?, ?, 'passport-phase15', 'windows', 'amnezia_vpn',
                  '5.0.0.5', ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            (
                "b" * 64,
                "a" * 64,
                owner_user_id,
                "active-build",
                "sha256:" + "b" * 64,
                "2026-08-14T10:01:00+00:00",
                "2026-08-14T10:11:00+00:00",
                "2" * 64,
                NOW,
                CLAIM_EXPIRES_AT,
                None,
                None,
            ),
            (
                "d" * 64,
                "c" * 64,
                owner_user_id,
                "consumed-build",
                "sha256:" + "d" * 64,
                "2026-08-14T09:57:00+00:00",
                "2026-08-14T10:11:00+00:00",
                "4" * 64,
                "2026-08-14T09:58:00+00:00",
                "2026-08-14T10:04:00+00:00",
                NOW,
                "issued",
            ),
        ),
    )
    connection.commit()
    return owner_user_id


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
            "claim_id_digest",
            "claimed_at",
            "claim_expires_at",
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
            "claim_id_digest",
            "claimed_at",
            "claim_expires_at",
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
            NOW,
            claim_id_digest=CALLBACK_CLAIM_DIGEST,
            claim_expires_at=CLAIM_EXPIRES_AT,
        ) is None
        claimed = restarted_repo.claim_callback_handle(
            "a" * 64,
            owner_user_id,
            NOW,
            claim_id_digest=CALLBACK_CLAIM_DIGEST,
            claim_expires_at=CLAIM_EXPIRES_AT,
        )
        assert isinstance(claimed, sqlite3.Row)
        assert claimed["request_fingerprint"] == "sha256:" + "a" * 64
        assert claimed["claim_id_digest"] == CALLBACK_CLAIM_DIGEST
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
            NOW,
            "protocol_selected",
            claim_id_digest=CALLBACK_CLAIM_DIGEST,
        ) is None
        claimed = repo.claim_callback_handle(
            "a" * 64,
            owner_user_id,
            NOW,
            claim_id_digest=CALLBACK_CLAIM_DIGEST,
            claim_expires_at=CLAIM_EXPIRES_AT,
        )
        assert claimed is not None

        consumed = repo.consume_callback_handle(
            "a" * 64,
            owner_user_id,
            NOW,
            "protocol_selected",
            claim_id_digest=CALLBACK_CLAIM_DIGEST,
        )
        assert isinstance(consumed, sqlite3.Row)
        assert consumed["consumed_at"] == "2026-08-14T10:05:00+00:00"
        assert consumed["terminal_reason"] == "protocol_selected"
        assert repo.claim_callback_handle(
            "a" * 64,
            owner_user_id,
            "2026-08-14T10:06:00+00:00",
            claim_id_digest="3" * 64,
            claim_expires_at="2026-08-14T10:09:00+00:00",
        ) is None
        assert repo.consume_callback_handle(
            "a" * 64,
            owner_user_id,
            "2026-08-14T10:06:00+00:00",
            "duplicate",
            claim_id_digest=CALLBACK_CLAIM_DIGEST,
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
            NOW,
            claim_id_digest=CONFIRMATION_CLAIM_DIGEST,
            claim_expires_at=CLAIM_EXPIRES_AT,
        ) is None
        assert repo.consume_issuance_confirmation(
            "b" * 64,
            other_owner_id,
            NOW,
            "issued",
            claim_id_digest=CONFIRMATION_CLAIM_DIGEST,
        ) is None
        claimed = repo.claim_issuance_confirmation(
            "b" * 64,
            owner_user_id,
            NOW,
            claim_id_digest=CONFIRMATION_CLAIM_DIGEST,
            claim_expires_at=CLAIM_EXPIRES_AT,
        )
        assert isinstance(claimed, sqlite3.Row)
        consumed = repo.consume_issuance_confirmation(
            "b" * 64,
            owner_user_id,
            NOW,
            "issued",
            claim_id_digest=CONFIRMATION_CLAIM_DIGEST,
        )
        assert isinstance(consumed, sqlite3.Row)
        assert consumed["terminal_reason"] == "issued"
        assert repo.claim_issuance_confirmation(
            "b" * 64,
            owner_user_id,
            "2026-08-14T10:06:00+00:00",
            claim_id_digest="4" * 64,
            claim_expires_at="2026-08-14T10:09:00+00:00",
        ) is None
    finally:
        connection.close()


def test_expired_callback_state_terminal_consume_is_owner_bound(database_path) -> None:
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
        expired_callback = callback_values(owner_user_id)
        expired_callback["expires_at"] = "2026-08-14T10:04:00+00:00"
        repo.create_callback_handle(**expired_callback)

        assert repo.consume_expired_callback_handle(
            "a" * 64, other_owner_id, NOW
        ) is None
        assert connection.execute(
            "SELECT consumed_at FROM telegram_callback_handles"
        ).fetchone()[0] is None

        consumed = repo.consume_expired_callback_handle(
            "a" * 64, owner_user_id, NOW
        )

        assert isinstance(consumed, sqlite3.Row)
        assert consumed["consumed_at"] == NOW
        assert consumed["terminal_reason"] == "expired"
    finally:
        connection.close()


def test_expired_confirmation_terminal_consume_is_owner_bound(database_path) -> None:
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
        expired_confirmation = confirmation_values(owner_user_id)
        expired_confirmation["expires_at"] = "2026-08-14T10:04:00+00:00"
        repo.create_issuance_confirmation(**expired_confirmation)

        assert repo.consume_expired_issuance_confirmation(
            "b" * 64, other_owner_id, NOW
        ) is None
        assert connection.execute(
            "SELECT consumed_at FROM protocol_issuance_confirmations"
        ).fetchone()[0] is None

        consumed = repo.consume_expired_issuance_confirmation(
            "b" * 64, owner_user_id, NOW
        )

        assert isinstance(consumed, sqlite3.Row)
        assert consumed["consumed_at"] == NOW
        assert consumed["terminal_reason"] == "expired"
    finally:
        connection.close()


def test_matching_claim_can_finalize_after_row_and_claim_ttl(database_path) -> None:
    connection = open_connection(database_path)
    try:
        owner_user_id = seed_owner_and_passport(connection)
        repo = Repository(connection)
        repo.create_callback_handle(**callback_values(owner_user_id))
        repo.create_issuance_confirmation(**confirmation_values(owner_user_id))
        assert repo.claim_callback_handle(
            "a" * 64,
            owner_user_id,
            NOW,
            claim_id_digest=CALLBACK_CLAIM_DIGEST,
            claim_expires_at="2026-08-14T10:06:00+00:00",
        ) is not None
        assert repo.claim_issuance_confirmation(
            "b" * 64,
            owner_user_id,
            NOW,
            claim_id_digest=CONFIRMATION_CLAIM_DIGEST,
            claim_expires_at="2026-08-14T10:06:00+00:00",
        ) is not None
        after_both_ttls = "2026-08-14T10:11:00+00:00"

        assert repo.consume_callback_handle(
            "a" * 64,
            owner_user_id,
            after_both_ttls,
            "protocol-selected",
            claim_id_digest="3" * 64,
        ) is None
        callback = repo.consume_callback_handle(
            "a" * 64,
            owner_user_id,
            after_both_ttls,
            "protocol-selected",
            claim_id_digest=CALLBACK_CLAIM_DIGEST,
        )
        confirmation = repo.consume_issuance_confirmation(
            "b" * 64,
            owner_user_id,
            after_both_ttls,
            "issued",
            claim_id_digest=CONFIRMATION_CLAIM_DIGEST,
        )

        assert callback is not None
        assert callback["terminal_reason"] == "protocol-selected"
        assert confirmation is not None
        assert confirmation["terminal_reason"] == "issued"
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
            NOW,
            claim_id_digest=CALLBACK_CLAIM_DIGEST,
            claim_expires_at=CLAIM_EXPIRES_AT,
        ) is not None
    finally:
        connection.close()


def test_callback_owner_and_passport_pair_is_database_bound(database_path) -> None:
    connection = open_connection(database_path)
    try:
        owner_user_id = seed_owner_and_passport(connection)
        other_owner_id = Repository(connection).upsert_user(
            telegram_id=15002,
            username="other",
            first_name="Other",
            last_name="Owner",
        )
        values = callback_values(owner_user_id)
        values["owner_user_id"] = other_owner_id

        with pytest.raises(sqlite3.IntegrityError):
            Repository(connection).create_callback_handle(**values)

        assert connection.execute(
            "SELECT COUNT(*) FROM telegram_callback_handles"
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT 1 FROM sqlite_master "
            "WHERE type = 'index' AND name = 'uq_device_passports_device_owner'"
        ).fetchone() is None
    finally:
        connection.close()


def test_phase15_digest_fields_reject_raw_and_non_lowercase_values(
    database_path,
) -> None:
    connection = open_connection(database_path)
    try:
        owner_user_id = seed_owner_and_passport(connection)
        repo = Repository(connection)
        invalid_callback = callback_values(owner_user_id)
        invalid_callback["handle_digest"] = "raw-callback-token"
        with pytest.raises(ValueError, match="handle_digest"):
            repo.create_callback_handle(**invalid_callback)
        invalid_callback["handle_digest"] = None
        with pytest.raises(ValueError, match="handle_digest"):
            repo.create_callback_handle(**invalid_callback)

        repo.create_callback_handle(**callback_values(owner_user_id))
        invalid_confirmation = confirmation_values(owner_user_id)
        invalid_confirmation["token_digest"] = "B" * 64
        with pytest.raises(ValueError, match="token_digest"):
            repo.create_issuance_confirmation(**invalid_confirmation)

        invalid_selection = confirmation_values(owner_user_id)
        invalid_selection["selection_handle_digest"] = "raw-selection-token"
        with pytest.raises(ValueError, match="selection_handle_digest"):
            repo.create_issuance_confirmation(**invalid_selection)

        with pytest.raises(ValueError, match="claim_id_digest"):
            repo.claim_callback_handle(
                "a" * 64,
                owner_user_id,
                NOW,
                claim_id_digest="raw-claim-token",
                claim_expires_at=CLAIM_EXPIRES_AT,
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                UPDATE telegram_callback_handles
                SET claim_id_digest = 'RAW',
                    claimed_at = ?,
                    claim_expires_at = ?
                WHERE handle_digest = ?
                """,
                (NOW, CLAIM_EXPIRES_AT, "a" * 64),
            )
    finally:
        connection.close()


def test_phase15_digest_constraints_reject_null_direct_sql(database_path) -> None:
    connection = open_connection(database_path)
    try:
        owner_user_id = seed_owner_and_passport(connection)
        repo = Repository(connection)
        repo.create_callback_handle(**callback_values(owner_user_id))
        repo.create_issuance_confirmation(**confirmation_values(owner_user_id))

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO telegram_callback_handles (
                    handle_digest, purpose, owner_user_id, passport_device_id,
                    request_fingerprint, created_at, expires_at
                ) VALUES (NULL, 'select_protocol', ?, 'passport-phase15',
                          ?, '2026-08-14T10:00:00+00:00',
                          '2026-08-14T10:10:00+00:00')
                """,
                (owner_user_id, "sha256:" + "c" * 64),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO protocol_issuance_confirmations (
                    token_digest, selection_handle_digest, owner_user_id,
                    passport_device_id, client_platform, client_application,
                    client_version, client_build, request_fingerprint,
                    created_at, expires_at
                ) VALUES (NULL, ?, ?, 'passport-phase15', 'windows',
                          'amnezia_vpn', '5.0.0.5', 'exact-build', ?,
                          '2026-08-14T10:01:00+00:00',
                          '2026-08-14T10:11:00+00:00')
                """,
                ("a" * 64, owner_user_id, "sha256:" + "d" * 64),
            )
        for table, identity_column, identity_digest in (
            ("telegram_callback_handles", "handle_digest", "a" * 64),
            ("protocol_issuance_confirmations", "token_digest", "b" * 64),
        ):
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(
                    f"""
                    UPDATE {table}
                    SET claim_id_digest = NULL,
                        claimed_at = ?,
                        claim_expires_at = ?
                    WHERE {identity_column} = ?
                    """,
                    (NOW, CLAIM_EXPIRES_AT, identity_digest),
                )
    finally:
        connection.close()


def test_competing_callback_claims_are_atomic_and_releasable(database_path) -> None:
    first = open_connection(database_path)
    owner_user_id = seed_owner_and_passport(first)
    other_owner_id = Repository(first).upsert_user(
        telegram_id=15002,
        username="other",
        first_name="Other",
        last_name="Owner",
    )
    Repository(first).create_callback_handle(**callback_values(owner_user_id))
    second = open_connection(database_path)
    try:
        first_repo = Repository(first)
        second_repo = Repository(second)
        first_claim = first_repo.claim_callback_handle(
            "a" * 64,
            owner_user_id,
            NOW,
            claim_id_digest=CALLBACK_CLAIM_DIGEST,
            claim_expires_at=CLAIM_EXPIRES_AT,
        )
        competing_claim = second_repo.claim_callback_handle(
            "a" * 64,
            owner_user_id,
            NOW,
            claim_id_digest="3" * 64,
            claim_expires_at=CLAIM_EXPIRES_AT,
        )
        assert [first_claim is not None, competing_claim is not None].count(True) == 1

        assert second_repo.release_callback_handle_claim(
            "a" * 64,
            other_owner_id,
            NOW,
            claim_id_digest=CALLBACK_CLAIM_DIGEST,
        ) is None
        assert second_repo.release_callback_handle_claim(
            "a" * 64,
            owner_user_id,
            NOW,
            claim_id_digest="3" * 64,
        ) is None
        assert second_repo.consume_callback_handle(
            "a" * 64,
            owner_user_id,
            NOW,
            "wrong-claim",
            claim_id_digest="3" * 64,
        ) is None

        released = first_repo.release_callback_handle_claim(
            "a" * 64,
            owner_user_id,
            NOW,
            claim_id_digest=CALLBACK_CLAIM_DIGEST,
        )
        assert isinstance(released, sqlite3.Row)
        assert tuple(
            released[key]
            for key in ("claim_id_digest", "claimed_at", "claim_expires_at")
        ) == (None, None, None)

        replacement = second_repo.claim_callback_handle(
            "a" * 64,
            owner_user_id,
            NOW,
            claim_id_digest="3" * 64,
            claim_expires_at=CLAIM_EXPIRES_AT,
        )
        assert isinstance(replacement, sqlite3.Row)
        consumed = second_repo.consume_callback_handle(
            "a" * 64,
            owner_user_id,
            NOW,
            "protocol-selected",
            claim_id_digest="3" * 64,
        )
        assert isinstance(consumed, sqlite3.Row)
        assert consumed["claim_id_digest"] == "3" * 64
        assert consumed["terminal_reason"] == "protocol-selected"
        assert first_repo.consume_callback_handle(
            "a" * 64,
            owner_user_id,
            NOW,
            "duplicate",
            claim_id_digest=CALLBACK_CLAIM_DIGEST,
        ) is None
    finally:
        second.close()
        first.close()


def test_confirmation_claim_survives_restart_and_expired_lease_is_replaced(
    database_path,
) -> None:
    setup = open_connection(database_path)
    owner_user_id = seed_owner_and_passport(setup)
    setup_repo = Repository(setup)
    setup_repo.create_callback_handle(**callback_values(owner_user_id))
    setup_repo.create_issuance_confirmation(**confirmation_values(owner_user_id))
    setup.close()

    first = open_connection(database_path)
    second = open_connection(database_path)
    try:
        first_repo = Repository(first)
        second_repo = Repository(second)
        first_claim = first_repo.claim_issuance_confirmation(
            "b" * 64,
            owner_user_id,
            NOW,
            claim_id_digest=CONFIRMATION_CLAIM_DIGEST,
            claim_expires_at="2026-08-14T10:06:00+00:00",
        )
        assert isinstance(first_claim, sqlite3.Row)
        assert second_repo.claim_issuance_confirmation(
            "b" * 64,
            owner_user_id,
            NOW,
            claim_id_digest="4" * 64,
            claim_expires_at=CLAIM_EXPIRES_AT,
        ) is None

        replacement = second_repo.claim_issuance_confirmation(
            "b" * 64,
            owner_user_id,
            "2026-08-14T10:07:00+00:00",
            claim_id_digest="4" * 64,
            claim_expires_at="2026-08-14T10:09:00+00:00",
        )
        assert isinstance(replacement, sqlite3.Row)
        assert first_repo.release_issuance_confirmation_claim(
            "b" * 64,
            owner_user_id,
            "2026-08-14T10:07:00+00:00",
            claim_id_digest=CONFIRMATION_CLAIM_DIGEST,
        ) is None
        assert first_repo.consume_issuance_confirmation(
            "b" * 64,
            owner_user_id,
            "2026-08-14T10:07:00+00:00",
            "stale-worker",
            claim_id_digest=CONFIRMATION_CLAIM_DIGEST,
        ) is None
        consumed = second_repo.consume_issuance_confirmation(
            "b" * 64,
            owner_user_id,
            "2026-08-14T10:07:00+00:00",
            "issued",
            claim_id_digest="4" * 64,
        )
        assert isinstance(consumed, sqlite3.Row)
        assert consumed["claim_id_digest"] == "4" * 64
        assert consumed["terminal_reason"] == "issued"
    finally:
        second.close()
        first.close()


def test_exact_ee66e108_phase15_schema_upgrades_without_row_loss(
    database_path,
) -> None:
    connection = open_connection(database_path)
    try:
        owner_user_id = seed_owner_and_passport(connection)
        connection.executescript(
            """
            DROP TABLE protocol_issuance_confirmations;
            DROP TABLE telegram_callback_handles;
            """
        )
        connection.executescript(EE66E108_PHASE15_SQL)
        connection.execute(
            """
            INSERT INTO telegram_callback_handles (
                handle_digest, purpose, owner_user_id, passport_device_id,
                client_platform, client_application, client_version,
                client_build, request_fingerprint, created_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            tuple(callback_values(owner_user_id).values()),
        )
        connection.execute(
            """
            INSERT INTO protocol_issuance_confirmations (
                token_digest, selection_handle_digest, owner_user_id,
                passport_device_id, client_platform, client_application,
                client_version, client_build, request_fingerprint,
                created_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            tuple(confirmation_values(owner_user_id).values()),
        )
        connection.commit()

        initialize_schema(connection)
        initialize_schema(connection)

        callback = connection.execute(
            "SELECT * FROM telegram_callback_handles WHERE handle_digest = ?",
            ("a" * 64,),
        ).fetchone()
        confirmation = connection.execute(
            "SELECT * FROM protocol_issuance_confirmations WHERE token_digest = ?",
            ("b" * 64,),
        ).fetchone()
        assert callback is not None
        assert confirmation is not None
        assert tuple(
            callback[key]
            for key in ("claim_id_digest", "claimed_at", "claim_expires_at")
        ) == (None, None, None)
        assert tuple(
            confirmation[key]
            for key in ("claim_id_digest", "claimed_at", "claim_expires_at")
        ) == (None, None, None)
        assert callback["request_fingerprint"] == "sha256:" + "a" * 64
        assert confirmation["selection_handle_digest"] == "a" * 64
        assert list(connection.execute("PRAGMA foreign_key_check")) == []
        assert connection.execute(
            "SELECT 1 FROM sqlite_master "
            "WHERE type = 'index' AND name = 'uq_device_passports_device_owner'"
        ).fetchone() is None
    finally:
        connection.close()


def test_legacy_null_digest_is_rejected_before_rebuild(database_path) -> None:
    connection = open_connection(database_path)
    try:
        owner_user_id = seed_owner_and_passport(connection)
        connection.executescript(
            """
            DROP TABLE protocol_issuance_confirmations;
            DROP TABLE telegram_callback_handles;
            """
        )
        connection.executescript(EE66E108_PHASE15_SQL)
        connection.execute(
            """
            INSERT INTO telegram_callback_handles (
                handle_digest, purpose, owner_user_id, passport_device_id,
                request_fingerprint, created_at, expires_at
            ) VALUES (NULL, 'select_protocol', ?, 'passport-phase15', ?,
                      '2026-08-14T10:00:00+00:00',
                      '2026-08-14T10:10:00+00:00')
            """,
            (owner_user_id, "sha256:" + "a" * 64),
        )
        connection.commit()

        with pytest.raises(RuntimeError, match="incompatible"):
            initialize_schema(connection)

        assert connection.execute(
            "SELECT COUNT(*) FROM telegram_callback_handles "
            "WHERE handle_digest IS NULL"
        ).fetchone()[0] == 1
        assert [
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(telegram_callback_handles)"
            )
        ] == [
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
        assert int(connection.execute("PRAGMA foreign_keys").fetchone()[0]) == 1
    finally:
        connection.close()


@pytest.mark.parametrize("foreign_keys_enabled", [0, 1])
def test_legacy_rebuild_failure_rolls_back_schema_rows_indexes_and_pragma(
    database_path,
    monkeypatch,
    foreign_keys_enabled,
) -> None:
    connection = open_connection(database_path)
    try:
        owner_user_id = seed_owner_and_passport(connection)
        connection.executescript(
            """
            DROP TABLE protocol_issuance_confirmations;
            DROP TABLE telegram_callback_handles;
            """
        )
        connection.executescript(EE66E108_PHASE15_SQL)
        connection.execute(
            """
            INSERT INTO telegram_callback_handles (
                handle_digest, purpose, owner_user_id, passport_device_id,
                client_platform, client_application, client_version,
                client_build, request_fingerprint, created_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            tuple(callback_values(owner_user_id).values()),
        )
        connection.execute(
            """
            INSERT INTO protocol_issuance_confirmations (
                token_digest, selection_handle_digest, owner_user_id,
                passport_device_id, client_platform, client_application,
                client_version, client_build, request_fingerprint,
                created_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            tuple(confirmation_values(owner_user_id).values()),
        )
        connection.commit()
        connection.execute(f"PRAGMA foreign_keys = {foreign_keys_enabled}")
        before_objects = [
            tuple(row)
            for row in connection.execute(
                """
                SELECT type, name, tbl_name, sql
                FROM sqlite_master
                WHERE tbl_name IN (
                    'telegram_callback_handles',
                    'protocol_issuance_confirmations'
                )
                ORDER BY type, name
                """
            )
        ]
        before_callback = tuple(
            connection.execute(
                "SELECT * FROM telegram_callback_handles"
            ).fetchone()
        )
        before_confirmation = tuple(
            connection.execute(
                "SELECT * FROM protocol_issuance_confirmations"
            ).fetchone()
        )
        monkeypatch.setattr(
            phase15_bootstrap,
            "CREATE_CALLBACK_TABLE_SQL",
            "CREATE TABL controlled_failure",
        )

        with pytest.raises(sqlite3.OperationalError):
            initialize_schema(connection)

        after_objects = [
            tuple(row)
            for row in connection.execute(
                """
                SELECT type, name, tbl_name, sql
                FROM sqlite_master
                WHERE tbl_name IN (
                    'telegram_callback_handles',
                    'protocol_issuance_confirmations'
                )
                ORDER BY type, name
                """
            )
        ]
        assert after_objects == before_objects
        assert tuple(
            connection.execute(
                "SELECT * FROM telegram_callback_handles"
            ).fetchone()
        ) == before_callback
        assert tuple(
            connection.execute(
                "SELECT * FROM protocol_issuance_confirmations"
            ).fetchone()
        ) == before_confirmation
        assert connection.execute(
            "SELECT 1 FROM sqlite_master "
            "WHERE type = 'table' AND name IN ("
            "'telegram_callback_handles_legacy', "
            "'protocol_issuance_confirmations_legacy')"
        ).fetchone() is None
        assert int(connection.execute("PRAGMA foreign_keys").fetchone()[0]) == (
            foreign_keys_enabled
        )
    finally:
        connection.close()


@pytest.mark.parametrize("foreign_keys_enabled", [0, 1])
def test_d827_rebuild_failure_after_index_drop_restores_entire_database(
    database_path,
    monkeypatch,
    foreign_keys_enabled,
) -> None:
    connection = open_connection(database_path)
    try:
        seed_exact_d827_schema(connection)
        connection.execute(f"PRAGMA foreign_keys = {foreign_keys_enabled}")
        schema_objects_before = {
            (str(row[0]), str(row[1])): (str(row[2]), row[3])
            for row in connection.execute(
                "SELECT type, name, tbl_name, sql FROM sqlite_master "
                "WHERE type IN ('table', 'index', 'trigger')"
            )
        }
        device_owner_index_before = tuple(
            connection.execute(
                "SELECT type, name, tbl_name, sql FROM sqlite_master "
                "WHERE type = 'index' "
                "AND name = 'uq_device_passports_device_owner'"
            ).fetchone()
        )
        callbacks_before = [
            tuple(row)
            for row in connection.execute(
                "SELECT * FROM telegram_callback_handles ORDER BY handle_digest"
            )
        ]
        confirmations_before = [
            tuple(row)
            for row in connection.execute(
                "SELECT * FROM protocol_issuance_confirmations ORDER BY token_digest"
            )
        ]
        passport_before = tuple(
            connection.execute(
                "SELECT * FROM device_passports WHERE device_id = 'passport-phase15'"
            ).fetchone()
        )
        event_before = tuple(
            connection.execute(
                "SELECT * FROM protocol_config_events "
                "WHERE event_type = 'd827_phase14_preserved'"
            ).fetchone()
        )
        checkpoint_observed = False

        def fail_after_exact_index_drop(conn: sqlite3.Connection) -> None:
            nonlocal checkpoint_observed
            checkpoint_observed = True
            assert conn.execute(
                "SELECT 1 FROM sqlite_master "
                "WHERE type = 'index' "
                "AND name = 'uq_device_passports_device_owner'"
            ).fetchone() is None
            assert {
                str(row[0])
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' "
                    "AND name IN (?, ?, ?, ?)",
                    (
                        "telegram_callback_handles",
                        "protocol_issuance_confirmations",
                        "telegram_callback_handles_legacy",
                        "protocol_issuance_confirmations_legacy",
                    ),
                )
            } == {
                "telegram_callback_handles",
                "protocol_issuance_confirmations",
            }
            raise RuntimeError("controlled d827 post-index-drop failure")

        monkeypatch.setattr(
            phase15_bootstrap,
            "_validate_d827_index_drop",
            fail_after_exact_index_drop,
            raising=False,
        )

        with pytest.raises(
            RuntimeError, match="controlled d827 post-index-drop failure"
        ):
            initialize_schema(connection)

        assert checkpoint_observed
        assert {
            (str(row[0]), str(row[1])): (str(row[2]), row[3])
            for row in connection.execute(
                "SELECT type, name, tbl_name, sql FROM sqlite_master "
                "WHERE type IN ('table', 'index', 'trigger')"
            )
        } == schema_objects_before
        assert tuple(
            connection.execute(
                "SELECT type, name, tbl_name, sql FROM sqlite_master "
                "WHERE type = 'index' "
                "AND name = 'uq_device_passports_device_owner'"
            ).fetchone()
        ) == device_owner_index_before
        assert [
            tuple(row)
            for row in connection.execute(
                "SELECT * FROM telegram_callback_handles ORDER BY handle_digest"
            )
        ] == callbacks_before
        assert [
            tuple(row)
            for row in connection.execute(
                "SELECT * FROM protocol_issuance_confirmations ORDER BY token_digest"
            )
        ] == confirmations_before
        assert tuple(
            connection.execute(
                "SELECT * FROM device_passports WHERE device_id = 'passport-phase15'"
            ).fetchone()
        ) == passport_before
        assert tuple(
            connection.execute(
                "SELECT * FROM protocol_config_events "
                "WHERE event_type = 'd827_phase14_preserved'"
            ).fetchone()
        ) == event_before
        assert connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name IN ("
            "'telegram_callback_handles_legacy', "
            "'protocol_issuance_confirmations_legacy')"
        ).fetchone() is None
        assert int(connection.execute("PRAGMA foreign_keys").fetchone()[0]) == (
            foreign_keys_enabled
        )
    finally:
        connection.close()


def test_exact_d827aff_schema_upgrades_without_phase14_side_effects(
    database_path,
) -> None:
    connection = open_connection(database_path)
    try:
        owner_user_id = seed_exact_d827_schema(connection)

        callbacks_before = [
            tuple(row)
            for row in connection.execute(
                "SELECT * FROM telegram_callback_handles ORDER BY handle_digest"
            )
        ]
        confirmations_before = [
            tuple(row)
            for row in connection.execute(
                "SELECT * FROM protocol_issuance_confirmations ORDER BY token_digest"
            )
        ]
        passport_before = tuple(
            connection.execute(
                "SELECT * FROM device_passports WHERE device_id = 'passport-phase15'"
            ).fetchone()
        )
        phase14_indexes_before = {
            str(row[1])
            for row in connection.execute("PRAGMA index_list(device_passports)")
        }
        assert "uq_device_passports_device_owner" in phase14_indexes_before

        initialize_schema(connection)
        initialize_schema(connection)

        assert [
            tuple(row)
            for row in connection.execute(
                "SELECT * FROM telegram_callback_handles ORDER BY handle_digest"
            )
        ] == callbacks_before
        assert [
            tuple(row)
            for row in connection.execute(
                "SELECT * FROM protocol_issuance_confirmations ORDER BY token_digest"
            )
        ] == confirmations_before
        assert tuple(
            connection.execute(
                "SELECT * FROM device_passports WHERE device_id = 'passport-phase15'"
            ).fetchone()
        ) == passport_before
        phase14_indexes_after = {
            str(row[1])
            for row in connection.execute("PRAGMA index_list(device_passports)")
        }
        assert phase14_indexes_after == phase14_indexes_before - {
            "uq_device_passports_device_owner"
        }
        assert "idx_phase14_unrelated_owner_fixture" in phase14_indexes_after
        assert connection.execute(
            "SELECT event_type FROM protocol_config_events "
            "WHERE event_type = 'd827_phase14_preserved'"
        ).fetchone()[0] == "d827_phase14_preserved"
        assert {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'trigger' "
                "AND tbl_name IN (?, ?)",
                ("telegram_callback_handles", "protocol_issuance_confirmations"),
            )
        } == {
            "trg_phase15_callback_owner_passport_insert",
            "trg_phase15_callback_owner_passport_update",
            "trg_phase15_confirmation_owner_passport_insert",
            "trg_phase15_confirmation_owner_passport_update",
        }
        assert connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name IN ("
            "'telegram_callback_handles_legacy', "
            "'protocol_issuance_confirmations_legacy')"
        ).fetchone() is None
        assert list(connection.execute("PRAGMA foreign_key_check")) == []
    finally:
        connection.close()
