import sqlite3
import threading

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


def phase15_validation_snapshot(connection: sqlite3.Connection) -> tuple[object, ...]:
    return (
        int(connection.execute("PRAGMA foreign_keys").fetchone()[0]),
        tuple(
            tuple(row)
            for row in connection.execute(
                "SELECT type, name, tbl_name, sql FROM sqlite_master "
                "ORDER BY type, name"
            )
        ),
        tuple(
            tuple(row)
            for row in connection.execute(
                "SELECT * FROM telegram_callback_handles ORDER BY handle_digest"
            )
        ),
        tuple(
            tuple(row)
            for row in connection.execute(
                "SELECT * FROM protocol_issuance_confirmations ORDER BY token_digest"
            )
        ),
    )


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


def reserve_attempt(
    repo: Repository,
    owner_user_id: int,
    *,
    protocol_version: str,
    request_fingerprint: str = "sha256:" + "b" * 64,
):
    return repo.reserve_protocol_issuance_attempt(
        passport_device_id="passport-phase15",
        protocol_version=protocol_version,
        request_fingerprint=request_fingerprint,
        actor_kind="user",
        actor_id=15001,
        client_application="amnezia_vpn",
        client_platform="windows",
        client_version="5.0.0.5",
        client_build="exact-build",
        runtime_instance_id=f"spain-{protocol_version}-runtime",
        compatibility_evidence_id="exact-evidence",
        owner_user_id=owner_user_id,
        intended_passport_device_id="passport-phase15",
    )


def install_fix6_confirmation_schema(
    connection: sqlite3.Connection,
    *,
    partial_attempt_unique: bool = False,
    attempt_target: str = "protocol_issuance_attempts",
    extra_attempt_foreign_keys: tuple[tuple[str, str], ...] = (),
) -> None:
    install_confirmation_schema_with_attempt_foreign_keys(
        connection,
        attempt_foreign_keys=(
            ("issuance_attempt_id", attempt_target),
            *extra_attempt_foreign_keys,
        ),
        partial_attempt_unique=partial_attempt_unique,
    )


def install_confirmation_schema_with_attempt_foreign_keys(
    connection: sqlite3.Connection,
    *,
    attempt_foreign_keys: tuple[tuple[str, str], ...],
    partial_attempt_unique: bool = False,
    generated_confusable_attempt_source: bool = False,
) -> None:
    connection.execute("DROP TABLE protocol_issuance_confirmations")
    confirmation_sql = phase15_bootstrap.CREATE_CONFIRMATION_TABLE_SQL
    if generated_confusable_attempt_source:
        confirmation_sql = confirmation_sql.replace(
            "    issuance_attempt_id INTEGER,\n",
            "    issuance_attempt_id INTEGER,\n"
            "    iſsuance_attempt_id INTEGER "
            "GENERATED ALWAYS AS (issuance_attempt_id) VIRTUAL,\n",
        )
    attempt_foreign_key_sql = "".join(
        f"    FOREIGN KEY({source}) REFERENCES {target}(id),\n"
        for source, target in attempt_foreign_keys
    )
    if attempt_foreign_key_sql:
        confirmation_sql = confirmation_sql.replace(
            "    FOREIGN KEY(owner_user_id) REFERENCES users(id),\n",
            attempt_foreign_key_sql
            + "    FOREIGN KEY(owner_user_id) REFERENCES users(id),\n",
        )
    if partial_attempt_unique:
        confirmation_sql = confirmation_sql.replace(
            "    UNIQUE(issuance_attempt_id),\n", ""
        )
    connection.execute(confirmation_sql)
    if partial_attempt_unique:
        connection.execute(
            "CREATE UNIQUE INDEX uq_phase15_attempt_binding_partial "
            "ON protocol_issuance_confirmations(issuance_attempt_id) "
            "WHERE issuance_attempt_id IS NULL"
        )
    phase15_bootstrap._ensure_phase15_objects(connection)
    connection.commit()


def replace_phase15_table_shape(
    connection: sqlite3.Connection,
    *,
    callback_sql: str,
    confirmation_sql: str,
) -> None:
    foreign_keys_enabled = int(
        connection.execute("PRAGMA foreign_keys").fetchone()[0]
    )
    connection.commit()
    connection.execute("PRAGMA foreign_keys = OFF")
    connection.execute("DROP TABLE protocol_issuance_confirmations")
    connection.execute("DROP TABLE telegram_callback_handles")
    connection.execute(callback_sql)
    connection.execute(confirmation_sql)
    phase15_bootstrap._ensure_phase15_objects(connection)
    connection.commit()
    connection.execute(f"PRAGMA foreign_keys = {foreign_keys_enabled}")


def assert_phase15_shape_rejected_without_mutation(
    connection: sqlite3.Connection,
) -> None:
    before = phase15_validation_snapshot(connection)

    with pytest.raises(RuntimeError, match="unsupported phase15"):
        phase15_bootstrap.ensure_phase15_bootstrap_schema(connection)

    assert phase15_validation_snapshot(connection) == before


def replace_attempt_table_with_legacy(
    connection: sqlite3.Connection, attempt: sqlite3.Row
) -> None:
    connection.commit()
    connection.execute("PRAGMA foreign_keys = OFF")
    connection.execute("DROP INDEX uq_protocol_issuance_blocking_attempt")
    connection.execute("DROP TABLE protocol_issuance_attempts")
    connection.executescript(
        """
        CREATE TABLE protocol_issuance_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            passport_device_id TEXT NOT NULL,
            protocol_version TEXT NOT NULL,
            request_fingerprint TEXT NOT NULL,
            actor_kind TEXT NOT NULL,
            actor_id INTEGER NOT NULL,
            client_application TEXT NOT NULL,
            client_platform TEXT NOT NULL,
            client_version TEXT NOT NULL,
            client_build TEXT,
            runtime_instance_id TEXT,
            compatibility_evidence_id TEXT,
            state TEXT NOT NULL DEFAULT 'reserved',
            local_device_id INTEGER,
            reason_code TEXT,
            reserved_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            completed_at TEXT,
            cancelled_at TEXT,
            recovery_required_at TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE UNIQUE INDEX uq_protocol_issuance_blocking_attempt
        ON protocol_issuance_attempts(passport_device_id, protocol_version)
        WHERE state IN ('reserved','recovery_required');
        """
    )
    connection.execute(
        """
        INSERT INTO protocol_issuance_attempts (
            id, passport_device_id, protocol_version, request_fingerprint,
            actor_kind, actor_id, client_application, client_platform,
            client_version, client_build, runtime_instance_id,
            compatibility_evidence_id, state, local_device_id, reason_code,
            reserved_at, completed_at, cancelled_at, recovery_required_at,
            created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        tuple(
            attempt[column]
            for column in (
                "id",
                "passport_device_id",
                "protocol_version",
                "request_fingerprint",
                "actor_kind",
                "actor_id",
                "client_application",
                "client_platform",
                "client_version",
                "client_build",
                "runtime_instance_id",
                "compatibility_evidence_id",
                "state",
                "local_device_id",
                "reason_code",
                "reserved_at",
                "completed_at",
                "cancelled_at",
                "recovery_required_at",
                "created_at",
                "updated_at",
            )
        ),
    )
    connection.commit()


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
            "issuance_attempt_id",
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
        assert (
            "protocol_issuance_attempts",
            "issuance_attempt_id",
            "id",
        ) not in confirmation_foreign_keys
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


@pytest.mark.parametrize("protocol_version", ["awg2", "awg3"])
def test_exact_bound_attempt_protects_confirmation_across_repositories(
    database_path, protocol_version
) -> None:
    first = open_connection(database_path)
    owner_user_id = seed_owner_and_passport(first)
    first_repo = Repository(first)
    first_repo.create_callback_handle(**callback_values(owner_user_id))
    first_repo.create_issuance_confirmation(**confirmation_values(owner_user_id))
    assert first_repo.claim_issuance_confirmation(
        "b" * 64,
        owner_user_id,
        NOW,
        claim_id_digest=CONFIRMATION_CLAIM_DIGEST,
        claim_expires_at=CLAIM_EXPIRES_AT,
    ) is not None

    assert first_repo.renew_issuance_confirmation_claim(
        "b" * 64,
        owner_user_id,
        "2026-08-14T10:07:00+00:00",
        claim_id_digest="4" * 64,
        claim_expires_at="2026-08-14T10:12:00+00:00",
    ) is None
    renewed = first_repo.renew_issuance_confirmation_claim(
        "b" * 64,
        owner_user_id,
        "2026-08-14T10:07:00+00:00",
        claim_id_digest=CONFIRMATION_CLAIM_DIGEST,
        claim_expires_at="2026-08-14T10:12:00+00:00",
    )
    assert renewed is not None
    assert renewed["claim_id_digest"] == CONFIRMATION_CLAIM_DIGEST
    assert renewed["claim_expires_at"] == "2026-08-14T10:12:00+00:00"

    attempt = reserve_attempt(
        first_repo,
        owner_user_id,
        protocol_version=protocol_version,
    )
    assert attempt is not None
    bound = first_repo.bind_issuance_confirmation_attempt(
        "b" * 64,
        owner_user_id,
        claim_id_digest=CONFIRMATION_CLAIM_DIGEST,
        attempt_id=int(attempt["id"]),
    )
    assert bound is not None
    assert bound["issuance_attempt_id"] == attempt["id"]

    restarted = open_connection(database_path)
    try:
        restarted_repo = Repository(restarted)
        after_ttls = "2026-08-14T10:13:00+00:00"
        assert restarted_repo.consume_expired_issuance_confirmation(
            "b" * 64, owner_user_id, after_ttls
        ) is None
        assert restarted_repo.prune_expired_phase15_callback_state(after_ttls) == 0
        consumed = first_repo.consume_issuance_confirmation(
            "b" * 64,
            owner_user_id,
            after_ttls,
            "issued",
            claim_id_digest=CONFIRMATION_CLAIM_DIGEST,
        )
        assert consumed is not None
        assert consumed["terminal_reason"] == "issued"
    finally:
        restarted.close()
        first.close()


@pytest.mark.parametrize("attempt_state", ["reserved", "recovery_required"])
def test_bound_durable_attempt_prevents_confirmation_claim_replacement_after_lease(
    database_path, attempt_state
) -> None:
    first = open_connection(database_path)
    owner_user_id = seed_owner_and_passport(first)
    first_repo = Repository(first)
    first_repo.create_callback_handle(**callback_values(owner_user_id))
    first_repo.create_issuance_confirmation(**confirmation_values(owner_user_id))
    assert first_repo.claim_issuance_confirmation(
        "b" * 64,
        owner_user_id,
        NOW,
        claim_id_digest=CONFIRMATION_CLAIM_DIGEST,
        claim_expires_at="2026-08-14T10:06:00+00:00",
    ) is not None
    attempt = reserve_attempt(first_repo, owner_user_id, protocol_version="awg3")
    assert attempt is not None
    assert first_repo.bind_issuance_confirmation_attempt(
        "b" * 64,
        owner_user_id,
        claim_id_digest=CONFIRMATION_CLAIM_DIGEST,
        attempt_id=int(attempt["id"]),
    ) is not None
    if attempt_state == "recovery_required":
        attempt = first_repo.mark_protocol_issuance_attempt_recovery_required(
            int(attempt["id"]),
            local_device_id=None,
            reason_code="issuer_failed",
        )
        assert attempt["state"] == "recovery_required"

    second = open_connection(database_path)
    try:
        second_repo = Repository(second)
        after_claim_lease = "2026-08-14T10:07:00+00:00"
        replacement = second_repo.claim_issuance_confirmation(
            "b" * 64,
            owner_user_id,
            after_claim_lease,
            claim_id_digest="4" * 64,
            claim_expires_at="2026-08-14T10:09:00+00:00",
        )

        assert replacement is None
        consumed = first_repo.consume_issuance_confirmation(
            "b" * 64,
            owner_user_id,
            after_claim_lease,
            "issued",
            claim_id_digest=CONFIRMATION_CLAIM_DIGEST,
        )
        assert consumed is not None
        assert consumed["claim_id_digest"] == CONFIRMATION_CLAIM_DIGEST
        assert consumed["terminal_reason"] == "issued"
        stored_attempt = first_repo.get_protocol_issuance_attempt(int(attempt["id"]))
        assert stored_attempt is not None
        assert stored_attempt["state"] == attempt_state
    finally:
        second.close()
        first.close()


def test_ascii_case_variant_attempt_binding_prevents_claim_replacement_after_lease(
    database_path,
) -> None:
    first = open_connection(database_path)
    owner_user_id = seed_owner_and_passport(first)
    replace_phase15_table_shape(
        first,
        callback_sql=phase15_bootstrap.CREATE_CALLBACK_TABLE_SQL,
        confirmation_sql=phase15_bootstrap.CREATE_CONFIRMATION_TABLE_SQL.replace(
            "    issuance_attempt_id INTEGER,\n",
            "    ISSUANCE_ATTEMPT_ID INTEGER,\n",
        ),
    )
    phase15_bootstrap.ensure_phase15_bootstrap_schema(first)
    assert tuple(
        str(row[1])
        for row in first.execute(
            "PRAGMA table_info(protocol_issuance_confirmations)"
        )
    )[-1] == "ISSUANCE_ATTEMPT_ID"

    first_repo = Repository(first)
    first_repo.create_callback_handle(**callback_values(owner_user_id))
    first_repo.create_issuance_confirmation(**confirmation_values(owner_user_id))
    assert first_repo.claim_issuance_confirmation(
        "b" * 64,
        owner_user_id,
        NOW,
        claim_id_digest=CONFIRMATION_CLAIM_DIGEST,
        claim_expires_at="2026-08-14T10:06:00+00:00",
    ) is not None
    attempt = reserve_attempt(first_repo, owner_user_id, protocol_version="awg3")
    assert attempt is not None
    assert first_repo.bind_issuance_confirmation_attempt(
        "b" * 64,
        owner_user_id,
        claim_id_digest=CONFIRMATION_CLAIM_DIGEST,
        attempt_id=int(attempt["id"]),
    ) is not None

    second = open_connection(database_path)
    try:
        after_claim_lease = "2026-08-14T10:07:00+00:00"
        assert Repository(second).claim_issuance_confirmation(
            "b" * 64,
            owner_user_id,
            after_claim_lease,
            claim_id_digest="4" * 64,
            claim_expires_at="2026-08-14T10:09:00+00:00",
        ) is None
        consumed = first_repo.consume_issuance_confirmation(
            "b" * 64,
            owner_user_id,
            after_claim_lease,
            "issued",
            claim_id_digest=CONFIRMATION_CLAIM_DIGEST,
        )
        assert consumed is not None
        assert consumed["claim_id_digest"] == CONFIRMATION_CLAIM_DIGEST
        assert consumed["terminal_reason"] == "issued"
    finally:
        second.close()
        first.close()


def test_matching_unclaimed_duplicate_does_not_inherit_attempt_protection(
    database_path,
) -> None:
    first = open_connection(database_path)
    owner_user_id = seed_owner_and_passport(first)
    first_repo = Repository(first)
    first_repo.create_callback_handle(**callback_values(owner_user_id))
    first_repo.create_issuance_confirmation(**confirmation_values(owner_user_id))
    assert first_repo.claim_issuance_confirmation(
        "b" * 64,
        owner_user_id,
        NOW,
        claim_id_digest=CONFIRMATION_CLAIM_DIGEST,
        claim_expires_at=CLAIM_EXPIRES_AT,
    ) is not None
    attempt = reserve_attempt(first_repo, owner_user_id, protocol_version="awg3")
    assert attempt is not None
    assert first_repo.bind_issuance_confirmation_attempt(
        "b" * 64,
        owner_user_id,
        claim_id_digest=CONFIRMATION_CLAIM_DIGEST,
        attempt_id=int(attempt["id"]),
    ) is not None

    duplicate_callback = callback_values(owner_user_id, suffix="c")
    duplicate_callback["request_fingerprint"] = "sha256:" + "b" * 64
    duplicate_callback["expires_at"] = "2026-08-14T10:06:00+00:00"
    first_repo.create_callback_handle(**duplicate_callback)
    duplicate_confirmation = confirmation_values(
        owner_user_id,
        suffix="d",
        selection_handle_digest="c" * 64,
    )
    duplicate_confirmation["request_fingerprint"] = "sha256:" + "b" * 64
    duplicate_confirmation["expires_at"] = "2026-08-14T10:06:00+00:00"
    first_repo.create_issuance_confirmation(**duplicate_confirmation)

    restarted = open_connection(database_path)
    try:
        restarted_repo = Repository(restarted)
        after_ttls = "2026-08-14T10:13:00+00:00"
        duplicate = restarted_repo.consume_expired_issuance_confirmation(
            "d" * 64, owner_user_id, after_ttls
        )
        assert duplicate is not None
        assert duplicate["terminal_reason"] == "expired"
        assert restarted_repo.consume_expired_issuance_confirmation(
            "b" * 64, owner_user_id, after_ttls
        ) is None
        assert restarted_repo.prune_expired_phase15_callback_state(after_ttls) == 2
        assert restarted.execute(
            "SELECT 1 FROM protocol_issuance_confirmations WHERE token_digest = ?",
            ("b" * 64,),
        ).fetchone() is not None
    finally:
        restarted.close()
        first.close()


def test_schema_classification_runs_under_immediate_transaction(
    database_path, monkeypatch
) -> None:
    connection = open_connection(database_path)
    seed_owner_and_passport(connection)
    observed: list[bool] = []
    original = phase15_bootstrap._column_names

    def observe_transaction(conn, table):
        observed.append(conn.in_transaction)
        return original(conn, table)

    monkeypatch.setattr(phase15_bootstrap, "_column_names", observe_transaction)
    phase15_bootstrap.ensure_phase15_bootstrap_schema(connection)

    assert observed
    assert all(observed)
    connection.close()


def test_two_initializers_classify_after_lock_and_preserve_claim_values(
    database_path, monkeypatch
) -> None:
    setup = open_connection(database_path)
    owner_user_id = seed_owner_and_passport(setup)
    setup.executescript(
        """
        DROP TABLE protocol_issuance_confirmations;
        DROP TABLE telegram_callback_handles;
        """
    )
    setup.execute(phase15_bootstrap.CREATE_CALLBACK_TABLE_SQL)
    predecessor_confirmation_sql = phase15_bootstrap.CREATE_CONFIRMATION_TABLE_SQL
    for fragment in (
        "    issuance_attempt_id INTEGER,\n",
        "    UNIQUE(issuance_attempt_id),\n",
        "    FOREIGN KEY(issuance_attempt_id) "
        "REFERENCES protocol_issuance_attempts(id),\n",
    ):
        predecessor_confirmation_sql = predecessor_confirmation_sql.replace(
            fragment, ""
        )
    setup.execute(predecessor_confirmation_sql)
    phase15_bootstrap._ensure_phase15_objects(setup)
    setup.commit()
    repo = Repository(setup)
    repo.create_callback_handle(**callback_values(owner_user_id))
    repo.create_issuance_confirmation(**confirmation_values(owner_user_id))
    assert repo.claim_callback_handle(
        "a" * 64,
        owner_user_id,
        NOW,
        claim_id_digest=CALLBACK_CLAIM_DIGEST,
        claim_expires_at=CLAIM_EXPIRES_AT,
    ) is not None
    assert repo.claim_issuance_confirmation(
        "b" * 64,
        owner_user_id,
        NOW,
        claim_id_digest=CONFIRMATION_CLAIM_DIGEST,
        claim_expires_at=CLAIM_EXPIRES_AT,
    ) is not None
    setup.close()

    first_holds_lock = threading.Event()
    second_attempted_begin = threading.Event()
    errors: list[BaseException] = []
    original_locked = phase15_bootstrap._ensure_phase15_bootstrap_schema_locked

    def coordinate_locked(conn):
        if threading.current_thread().name == "phase15-initializer-first":
            first_holds_lock.set()
            assert second_attempted_begin.wait(5)
        return original_locked(conn)

    monkeypatch.setattr(
        phase15_bootstrap,
        "_ensure_phase15_bootstrap_schema_locked",
        coordinate_locked,
    )

    def initialize(name: str, observe_begin: bool = False) -> None:
        connection = open_connection(database_path)
        if observe_begin:
            connection.set_trace_callback(
                lambda sql: second_attempted_begin.set()
                if sql.strip().upper() == "BEGIN IMMEDIATE"
                else None
            )
        try:
            phase15_bootstrap.ensure_phase15_bootstrap_schema(connection)
        except BaseException as exc:
            errors.append(exc)
        finally:
            connection.close()

    first = threading.Thread(
        target=initialize,
        args=("first",),
        name="phase15-initializer-first",
    )
    second = threading.Thread(
        target=initialize,
        args=("second", True),
        name="phase15-initializer-second",
    )
    first.start()
    assert first_holds_lock.wait(5)
    second.start()
    first.join(5)
    second.join(5)

    assert first.is_alive() is False
    assert second.is_alive() is False
    assert errors == []
    verified = open_connection(database_path)
    try:
        columns = tuple(
            row[1]
            for row in verified.execute(
                "PRAGMA table_info(protocol_issuance_confirmations)"
            )
        )
        assert columns[-1] == "issuance_attempt_id"
        callback_claim = verified.execute(
            "SELECT claim_id_digest, claimed_at, claim_expires_at "
            "FROM telegram_callback_handles WHERE handle_digest = ?",
            ("a" * 64,),
        ).fetchone()
        confirmation_claim = verified.execute(
            "SELECT claim_id_digest, claimed_at, claim_expires_at "
            "FROM protocol_issuance_confirmations WHERE token_digest = ?",
            ("b" * 64,),
        ).fetchone()
        assert tuple(callback_claim) == (CALLBACK_CLAIM_DIGEST, NOW, CLAIM_EXPIRES_AT)
        assert tuple(confirmation_claim) == (
            CONFIRMATION_CLAIM_DIGEST,
            NOW,
            CLAIM_EXPIRES_AT,
        )
    finally:
        verified.close()


def test_phase14_legacy_attempt_migration_preserves_fix6_confirmation_binding(
    database_path,
) -> None:
    connection = open_connection(database_path)
    try:
        owner_user_id = seed_owner_and_passport(connection)
        repo = Repository(connection)
        repo.create_callback_handle(**callback_values(owner_user_id))
        repo.create_issuance_confirmation(**confirmation_values(owner_user_id))
        assert repo.claim_issuance_confirmation(
            "b" * 64,
            owner_user_id,
            NOW,
            claim_id_digest=CONFIRMATION_CLAIM_DIGEST,
            claim_expires_at=CLAIM_EXPIRES_AT,
        ) is not None
        attempt = reserve_attempt(repo, owner_user_id, protocol_version="awg3")
        assert attempt is not None
        assert repo.bind_issuance_confirmation_attempt(
            "b" * 64,
            owner_user_id,
            claim_id_digest=CONFIRMATION_CLAIM_DIGEST,
            attempt_id=int(attempt["id"]),
        ) is not None
        confirmation_before = tuple(
            connection.execute(
                "SELECT * FROM protocol_issuance_confirmations"
            ).fetchone()
        )
        replace_attempt_table_with_legacy(connection, attempt)

        initialize_schema(connection)
        initialize_schema(connection)

        confirmation_after = connection.execute(
            "SELECT * FROM protocol_issuance_confirmations"
        ).fetchone()
        migrated_attempt = connection.execute(
            "SELECT * FROM protocol_issuance_attempts WHERE id = ?",
            (attempt["id"],),
        ).fetchone()
        assert tuple(confirmation_after) == confirmation_before
        assert confirmation_after["issuance_attempt_id"] == migrated_attempt["id"]
        assert migrated_attempt["owner_user_id"] == owner_user_id
        assert migrated_attempt["intended_passport_device_id"] == "passport-phase15"
        assert connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' "
            "AND name = 'protocol_issuance_attempts_legacy'"
        ).fetchone() is None
        assert {
            str(row[2])
            for row in connection.execute(
                "PRAGMA foreign_key_list(protocol_issuance_confirmations)"
            )
        }.isdisjoint(
            {"protocol_issuance_attempts", "protocol_issuance_attempts_legacy"}
        )
        assert int(connection.execute("PRAGMA foreign_keys").fetchone()[0]) == 0
        connection.execute("PRAGMA foreign_keys = ON")
        assert list(connection.execute("PRAGMA foreign_key_check")) == []
    finally:
        connection.close()


@pytest.mark.parametrize("foreign_keys_enabled", [0, 1])
def test_fix6_confirmation_fk_predecessor_upgrades_without_value_loss(
    database_path, foreign_keys_enabled
) -> None:
    connection = open_connection(database_path)
    try:
        owner_user_id = seed_owner_and_passport(connection)
        install_fix6_confirmation_schema(connection)
        repo = Repository(connection)
        repo.create_callback_handle(**callback_values(owner_user_id))
        repo.create_issuance_confirmation(**confirmation_values(owner_user_id))
        assert repo.claim_issuance_confirmation(
            "b" * 64,
            owner_user_id,
            NOW,
            claim_id_digest=CONFIRMATION_CLAIM_DIGEST,
            claim_expires_at=CLAIM_EXPIRES_AT,
        ) is not None
        attempt = reserve_attempt(repo, owner_user_id, protocol_version="awg3")
        assert attempt is not None
        assert repo.bind_issuance_confirmation_attempt(
            "b" * 64,
            owner_user_id,
            claim_id_digest=CONFIRMATION_CLAIM_DIGEST,
            attempt_id=int(attempt["id"]),
        ) is not None
        before = tuple(
            connection.execute(
                "SELECT * FROM protocol_issuance_confirmations"
            ).fetchone()
        )
        connection.execute(f"PRAGMA foreign_keys = {foreign_keys_enabled}")

        phase15_bootstrap.ensure_phase15_bootstrap_schema(connection)
        phase15_bootstrap.ensure_phase15_bootstrap_schema(connection)

        after = connection.execute(
            "SELECT * FROM protocol_issuance_confirmations"
        ).fetchone()
        assert tuple(after) == before
        assert after["issuance_attempt_id"] == attempt["id"]
        assert {
            str(row[2])
            for row in connection.execute(
                "PRAGMA foreign_key_list(protocol_issuance_confirmations)"
            )
        }.isdisjoint(
            {"protocol_issuance_attempts", "protocol_issuance_attempts_legacy"}
        )
        assert int(connection.execute("PRAGMA foreign_keys").fetchone()[0]) == (
            foreign_keys_enabled
        )
        assert list(connection.execute("PRAGMA foreign_key_check")) == []
    finally:
        connection.close()


def test_partial_attempt_binding_unique_is_rejected(database_path) -> None:
    connection = open_connection(database_path)
    try:
        seed_owner_and_passport(connection)
        install_fix6_confirmation_schema(connection, partial_attempt_unique=True)

        with pytest.raises(RuntimeError, match="issuance attempt binding"):
            phase15_bootstrap.ensure_phase15_bootstrap_schema(connection)
    finally:
        connection.close()


@pytest.mark.parametrize(
    "attempt_target",
    ("protocol_issuance_attempts", "protocol_issuance_attempts_legacy"),
)
def test_canonical_schema_rejects_attempt_table_fk_from_nonbinding_column(
    database_path, attempt_target
) -> None:
    connection = open_connection(database_path)
    try:
        seed_owner_and_passport(connection)
        install_confirmation_schema_with_attempt_foreign_keys(
            connection,
            attempt_foreign_keys=(("owner_user_id", attempt_target),),
        )
        foreign_keys_before = tuple(
            tuple(row)
            for row in connection.execute(
                "PRAGMA foreign_key_list(protocol_issuance_confirmations)"
            )
        )

        with pytest.raises(RuntimeError, match="attempt binding"):
            phase15_bootstrap.ensure_phase15_bootstrap_schema(connection)

        assert tuple(
            tuple(row)
            for row in connection.execute(
                "PRAGMA foreign_key_list(protocol_issuance_confirmations)"
            )
        ) == foreign_keys_before
    finally:
        connection.close()


@pytest.mark.parametrize(
    "extra_attempt_target",
    ("protocol_issuance_attempts", "Protocol_Issuance_Attempts"),
)
def test_fix6_predecessor_with_extra_attempt_table_fk_is_rejected(
    database_path, extra_attempt_target
) -> None:
    connection = open_connection(database_path)
    try:
        seed_owner_and_passport(connection)
        install_fix6_confirmation_schema(
            connection,
            extra_attempt_foreign_keys=(
                ("owner_user_id", extra_attempt_target),
            ),
        )
        foreign_keys_before = tuple(
            tuple(row)
            for row in connection.execute(
                "PRAGMA foreign_key_list(protocol_issuance_confirmations)"
            )
        )

        with pytest.raises(RuntimeError, match="attempt binding"):
            phase15_bootstrap.ensure_phase15_bootstrap_schema(connection)

        assert tuple(
            tuple(row)
            for row in connection.execute(
                "PRAGMA foreign_key_list(protocol_issuance_confirmations)"
            )
        ) == foreign_keys_before
    finally:
        connection.close()


@pytest.mark.parametrize(
    "attempt_target",
    ("PROTOCOL_ISSUANCE_ATTEMPTS", "Protocol_Issuance_Attempts_Legacy"),
)
def test_canonical_schema_rejects_case_variant_attempt_table_fk(
    database_path, attempt_target
) -> None:
    connection = open_connection(database_path)
    try:
        seed_owner_and_passport(connection)
        install_confirmation_schema_with_attempt_foreign_keys(
            connection,
            attempt_foreign_keys=(("owner_user_id", attempt_target),),
        )

        with pytest.raises(RuntimeError, match="attempt binding"):
            phase15_bootstrap.ensure_phase15_bootstrap_schema(connection)
    finally:
        connection.close()


@pytest.mark.parametrize(
    "attempt_target",
    ("PROTOCOL_ISSUANCE_ATTEMPTS", "Protocol_Issuance_Attempts_Legacy"),
)
def test_case_variant_exact_fix6_predecessor_upgrades(
    database_path, attempt_target
) -> None:
    connection = open_connection(database_path)
    try:
        seed_owner_and_passport(connection)
        install_fix6_confirmation_schema(
            connection,
            attempt_target=attempt_target,
        )

        phase15_bootstrap.ensure_phase15_bootstrap_schema(connection)
        phase15_bootstrap.ensure_phase15_bootstrap_schema(connection)

        assert {
            str(row[2]).casefold()
            for row in connection.execute(
                "PRAGMA foreign_key_list(protocol_issuance_confirmations)"
            )
        }.isdisjoint(
            {"protocol_issuance_attempts", "protocol_issuance_attempts_legacy"}
        )
        assert list(connection.execute("PRAGMA foreign_key_check")) == []
    finally:
        connection.close()


@pytest.mark.parametrize(
    "attempt_target",
    (
        "protocol_issuance_attempts",
        "protocol_issuance_attempts_legacy",
    ),
)
def test_unicode_confusable_attempt_fk_source_is_rejected_without_upgrade(
    database_path, attempt_target
) -> None:
    connection = open_connection(database_path)
    try:
        seed_owner_and_passport(connection)
        install_confirmation_schema_with_attempt_foreign_keys(
            connection,
            attempt_foreign_keys=(("iſsuance_attempt_id", attempt_target),),
            generated_confusable_attempt_source=True,
        )
        before = phase15_validation_snapshot(connection)

        with pytest.raises(RuntimeError, match="attempt binding"):
            phase15_bootstrap.ensure_phase15_bootstrap_schema(connection)

        assert phase15_validation_snapshot(connection) == before
    finally:
        connection.close()


def test_same_name_noop_callback_trigger_is_rejected_without_mutation(
    database_path,
) -> None:
    connection = open_connection(database_path)
    try:
        seed_owner_and_passport(connection)
        repo = Repository(connection)
        mismatched_owner_id = repo.upsert_user(
            telegram_id=15002,
            username="phase15-mismatch",
            first_name="Mismatch",
            last_name="Owner",
        )
        connection.execute("DROP TRIGGER trg_phase15_callback_owner_passport_insert")
        connection.execute(
            """
            CREATE TRIGGER trg_phase15_callback_owner_passport_insert
            BEFORE INSERT ON telegram_callback_handles
            FOR EACH ROW BEGIN SELECT 1; END
            """
        )
        connection.commit()

        repo.create_callback_handle(
            **callback_values(mismatched_owner_id, suffix="e")
        )
        inserted = connection.execute(
            "SELECT owner_user_id, passport_device_id "
            "FROM telegram_callback_handles WHERE handle_digest = ?",
            ("e" * 64,),
        ).fetchone()
        assert tuple(inserted) == (mismatched_owner_id, "passport-phase15")
        before = phase15_validation_snapshot(connection)

        with pytest.raises(RuntimeError, match="owner binding triggers"):
            phase15_bootstrap.ensure_phase15_bootstrap_schema(connection)

        assert phase15_validation_snapshot(connection) == before
    finally:
        connection.close()


def test_same_name_noop_confirmation_trigger_is_rejected_without_mutation(
    database_path,
) -> None:
    connection = open_connection(database_path)
    try:
        seed_owner_and_passport(connection)
        repo = Repository(connection)
        mismatched_owner_id = repo.upsert_user(
            telegram_id=15002,
            username="phase15-mismatch",
            first_name="Mismatch",
            last_name="Owner",
        )
        connection.execute("DROP TRIGGER trg_phase15_callback_owner_passport_insert")
        connection.execute(
            """
            CREATE TRIGGER trg_phase15_callback_owner_passport_insert
            BEFORE INSERT ON telegram_callback_handles
            FOR EACH ROW BEGIN SELECT 1; END
            """
        )
        connection.commit()
        repo.create_callback_handle(
            **callback_values(mismatched_owner_id, suffix="f")
        )
        connection.execute("DROP TRIGGER trg_phase15_callback_owner_passport_insert")
        connection.execute(phase15_bootstrap.TRIGGER_SQL[0])
        connection.execute(
            "DROP TRIGGER trg_phase15_confirmation_owner_passport_insert"
        )
        connection.execute(
            """
            CREATE TRIGGER trg_phase15_confirmation_owner_passport_insert
            BEFORE INSERT ON protocol_issuance_confirmations
            FOR EACH ROW BEGIN SELECT 1; END
            """
        )
        connection.commit()

        repo.create_issuance_confirmation(
            **confirmation_values(
                mismatched_owner_id,
                suffix="f",
                selection_handle_digest="f" * 64,
            )
        )
        inserted = connection.execute(
            "SELECT owner_user_id, passport_device_id "
            "FROM protocol_issuance_confirmations WHERE token_digest = ?",
            ("f" * 64,),
        ).fetchone()
        assert tuple(inserted) == (mismatched_owner_id, "passport-phase15")
        before = phase15_validation_snapshot(connection)

        with pytest.raises(RuntimeError, match="owner binding triggers"):
            phase15_bootstrap.ensure_phase15_bootstrap_schema(connection)

        assert phase15_validation_snapshot(connection) == before
    finally:
        connection.close()


def test_weakened_owner_passport_predicate_is_rejected_without_mutation(
    database_path,
) -> None:
    connection = open_connection(database_path)
    try:
        seed_owner_and_passport(connection)
        repo = Repository(connection)
        mismatched_owner_id = repo.upsert_user(
            telegram_id=15002,
            username="phase15-mismatch",
            first_name="Mismatch",
            last_name="Owner",
        )
        connection.execute("DROP TRIGGER trg_phase15_callback_owner_passport_insert")
        connection.execute(
            """
            CREATE TRIGGER trg_phase15_callback_owner_passport_insert
            BEFORE INSERT ON telegram_callback_handles
            FOR EACH ROW
            WHEN NOT EXISTS (
                SELECT 1 FROM device_passports
                WHERE device_id = NEW.passport_device_id
                   OR owner_user_id = NEW.owner_user_id
            )
            BEGIN
                SELECT RAISE(ABORT, 'phase15 callback owner/passport mismatch');
            END
            """
        )
        connection.commit()

        repo.create_callback_handle(
            **callback_values(mismatched_owner_id, suffix="8")
        )
        inserted = connection.execute(
            "SELECT owner_user_id, passport_device_id "
            "FROM telegram_callback_handles WHERE handle_digest = ?",
            ("8" * 64,),
        ).fetchone()
        assert tuple(inserted) == (mismatched_owner_id, "passport-phase15")
        before = phase15_validation_snapshot(connection)

        with pytest.raises(RuntimeError, match="owner binding triggers"):
            phase15_bootstrap.ensure_phase15_bootstrap_schema(connection)

        assert phase15_validation_snapshot(connection) == before
    finally:
        connection.close()


def test_long_s_in_trigger_new_column_is_rejected_without_mutation(
    database_path,
) -> None:
    connection = open_connection(database_path)
    try:
        seed_owner_and_passport(connection)
        mutated_sql = phase15_bootstrap.TRIGGER_SQL[0].replace(
            "NEW.owner_user_id",
            "NEW.owner_uſer_id",
        )
        connection.execute("DROP TRIGGER trg_phase15_callback_owner_passport_insert")
        connection.execute(mutated_sql)
        connection.commit()
        stored_sql = connection.execute(
            "SELECT sql FROM sqlite_master "
            "WHERE type = 'trigger' "
            "AND name = 'trg_phase15_callback_owner_passport_insert'"
        ).fetchone()[0]
        assert "NEW.owner_uſer_id" in stored_sql
        before = phase15_validation_snapshot(connection)

        with pytest.raises(RuntimeError, match="owner binding triggers"):
            phase15_bootstrap.ensure_phase15_bootstrap_schema(connection)

        assert phase15_validation_snapshot(connection) == before
    finally:
        connection.close()


def test_kelvin_sign_in_trigger_name_is_rejected_without_mutation(
    database_path,
) -> None:
    connection = open_connection(database_path)
    try:
        seed_owner_and_passport(connection)
        mutated_name = "trg_phase15_callbacK_owner_passport_insert"
        mutated_sql = phase15_bootstrap.TRIGGER_SQL[0].replace(
            "trg_phase15_callback_owner_passport_insert",
            mutated_name,
        )
        connection.execute("DROP TRIGGER trg_phase15_callback_owner_passport_insert")
        connection.execute(mutated_sql)
        connection.commit()
        stored_name = connection.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type = 'trigger' AND name = ?",
            (mutated_name,),
        ).fetchone()[0]
        assert stored_name == mutated_name
        before = phase15_validation_snapshot(connection)

        with pytest.raises(RuntimeError, match="owner binding triggers"):
            phase15_bootstrap.ensure_phase15_bootstrap_schema(connection)

        assert phase15_validation_snapshot(connection) == before
    finally:
        connection.close()


def test_ascii_case_variant_trigger_name_remains_supported(database_path) -> None:
    connection = open_connection(database_path)
    try:
        seed_owner_and_passport(connection)
        uppercase_name = "TRG_PHASE15_CALLBACK_OWNER_PASSPORT_INSERT"
        uppercase_name_sql = phase15_bootstrap.TRIGGER_SQL[0].replace(
            "trg_phase15_callback_owner_passport_insert",
            uppercase_name,
        )
        connection.execute("DROP TRIGGER trg_phase15_callback_owner_passport_insert")
        connection.execute(uppercase_name_sql)
        connection.commit()

        phase15_bootstrap.ensure_phase15_bootstrap_schema(connection)
        phase15_bootstrap.ensure_phase15_bootstrap_schema(connection)

        assert connection.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type = 'trigger' AND name = ?",
            (uppercase_name,),
        ).fetchone()[0] == uppercase_name
    finally:
        connection.close()


@pytest.mark.parametrize(
    ("callback_sql", "confirmation_sql"),
    (
        (
            phase15_bootstrap.CREATE_CALLBACK_TABLE_SQL.replace(
                "handle_digest TEXT NOT NULL PRIMARY KEY",
                "handle_digest TEXT NOT NULL",
            ),
            phase15_bootstrap.CREATE_CONFIRMATION_TABLE_SQL,
        ),
        (
            phase15_bootstrap.CREATE_CALLBACK_TABLE_SQL,
            phase15_bootstrap.CREATE_CONFIRMATION_TABLE_SQL.replace(
                "token_digest TEXT NOT NULL PRIMARY KEY",
                "token_digest TEXT NOT NULL",
            ),
        ),
    ),
    ids=("callback", "confirmation"),
)
def test_missing_identity_primary_key_is_rejected_without_mutation(
    database_path,
    callback_sql,
    confirmation_sql,
) -> None:
    connection = open_connection(database_path)
    try:
        seed_owner_and_passport(connection)
        replace_phase15_table_shape(
            connection,
            callback_sql=callback_sql,
            confirmation_sql=confirmation_sql,
        )

        assert_phase15_shape_rejected_without_mutation(connection)
    finally:
        connection.close()


def test_duplicate_confirmation_claim_is_rejected_without_further_mutation(
    database_path,
) -> None:
    connection = open_connection(database_path)
    try:
        owner_user_id = seed_owner_and_passport(connection)
        replace_phase15_table_shape(
            connection,
            callback_sql=phase15_bootstrap.CREATE_CALLBACK_TABLE_SQL,
            confirmation_sql=phase15_bootstrap.CREATE_CONFIRMATION_TABLE_SQL.replace(
                "token_digest TEXT NOT NULL PRIMARY KEY",
                "token_digest TEXT NOT NULL",
            ),
        )
        repo = Repository(connection)
        repo.create_callback_handle(**callback_values(owner_user_id))
        values = confirmation_values(owner_user_id)
        repo.create_issuance_confirmation(**values)
        repo.create_issuance_confirmation(**values)
        assert connection.execute(
            "SELECT COUNT(*) FROM protocol_issuance_confirmations "
            "WHERE token_digest = ?",
            ("b" * 64,),
        ).fetchone()[0] == 2

        assert repo.claim_issuance_confirmation(
            "b" * 64,
            owner_user_id,
            NOW,
            claim_id_digest=CONFIRMATION_CLAIM_DIGEST,
            claim_expires_at=CLAIM_EXPIRES_AT,
        ) is None
        assert tuple(
            tuple(row)
            for row in connection.execute(
                "SELECT claim_id_digest, claimed_at, claim_expires_at "
                "FROM protocol_issuance_confirmations "
                "WHERE token_digest = ? ORDER BY rowid",
                ("b" * 64,),
            )
        ) == (
            (CONFIRMATION_CLAIM_DIGEST, NOW, CLAIM_EXPIRES_AT),
            (CONFIRMATION_CLAIM_DIGEST, NOW, CLAIM_EXPIRES_AT),
        )

        assert_phase15_shape_rejected_without_mutation(connection)
    finally:
        connection.close()


@pytest.mark.parametrize(
    ("callback_sql", "confirmation_sql"),
    (
        (
            phase15_bootstrap.CREATE_CALLBACK_TABLE_SQL.replace(
                "purpose TEXT NOT NULL",
                "purpose BLOB NOT NULL",
            ),
            phase15_bootstrap.CREATE_CONFIRMATION_TABLE_SQL,
        ),
        (
            phase15_bootstrap.CREATE_CALLBACK_TABLE_SQL,
            phase15_bootstrap.CREATE_CONFIRMATION_TABLE_SQL.replace(
                "client_build TEXT NOT NULL",
                "client_build TEXT",
            ),
        ),
        (
            phase15_bootstrap.CREATE_CALLBACK_TABLE_SQL.replace(
                "purpose TEXT NOT NULL",
                "purpose TEXT NOT NULL DEFAULT 'select_protocol'",
            ),
            phase15_bootstrap.CREATE_CONFIRMATION_TABLE_SQL,
        ),
        (
            phase15_bootstrap.CREATE_CALLBACK_TABLE_SQL.replace(
                "claim_expires_at > claimed_at",
                "claim_expires_at >= claimed_at",
            ),
            phase15_bootstrap.CREATE_CONFIRMATION_TABLE_SQL,
        ),
        (
            phase15_bootstrap.CREATE_CALLBACK_TABLE_SQL,
            phase15_bootstrap.CREATE_CONFIRMATION_TABLE_SQL.replace(
                "    UNIQUE(issuance_attempt_id),\n",
                "    UNIQUE(issuance_attempt_id),\n"
                "    UNIQUE(request_fingerprint),\n",
            ),
        ),
    ),
    ids=("type", "not-null", "default", "check", "extra-unique"),
)
def test_altered_column_or_constraint_is_rejected_without_mutation(
    database_path,
    callback_sql,
    confirmation_sql,
) -> None:
    connection = open_connection(database_path)
    try:
        seed_owner_and_passport(connection)
        replace_phase15_table_shape(
            connection,
            callback_sql=callback_sql,
            confirmation_sql=confirmation_sql,
        )

        assert_phase15_shape_rejected_without_mutation(connection)
    finally:
        connection.close()


def test_extra_unrelated_foreign_key_is_rejected_without_mutation(
    database_path,
) -> None:
    connection = open_connection(database_path)
    try:
        seed_owner_and_passport(connection)
        confirmation_sql = phase15_bootstrap.CREATE_CONFIRMATION_TABLE_SQL.replace(
            "    FOREIGN KEY(owner_user_id) REFERENCES users(id),\n",
            "    FOREIGN KEY(owner_user_id) REFERENCES servers(id),\n"
            "    FOREIGN KEY(owner_user_id) REFERENCES users(id),\n",
        )
        replace_phase15_table_shape(
            connection,
            callback_sql=phase15_bootstrap.CREATE_CALLBACK_TABLE_SQL,
            confirmation_sql=confirmation_sql,
        )

        assert_phase15_shape_rejected_without_mutation(connection)
    finally:
        connection.close()


@pytest.mark.parametrize("alter_expected", (False, True), ids=("extra", "altered"))
def test_unexpected_explicit_index_shape_is_rejected_without_mutation(
    database_path,
    alter_expected,
) -> None:
    connection = open_connection(database_path)
    try:
        seed_owner_and_passport(connection)
        if alter_expected:
            connection.execute(
                "DROP INDEX idx_telegram_callback_handles_expires_at"
            )
            connection.execute(
                "CREATE INDEX idx_telegram_callback_handles_expires_at "
                "ON telegram_callback_handles(created_at)"
            )
        else:
            connection.execute(
                "CREATE INDEX idx_phase15_unexpected_callback_created_at "
                "ON telegram_callback_handles(created_at)"
            )
        connection.commit()

        assert_phase15_shape_rejected_without_mutation(connection)
    finally:
        connection.close()


def test_extra_phase15_table_trigger_is_rejected_without_mutation(
    database_path,
) -> None:
    connection = open_connection(database_path)
    try:
        seed_owner_and_passport(connection)
        connection.execute(
            "CREATE TRIGGER trg_phase15_unexpected_callback_delete "
            "AFTER DELETE ON telegram_callback_handles "
            "FOR EACH ROW BEGIN SELECT 1; END"
        )
        connection.commit()

        assert_phase15_shape_rejected_without_mutation(connection)
    finally:
        connection.close()


def test_malformed_prebinding_constraint_is_rejected_without_mutation(
    database_path,
) -> None:
    connection = open_connection(database_path)
    try:
        seed_owner_and_passport(connection)
        malformed_confirmation_sql = (
            phase15_bootstrap.PRE_BINDING_CONFIRMATION_TABLE_SQL.replace(
                "claim_expires_at > claimed_at",
                "claim_expires_at >= claimed_at",
            )
        )
        replace_phase15_table_shape(
            connection,
            callback_sql=phase15_bootstrap.CREATE_CALLBACK_TABLE_SQL,
            confirmation_sql=malformed_confirmation_sql,
        )

        assert_phase15_shape_rejected_without_mutation(connection)
    finally:
        connection.close()


@pytest.mark.parametrize(
    "attempt_target",
    ("protocol_issuance_attempts", "protocol_issuance_attempts_legacy"),
)
def test_malformed_fix6_identity_constraint_is_rejected_without_mutation(
    database_path,
    attempt_target,
) -> None:
    connection = open_connection(database_path)
    try:
        seed_owner_and_passport(connection)
        malformed_confirmation_sql = (
            phase15_bootstrap.CREATE_CONFIRMATION_TABLE_SQL.replace(
                "token_digest TEXT NOT NULL PRIMARY KEY",
                "token_digest TEXT NOT NULL",
            ).replace(
                "    FOREIGN KEY(owner_user_id) REFERENCES users(id),\n",
                "    FOREIGN KEY(issuance_attempt_id) "
                f"REFERENCES {attempt_target}(id),\n"
                "    FOREIGN KEY(owner_user_id) REFERENCES users(id),\n",
            )
        )
        replace_phase15_table_shape(
            connection,
            callback_sql=phase15_bootstrap.CREATE_CALLBACK_TABLE_SQL,
            confirmation_sql=malformed_confirmation_sql,
        )

        assert_phase15_shape_rejected_without_mutation(connection)
    finally:
        connection.close()


@pytest.mark.parametrize("foreign_keys_enabled", (0, 1))
def test_exact_prebinding_schema_upgrades_without_value_loss(
    database_path,
    foreign_keys_enabled,
) -> None:
    connection = open_connection(database_path)
    try:
        owner_user_id = seed_owner_and_passport(connection)
        replace_phase15_table_shape(
            connection,
            callback_sql=phase15_bootstrap.CREATE_CALLBACK_TABLE_SQL,
            confirmation_sql=phase15_bootstrap.PRE_BINDING_CONFIRMATION_TABLE_SQL,
        )
        repo = Repository(connection)
        repo.create_callback_handle(**callback_values(owner_user_id))
        repo.create_issuance_confirmation(**confirmation_values(owner_user_id))
        assert repo.claim_callback_handle(
            "a" * 64,
            owner_user_id,
            NOW,
            claim_id_digest=CALLBACK_CLAIM_DIGEST,
            claim_expires_at=CLAIM_EXPIRES_AT,
        ) is not None
        assert repo.claim_issuance_confirmation(
            "b" * 64,
            owner_user_id,
            NOW,
            claim_id_digest=CONFIRMATION_CLAIM_DIGEST,
            claim_expires_at=CLAIM_EXPIRES_AT,
        ) is not None
        callback_before = tuple(
            connection.execute("SELECT * FROM telegram_callback_handles").fetchone()
        )
        confirmation_before = tuple(
            connection.execute(
                "SELECT * FROM protocol_issuance_confirmations"
            ).fetchone()
        )
        connection.execute(f"PRAGMA foreign_keys = {foreign_keys_enabled}")

        phase15_bootstrap.ensure_phase15_bootstrap_schema(connection)
        phase15_bootstrap.ensure_phase15_bootstrap_schema(connection)

        callback_after = tuple(
            connection.execute("SELECT * FROM telegram_callback_handles").fetchone()
        )
        confirmation_after = tuple(
            connection.execute(
                "SELECT * FROM protocol_issuance_confirmations"
            ).fetchone()
        )
        assert callback_after == callback_before
        assert confirmation_after[:-1] == confirmation_before
        assert confirmation_after[-1] is None
        assert int(connection.execute("PRAGMA foreign_keys").fetchone()[0]) == (
            foreign_keys_enabled
        )
        assert list(connection.execute("PRAGMA foreign_key_check")) == []
    finally:
        connection.close()


def test_textnot_column_declaration_is_rejected_without_mutation(
    database_path,
) -> None:
    connection = open_connection(database_path)
    try:
        owner_user_id = seed_owner_and_passport(connection)
        malformed_callback_sql = phase15_bootstrap.CREATE_CALLBACK_TABLE_SQL.replace(
            "purpose TEXT NOT NULL",
            "purpose TEXTNOT NULL",
        )
        replace_phase15_table_shape(
            connection,
            callback_sql=malformed_callback_sql,
            confirmation_sql=phase15_bootstrap.CREATE_CONFIRMATION_TABLE_SQL,
        )
        purpose_info = next(
            row
            for row in connection.execute(
                "PRAGMA table_info(telegram_callback_handles)"
            )
            if row[1] == "purpose"
        )
        assert (purpose_info[2], purpose_info[3]) == ("TEXTNOT", 0)
        values = callback_values(owner_user_id, suffix="8")
        values["purpose"] = None
        Repository(connection).create_callback_handle(**values)
        assert connection.execute(
            "SELECT purpose FROM telegram_callback_handles "
            "WHERE handle_digest = ?",
            ("8" * 64,),
        ).fetchone()[0] is None

        assert_phase15_shape_rejected_without_mutation(connection)
    finally:
        connection.close()


def test_isnull_constraint_token_merge_is_rejected_without_mutation(
    database_path,
) -> None:
    connection = open_connection(database_path)
    try:
        seed_owner_and_passport(connection)
        malformed_callback_sql = phase15_bootstrap.CREATE_CALLBACK_TABLE_SQL.replace(
            "claim_id_digest IS NULL",
            "claim_id_digest ISNULL",
        )
        replace_phase15_table_shape(
            connection,
            callback_sql=malformed_callback_sql,
            confirmation_sql=phase15_bootstrap.CREATE_CONFIRMATION_TABLE_SQL,
        )
        stored_sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' "
            "AND name = 'telegram_callback_handles'"
        ).fetchone()[0]
        assert "claim_id_digest ISNULL" in stored_sql

        assert_phase15_shape_rejected_without_mutation(connection)
    finally:
        connection.close()


@pytest.mark.parametrize(
    ("canonical", "merged"),
    (
        ("value TEXT NOT NULL", "value TEXTNOT NULL"),
        ("value IS NULL", "value ISNULL"),
        ("value NOT GLOB 'x'", "value NOTGLOB 'x'"),
        ("value >= 1", "value > = 1"),
    ),
    ids=("text-not", "is-null", "not-glob", "operator"),
)
def test_sql_normalization_preserves_token_boundaries(
    canonical,
    merged,
) -> None:
    assert phase15_bootstrap._normalize_sql(canonical) != (
        phase15_bootstrap._normalize_sql(merged)
    )


def test_sql_normalization_preserves_literal_bytes() -> None:
    assert phase15_bootstrap._normalize_sql("value = 'a b'") != (
        phase15_bootstrap._normalize_sql("value = 'ab'")
    )
    assert phase15_bootstrap._normalize_sql("value = 'A'") != (
        phase15_bootstrap._normalize_sql("value = 'a'")
    )


@pytest.mark.parametrize(
    "mutate",
    (
        lambda sql: sql.replace(
            "purpose TEXT NOT NULL,",
            "purpose TEXT NOT NULL /* unsupported */,",
        ),
        lambda sql: sql.replace(
            "purpose TEXT NOT NULL",
            '"purpose" TEXT NOT NULL',
        ),
        lambda sql: sql.replace(
            "    UNIQUE(handle_digest, owner_user_id, passport_device_id),\n",
            "    UNIQUE(handle_digest, owner_user_id, passport_device_id),\n"
            "    CHECK (X'00' != X'01'),\n",
        ),
    ),
    ids=("comment", "quoted-identifier", "blob-literal"),
)
def test_unsupported_sql_token_forms_are_rejected_without_mutation(
    database_path,
    mutate,
) -> None:
    connection = open_connection(database_path)
    try:
        seed_owner_and_passport(connection)
        replace_phase15_table_shape(
            connection,
            callback_sql=mutate(phase15_bootstrap.CREATE_CALLBACK_TABLE_SQL),
            confirmation_sql=phase15_bootstrap.CREATE_CONFIRMATION_TABLE_SQL,
        )

        assert_phase15_shape_rejected_without_mutation(connection)
    finally:
        connection.close()


def test_ascii_case_and_sqlite_whitespace_variants_remain_supported(
    database_path,
) -> None:
    connection = open_connection(database_path)
    try:
        seed_owner_and_passport(connection)
        callback_sql = phase15_bootstrap.CREATE_CALLBACK_TABLE_SQL.replace(
            "CREATE TABLE",
            "cReAtE  \n\tTaBlE",
        ).replace(
            "purpose TEXT NOT NULL",
            "PURPOSE\tTEXT\r\n        NOT  NULL",
        )
        confirmation_sql = (
            phase15_bootstrap.CREATE_CONFIRMATION_TABLE_SQL.replace(
                "CREATE TABLE",
                "CrEaTe\r\n TaBlE",
            ).replace(
                "client_build TEXT NOT NULL",
                "CLIENT_BUILD  TEXT\tNOT\n NULL",
            )
        )
        replace_phase15_table_shape(
            connection,
            callback_sql=callback_sql,
            confirmation_sql=confirmation_sql,
        )
        connection.execute(
            "DROP INDEX idx_telegram_callback_handles_owner_passport"
        )
        connection.execute(
            "cReAtE  InDeX idx_telegram_callback_handles_owner_passport\n"
            "ON telegram_callback_handles (owner_user_id,\tpassport_device_id)"
        )
        connection.execute(
            "DROP TRIGGER trg_phase15_callback_owner_passport_insert"
        )
        trigger_sql = phase15_bootstrap.TRIGGER_SQL[0].replace(
            "CREATE TRIGGER IF NOT EXISTS",
            "cReAtE  TrIgGeR IF\tNOT\nEXISTS",
        ).replace(
            "BEFORE INSERT ON",
            "BeFoRe\r\nINSERT\tON",
        )
        connection.execute(trigger_sql)
        connection.commit()

        phase15_bootstrap.ensure_phase15_bootstrap_schema(connection)
        phase15_bootstrap.ensure_phase15_bootstrap_schema(connection)
    finally:
        connection.close()


def test_canonical_attempt_binding_unique_rejects_second_non_null_binding(
    database_path,
) -> None:
    connection = open_connection(database_path)
    try:
        owner_user_id = seed_owner_and_passport(connection)
        repo = Repository(connection)
        repo.create_callback_handle(**callback_values(owner_user_id))
        repo.create_issuance_confirmation(**confirmation_values(owner_user_id))
        second_callback = callback_values(owner_user_id, suffix="c")
        repo.create_callback_handle(**second_callback)
        second_confirmation = confirmation_values(
            owner_user_id,
            suffix="d",
            selection_handle_digest="c" * 64,
        )
        repo.create_issuance_confirmation(**second_confirmation)
        attempt = reserve_attempt(repo, owner_user_id, protocol_version="awg3")
        assert attempt is not None

        connection.execute(
            "UPDATE protocol_issuance_confirmations SET issuance_attempt_id = ? "
            "WHERE token_digest = ?",
            (attempt["id"], "b" * 64),
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE protocol_issuance_confirmations "
                "SET issuance_attempt_id = ? WHERE token_digest = ?",
                (attempt["id"], "d" * 64),
            )
        assert connection.execute(
            "SELECT issuance_attempt_id FROM protocol_issuance_confirmations "
            "WHERE token_digest = ?",
            ("b" * 64,),
        ).fetchone()[0] == attempt["id"]
        assert connection.execute(
            "SELECT issuance_attempt_id FROM protocol_issuance_confirmations "
            "WHERE token_digest = ?",
            ("d" * 64,),
        ).fetchone()[0] is None
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
            "a" * 64,
            other_owner_id,
            NOW,
            expected_purpose="select_protocol",
        ) is None
        assert connection.execute(
            "SELECT consumed_at FROM telegram_callback_handles"
        ).fetchone()[0] is None

        consumed = repo.consume_expired_callback_handle(
            "a" * 64,
            owner_user_id,
            NOW,
            expected_purpose="select_protocol",
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


def test_expired_claimed_callback_cannot_be_terminal_consumed(database_path) -> None:
    connection = open_connection(database_path)
    try:
        owner_user_id = seed_owner_and_passport(connection)
        repo = Repository(connection)
        claimed_callback = callback_values(owner_user_id)
        claimed_callback["expires_at"] = "2026-08-14T10:06:00+00:00"
        repo.create_callback_handle(**claimed_callback)
        assert repo.claim_callback_handle(
            "a" * 64,
            owner_user_id,
            NOW,
            claim_id_digest=CALLBACK_CLAIM_DIGEST,
            claim_expires_at=CLAIM_EXPIRES_AT,
        ) is not None
        after_both_ttls = "2026-08-14T10:09:00+00:00"

        assert repo.consume_expired_callback_handle(
            "a" * 64,
            owner_user_id,
            after_both_ttls,
            expected_purpose="select_protocol",
        ) is None
        consumed = repo.consume_callback_handle(
            "a" * 64,
            owner_user_id,
            after_both_ttls,
            "protocol-selected",
            claim_id_digest=CALLBACK_CLAIM_DIGEST,
        )

        assert consumed is not None
        assert consumed["terminal_reason"] == "protocol-selected"
    finally:
        connection.close()


def test_expired_claimed_confirmation_cannot_be_terminal_consumed(
    database_path,
) -> None:
    connection = open_connection(database_path)
    try:
        owner_user_id = seed_owner_and_passport(connection)
        repo = Repository(connection)
        repo.create_callback_handle(**callback_values(owner_user_id))
        claimed_confirmation = confirmation_values(owner_user_id)
        claimed_confirmation["expires_at"] = "2026-08-14T10:06:00+00:00"
        repo.create_issuance_confirmation(**claimed_confirmation)
        assert repo.claim_issuance_confirmation(
            "b" * 64,
            owner_user_id,
            NOW,
            claim_id_digest=CONFIRMATION_CLAIM_DIGEST,
            claim_expires_at=CLAIM_EXPIRES_AT,
        ) is not None
        after_both_ttls = "2026-08-14T10:09:00+00:00"

        assert repo.consume_expired_issuance_confirmation(
            "b" * 64, owner_user_id, after_both_ttls
        ) is None
        consumed = repo.consume_issuance_confirmation(
            "b" * 64,
            owner_user_id,
            after_both_ttls,
            "issued",
            claim_id_digest=CONFIRMATION_CLAIM_DIGEST,
        )

        assert consumed is not None
        assert consumed["terminal_reason"] == "issued"
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


def test_prune_preserves_expired_claimed_callback_and_confirmation(
    database_path,
) -> None:
    connection = open_connection(database_path)
    try:
        owner_user_id = seed_owner_and_passport(connection)
        repo = Repository(connection)
        claimed_callback = callback_values(owner_user_id)
        claimed_callback["expires_at"] = "2026-08-14T10:06:00+00:00"
        repo.create_callback_handle(**claimed_callback)
        claimed_confirmation = confirmation_values(owner_user_id)
        claimed_confirmation["expires_at"] = "2026-08-14T10:06:00+00:00"
        repo.create_issuance_confirmation(**claimed_confirmation)
        assert repo.claim_callback_handle(
            "a" * 64,
            owner_user_id,
            NOW,
            claim_id_digest=CALLBACK_CLAIM_DIGEST,
            claim_expires_at=CLAIM_EXPIRES_AT,
        ) is not None
        assert repo.claim_issuance_confirmation(
            "b" * 64,
            owner_user_id,
            NOW,
            claim_id_digest=CONFIRMATION_CLAIM_DIGEST,
            claim_expires_at=CLAIM_EXPIRES_AT,
        ) is not None
        after_both_ttls = "2026-08-14T10:09:00+00:00"

        assert repo.prune_expired_phase15_callback_state(after_both_ttls) == 0
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
        assert confirmation is not None
    finally:
        connection.close()


def test_restart_terminally_consumes_abandoned_claims_with_owner_boundary(
    database_path,
) -> None:
    connection = open_connection(database_path)
    try:
        owner_user_id = seed_owner_and_passport(connection)
        other_owner_id = Repository(connection).upsert_user(
            telegram_id=15002,
            username="other",
            first_name="Other",
            last_name="Owner",
        )
        live_repo = Repository(connection)
        callback = callback_values(owner_user_id)
        callback["expires_at"] = "2026-08-14T10:06:00+00:00"
        confirmation = confirmation_values(owner_user_id)
        confirmation["expires_at"] = "2026-08-14T10:06:00+00:00"
        live_repo.create_callback_handle(**callback)
        live_repo.create_issuance_confirmation(**confirmation)
        assert live_repo.claim_callback_handle(
            "a" * 64,
            owner_user_id,
            NOW,
            claim_id_digest=CALLBACK_CLAIM_DIGEST,
            claim_expires_at=CLAIM_EXPIRES_AT,
        ) is not None
        assert live_repo.claim_issuance_confirmation(
            "b" * 64,
            owner_user_id,
            NOW,
            claim_id_digest=CONFIRMATION_CLAIM_DIGEST,
            claim_expires_at=CLAIM_EXPIRES_AT,
        ) is not None
        after_both_ttls = "2026-08-14T10:09:00+00:00"

        assert live_repo.prune_expired_phase15_callback_state(after_both_ttls) == 0
        restarted_repo = Repository(connection)
        assert restarted_repo.consume_expired_callback_handle(
            "a" * 64,
            other_owner_id,
            after_both_ttls,
            expected_purpose="select_protocol",
        ) is None
        assert restarted_repo.consume_expired_issuance_confirmation(
            "b" * 64,
            other_owner_id,
            after_both_ttls,
        ) is None

        expired_callback = restarted_repo.consume_expired_callback_handle(
            "a" * 64,
            owner_user_id,
            after_both_ttls,
            expected_purpose="select_protocol",
        )
        expired_confirmation = restarted_repo.consume_expired_issuance_confirmation(
            "b" * 64,
            owner_user_id,
            after_both_ttls,
        )

        assert expired_callback is not None
        assert expired_callback["terminal_reason"] == "expired"
        assert expired_confirmation is not None
        assert expired_confirmation["terminal_reason"] == "expired"
        assert restarted_repo.prune_expired_phase15_callback_state(after_both_ttls) == 2
    finally:
        connection.close()


def test_restart_directly_prunes_abandoned_expired_claims(database_path) -> None:
    connection = open_connection(database_path)
    try:
        owner_user_id = seed_owner_and_passport(connection)
        live_repo = Repository(connection)
        callback = callback_values(owner_user_id)
        callback["expires_at"] = "2026-08-14T10:06:00+00:00"
        confirmation = confirmation_values(owner_user_id)
        confirmation["expires_at"] = "2026-08-14T10:06:00+00:00"
        live_repo.create_callback_handle(**callback)
        live_repo.create_issuance_confirmation(**confirmation)
        assert live_repo.claim_callback_handle(
            "a" * 64,
            owner_user_id,
            NOW,
            claim_id_digest=CALLBACK_CLAIM_DIGEST,
            claim_expires_at=CLAIM_EXPIRES_AT,
        ) is not None
        assert live_repo.claim_issuance_confirmation(
            "b" * 64,
            owner_user_id,
            NOW,
            claim_id_digest=CONFIRMATION_CLAIM_DIGEST,
            claim_expires_at=CLAIM_EXPIRES_AT,
        ) is not None

        restarted_repo = Repository(connection)
        assert restarted_repo.prune_expired_phase15_callback_state(
            "2026-08-14T10:09:00+00:00"
        ) == 2
        assert connection.execute(
            "SELECT COUNT(*) FROM telegram_callback_handles"
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM protocol_issuance_confirmations"
        ).fetchone()[0] == 0
    finally:
        connection.close()


def test_replaced_claim_digests_are_not_protected_by_old_registration(
    database_path,
) -> None:
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
        connection.execute(
            "UPDATE telegram_callback_handles "
            "SET claim_id_digest = ?, claimed_at = ?, claim_expires_at = ?",
            ("3" * 64, "2026-08-14T10:07:00+00:00", "2026-08-14T10:09:00+00:00"),
        )
        connection.execute(
            "UPDATE protocol_issuance_confirmations "
            "SET claim_id_digest = ?, claimed_at = ?, claim_expires_at = ?",
            ("4" * 64, "2026-08-14T10:07:00+00:00", "2026-08-14T10:09:00+00:00"),
        )
        connection.commit()

        assert repo.prune_expired_phase15_callback_state(
            "2026-08-14T10:11:00+00:00"
        ) == 2
    finally:
        connection.close()


def test_prune_removes_expired_claimed_and_consumed_callback_and_confirmation(
    database_path,
) -> None:
    connection = open_connection(database_path)
    try:
        owner_user_id = seed_owner_and_passport(connection)
        repo = Repository(connection)
        claimed_callback = callback_values(owner_user_id)
        claimed_callback["expires_at"] = "2026-08-14T10:06:00+00:00"
        repo.create_callback_handle(**claimed_callback)
        claimed_confirmation = confirmation_values(owner_user_id)
        claimed_confirmation["expires_at"] = "2026-08-14T10:06:00+00:00"
        repo.create_issuance_confirmation(**claimed_confirmation)
        assert repo.claim_callback_handle(
            "a" * 64,
            owner_user_id,
            NOW,
            claim_id_digest=CALLBACK_CLAIM_DIGEST,
            claim_expires_at=CLAIM_EXPIRES_AT,
        ) is not None
        assert repo.claim_issuance_confirmation(
            "b" * 64,
            owner_user_id,
            NOW,
            claim_id_digest=CONFIRMATION_CLAIM_DIGEST,
            claim_expires_at=CLAIM_EXPIRES_AT,
        ) is not None
        after_both_ttls = "2026-08-14T10:09:00+00:00"
        assert repo.consume_callback_handle(
            "a" * 64,
            owner_user_id,
            after_both_ttls,
            "protocol-selected",
            claim_id_digest=CALLBACK_CLAIM_DIGEST,
        ) is not None
        assert repo.consume_issuance_confirmation(
            "b" * 64,
            owner_user_id,
            after_both_ttls,
            "issued",
            claim_id_digest=CONFIRMATION_CLAIM_DIGEST,
        ) is not None

        assert repo.prune_expired_phase15_callback_state(after_both_ttls) == 2
        assert connection.execute(
            "SELECT 1 FROM telegram_callback_handles WHERE handle_digest = ?",
            ("a" * 64,),
        ).fetchone() is None
        assert connection.execute(
            "SELECT 1 FROM protocol_issuance_confirmations WHERE token_digest = ?",
            ("b" * 64,),
        ).fetchone() is None
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
        confirmations_after = [
            tuple(row)
            for row in connection.execute(
                "SELECT * FROM protocol_issuance_confirmations ORDER BY token_digest"
            )
        ]
        assert [row[:-1] for row in confirmations_after] == confirmations_before
        assert [row[-1] for row in confirmations_after] == [None, None]
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
