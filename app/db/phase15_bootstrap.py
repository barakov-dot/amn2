import sqlite3


LEGACY_CALLBACK_COLUMNS = (
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
)
LEGACY_CONFIRMATION_COLUMNS = (
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
)
CLAIM_COLUMNS = ("claim_id_digest", "claimed_at", "claim_expires_at")
CALLBACK_COLUMNS = (
    LEGACY_CALLBACK_COLUMNS[:11]
    + CLAIM_COLUMNS
    + LEGACY_CALLBACK_COLUMNS[11:]
)
CONFIRMATION_COLUMNS = (
    LEGACY_CONFIRMATION_COLUMNS[:11]
    + CLAIM_COLUMNS
    + LEGACY_CONFIRMATION_COLUMNS[11:]
)


CREATE_CALLBACK_TABLE_SQL = """
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
)
"""


CREATE_CONFIRMATION_TABLE_SQL = """
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
)
"""


INDEX_SQL = (
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_device_passports_device_owner "
    "ON device_passports(device_id, owner_user_id)",
    "CREATE INDEX IF NOT EXISTS idx_telegram_callback_handles_owner_passport "
    "ON telegram_callback_handles(owner_user_id, passport_device_id)",
    "CREATE INDEX IF NOT EXISTS idx_telegram_callback_handles_expires_at "
    "ON telegram_callback_handles(expires_at)",
    "CREATE INDEX IF NOT EXISTS idx_protocol_issuance_confirmations_owner_passport "
    "ON protocol_issuance_confirmations(owner_user_id, passport_device_id)",
    "CREATE INDEX IF NOT EXISTS idx_protocol_issuance_confirmations_selection_handle "
    "ON protocol_issuance_confirmations(selection_handle_digest)",
    "CREATE INDEX IF NOT EXISTS idx_protocol_issuance_confirmations_expires_at "
    "ON protocol_issuance_confirmations(expires_at)",
)


def ensure_phase15_bootstrap_schema(conn: sqlite3.Connection) -> None:
    callback_columns = _column_names(conn, "telegram_callback_handles")
    confirmation_columns = _column_names(conn, "protocol_issuance_confirmations")
    legacy_copy_exists = any(
        _table_exists(conn, table)
        for table in (
            "telegram_callback_handles_legacy",
            "protocol_issuance_confirmations_legacy",
        )
    )
    if legacy_copy_exists:
        raise RuntimeError("phase15 bootstrap schema migration is ambiguous")

    if not callback_columns and not confirmation_columns:
        _create_phase15_schema(conn)
        return

    if (
        callback_columns == CALLBACK_COLUMNS
        and confirmation_columns == CONFIRMATION_COLUMNS
    ):
        _validate_canonical_shape(conn)
        _ensure_indexes(conn)
        return

    if (
        callback_columns == LEGACY_CALLBACK_COLUMNS
        and confirmation_columns == LEGACY_CONFIRMATION_COLUMNS
    ):
        _validate_legacy_shape(conn)
        _upgrade_legacy_schema(conn)
        return

    raise RuntimeError("unsupported partial phase15 bootstrap schema")


def _create_phase15_schema(conn: sqlite3.Connection) -> None:
    conn.execute(INDEX_SQL[0])
    conn.execute(CREATE_CALLBACK_TABLE_SQL)
    conn.execute(CREATE_CONFIRMATION_TABLE_SQL)
    for statement in INDEX_SQL[1:]:
        conn.execute(statement)


def _ensure_indexes(conn: sqlite3.Connection) -> None:
    for statement in INDEX_SQL:
        conn.execute(statement)


def _upgrade_legacy_schema(conn: sqlite3.Connection) -> None:
    if conn.in_transaction:
        raise RuntimeError("phase15 bootstrap upgrade requires no active transaction")

    foreign_keys_enabled = int(conn.execute("PRAGMA foreign_keys").fetchone()[0])
    try:
        conn.execute("PRAGMA foreign_keys = OFF")
        conn.execute("BEGIN IMMEDIATE")
        callback_count, confirmation_count = _prevalidate_legacy_rows(conn)

        conn.execute(INDEX_SQL[0])
        for index_name in (
            "idx_protocol_issuance_confirmations_owner_passport",
            "idx_protocol_issuance_confirmations_selection_handle",
            "idx_protocol_issuance_confirmations_expires_at",
            "idx_telegram_callback_handles_owner_passport",
            "idx_telegram_callback_handles_expires_at",
        ):
            conn.execute(f"DROP INDEX IF EXISTS {index_name}")

        conn.execute(
            "ALTER TABLE protocol_issuance_confirmations "
            "RENAME TO protocol_issuance_confirmations_legacy"
        )
        conn.execute(
            "ALTER TABLE telegram_callback_handles "
            "RENAME TO telegram_callback_handles_legacy"
        )
        conn.execute(CREATE_CALLBACK_TABLE_SQL)
        conn.execute(CREATE_CONFIRMATION_TABLE_SQL)

        callback_columns = ", ".join(LEGACY_CALLBACK_COLUMNS)
        confirmation_columns = ", ".join(LEGACY_CONFIRMATION_COLUMNS)
        conn.execute(
            f"INSERT INTO telegram_callback_handles ({callback_columns}) "
            f"SELECT {callback_columns} FROM telegram_callback_handles_legacy"
        )
        conn.execute(
            f"INSERT INTO protocol_issuance_confirmations ({confirmation_columns}) "
            f"SELECT {confirmation_columns} "
            "FROM protocol_issuance_confirmations_legacy"
        )

        copied_callback_count = int(
            conn.execute("SELECT COUNT(*) FROM telegram_callback_handles").fetchone()[0]
        )
        copied_confirmation_count = int(
            conn.execute(
                "SELECT COUNT(*) FROM protocol_issuance_confirmations"
            ).fetchone()[0]
        )
        if (
            copied_callback_count != callback_count
            or copied_confirmation_count != confirmation_count
        ):
            raise RuntimeError("phase15 bootstrap migration row count mismatch")

        conn.execute("DROP TABLE protocol_issuance_confirmations_legacy")
        conn.execute("DROP TABLE telegram_callback_handles_legacy")
        for statement in INDEX_SQL[1:]:
            conn.execute(statement)

        violations = conn.execute("PRAGMA foreign_key_check").fetchall()
        if violations:
            raise sqlite3.IntegrityError(
                f"foreign key violations after phase15 migration: {violations!r}"
            )
        conn.commit()
    except BaseException:
        if conn.in_transaction:
            conn.rollback()
        raise
    finally:
        conn.execute(f"PRAGMA foreign_keys = {foreign_keys_enabled}")


def _prevalidate_legacy_rows(conn: sqlite3.Connection) -> tuple[int, int]:
    callback_count = int(
        conn.execute("SELECT COUNT(*) FROM telegram_callback_handles").fetchone()[0]
    )
    confirmation_count = int(
        conn.execute(
            "SELECT COUNT(*) FROM protocol_issuance_confirmations"
        ).fetchone()[0]
    )
    invalid_callbacks = int(
        conn.execute(
            """
            SELECT COUNT(*)
            FROM telegram_callback_handles AS callback
            LEFT JOIN users AS owner ON owner.id = callback.owner_user_id
            LEFT JOIN device_passports AS passport
              ON passport.device_id = callback.passport_device_id
             AND passport.owner_user_id = callback.owner_user_id
            WHERE length(callback.handle_digest) != 64
               OR callback.handle_digest GLOB '*[^0-9a-f]*'
               OR owner.id IS NULL
               OR passport.device_id IS NULL
               OR ((callback.consumed_at IS NULL)
                   <> (callback.terminal_reason IS NULL))
            """
        ).fetchone()[0]
    )
    invalid_confirmations = int(
        conn.execute(
            """
            SELECT COUNT(*)
            FROM protocol_issuance_confirmations AS confirmation
            LEFT JOIN users AS owner ON owner.id = confirmation.owner_user_id
            LEFT JOIN device_passports AS passport
              ON passport.device_id = confirmation.passport_device_id
             AND passport.owner_user_id = confirmation.owner_user_id
            LEFT JOIN telegram_callback_handles AS callback
              ON callback.handle_digest = confirmation.selection_handle_digest
             AND callback.owner_user_id = confirmation.owner_user_id
             AND callback.passport_device_id = confirmation.passport_device_id
            WHERE length(confirmation.token_digest) != 64
               OR confirmation.token_digest GLOB '*[^0-9a-f]*'
               OR length(confirmation.selection_handle_digest) != 64
               OR confirmation.selection_handle_digest GLOB '*[^0-9a-f]*'
               OR owner.id IS NULL
               OR passport.device_id IS NULL
               OR callback.handle_digest IS NULL
               OR ((confirmation.consumed_at IS NULL)
                   <> (confirmation.terminal_reason IS NULL))
            """
        ).fetchone()[0]
    )
    if invalid_callbacks or invalid_confirmations:
        raise RuntimeError("phase15 legacy rows are incompatible with lease schema")
    return callback_count, confirmation_count


def _validate_legacy_shape(conn: sqlite3.Connection) -> None:
    if not _has_unique_index(
        conn,
        "telegram_callback_handles",
        ("handle_digest", "owner_user_id", "passport_device_id"),
    ):
        raise RuntimeError("unsupported phase15 callback handle constraints")
    if not _has_foreign_key(
        conn,
        "protocol_issuance_confirmations",
        "telegram_callback_handles",
        (
            ("selection_handle_digest", "handle_digest"),
            ("owner_user_id", "owner_user_id"),
            ("passport_device_id", "passport_device_id"),
        ),
    ):
        raise RuntimeError("unsupported phase15 confirmation constraints")


def _validate_canonical_shape(conn: sqlite3.Connection) -> None:
    if not _has_unique_index(
        conn,
        "telegram_callback_handles",
        ("handle_digest", "owner_user_id", "passport_device_id"),
    ):
        raise RuntimeError("unsupported phase15 callback handle constraints")
    required_foreign_keys = (
        (
            "telegram_callback_handles",
            "device_passports",
            (
                ("passport_device_id", "device_id"),
                ("owner_user_id", "owner_user_id"),
            ),
        ),
        (
            "protocol_issuance_confirmations",
            "telegram_callback_handles",
            (
                ("selection_handle_digest", "handle_digest"),
                ("owner_user_id", "owner_user_id"),
                ("passport_device_id", "passport_device_id"),
            ),
        ),
        (
            "protocol_issuance_confirmations",
            "device_passports",
            (
                ("passport_device_id", "device_id"),
                ("owner_user_id", "owner_user_id"),
            ),
        ),
    )
    if not all(
        _has_foreign_key(conn, table, target, columns)
        for table, target, columns in required_foreign_keys
    ):
        raise RuntimeError("unsupported phase15 owner binding constraints")
    for table, digest_columns in (
        ("telegram_callback_handles", ("handle_digest", "claim_id_digest")),
        (
            "protocol_issuance_confirmations",
            ("token_digest", "selection_handle_digest", "claim_id_digest"),
        ),
    ):
        sql_row = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table,),
        ).fetchone()
        table_sql = str(sql_row[0]) if sql_row is not None else ""
        if any(
            f"{column} NOT GLOB '*[^0-9a-f]*'" not in table_sql
            for column in digest_columns
        ):
            raise RuntimeError("unsupported phase15 digest constraints")


def _has_foreign_key(
    conn: sqlite3.Connection,
    table: str,
    target: str,
    columns: tuple[tuple[str, str], ...],
) -> bool:
    groups: dict[int, list[tuple[str, str, str]]] = {}
    for row in conn.execute(f"PRAGMA foreign_key_list({table})"):
        groups.setdefault(int(row[0]), []).append(
            (str(row[2]), str(row[3]), str(row[4]))
        )
    expected = [(target, source, destination) for source, destination in columns]
    return any(group == expected for group in groups.values())


def _has_unique_index(
    conn: sqlite3.Connection, table: str, columns: tuple[str, ...]
) -> bool:
    for row in conn.execute(f"PRAGMA index_list({table})"):
        if not int(row[2]):
            continue
        actual = tuple(
            str(index_row[2])
            for index_row in conn.execute(f"PRAGMA index_info({row[1]})")
        )
        if actual == columns:
            return True
    return False


def _column_names(conn: sqlite3.Connection, table: str) -> tuple[str, ...]:
    return tuple(str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})"))


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    return (
        conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table,),
        ).fetchone()
        is not None
    )
