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
    handle_digest TEXT NOT NULL PRIMARY KEY
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
            claim_id_digest IS NOT NULL
            AND length(claim_id_digest) = 64
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
    FOREIGN KEY(passport_device_id) REFERENCES device_passports(device_id)
)
"""


CREATE_CONFIRMATION_TABLE_SQL = """
CREATE TABLE protocol_issuance_confirmations (
    token_digest TEXT NOT NULL PRIMARY KEY
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
            claim_id_digest IS NOT NULL
            AND length(claim_id_digest) = 64
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
    FOREIGN KEY(passport_device_id) REFERENCES device_passports(device_id)
)
"""


D827_CALLBACK_TABLE_SQL = (
    CREATE_CALLBACK_TABLE_SQL.replace(
        "handle_digest TEXT NOT NULL PRIMARY KEY",
        "handle_digest TEXT PRIMARY KEY",
    )
    .replace(
        "            claim_id_digest IS NOT NULL\n"
        "            AND length(claim_id_digest) = 64",
        "            length(claim_id_digest) = 64",
    )
    .replace(
        "FOREIGN KEY(passport_device_id) REFERENCES device_passports(device_id)",
        "FOREIGN KEY(passport_device_id, owner_user_id)\n"
        "        REFERENCES device_passports(device_id, owner_user_id)",
    )
)
D827_CONFIRMATION_TABLE_SQL = (
    CREATE_CONFIRMATION_TABLE_SQL.replace(
        "token_digest TEXT NOT NULL PRIMARY KEY",
        "token_digest TEXT PRIMARY KEY",
    )
    .replace(
        "            claim_id_digest IS NOT NULL\n"
        "            AND length(claim_id_digest) = 64",
        "            length(claim_id_digest) = 64",
    )
    .replace(
        "FOREIGN KEY(passport_device_id) REFERENCES device_passports(device_id)",
        "FOREIGN KEY(passport_device_id, owner_user_id)\n"
        "        REFERENCES device_passports(device_id, owner_user_id)",
    )
)
D827_DEVICE_OWNER_INDEX_SQL = (
    "CREATE UNIQUE INDEX uq_device_passports_device_owner "
    "ON device_passports(device_id, owner_user_id)"
)


INDEX_SQL = (
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


TRIGGER_SQL = (
    """
    CREATE TRIGGER IF NOT EXISTS trg_phase15_callback_owner_passport_insert
    BEFORE INSERT ON telegram_callback_handles
    FOR EACH ROW
    WHEN NOT EXISTS (
        SELECT 1
        FROM device_passports
        WHERE device_id = NEW.passport_device_id
          AND owner_user_id = NEW.owner_user_id
    )
    BEGIN
        SELECT RAISE(ABORT, 'phase15 callback owner/passport mismatch');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_phase15_callback_owner_passport_update
    BEFORE UPDATE OF owner_user_id, passport_device_id
    ON telegram_callback_handles
    FOR EACH ROW
    WHEN NOT EXISTS (
        SELECT 1
        FROM device_passports
        WHERE device_id = NEW.passport_device_id
          AND owner_user_id = NEW.owner_user_id
    )
    BEGIN
        SELECT RAISE(ABORT, 'phase15 callback owner/passport mismatch');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_phase15_confirmation_owner_passport_insert
    BEFORE INSERT ON protocol_issuance_confirmations
    FOR EACH ROW
    WHEN NOT EXISTS (
        SELECT 1
        FROM device_passports
        WHERE device_id = NEW.passport_device_id
          AND owner_user_id = NEW.owner_user_id
    )
    BEGIN
        SELECT RAISE(ABORT, 'phase15 confirmation owner/passport mismatch');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_phase15_confirmation_owner_passport_update
    BEFORE UPDATE OF owner_user_id, passport_device_id
    ON protocol_issuance_confirmations
    FOR EACH ROW
    WHEN NOT EXISTS (
        SELECT 1
        FROM device_passports
        WHERE device_id = NEW.passport_device_id
          AND owner_user_id = NEW.owner_user_id
    )
    BEGIN
        SELECT RAISE(ABORT, 'phase15 confirmation owner/passport mismatch');
    END
    """,
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
        if _is_exact_d827_predecessor_shape(conn):
            _upgrade_d827_schema(conn)
            return
        _validate_canonical_shape(conn)
        _ensure_phase15_objects(conn)
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
    conn.execute(CREATE_CALLBACK_TABLE_SQL)
    conn.execute(CREATE_CONFIRMATION_TABLE_SQL)
    _ensure_phase15_objects(conn)


def _ensure_phase15_objects(conn: sqlite3.Connection) -> None:
    for statement in INDEX_SQL:
        conn.execute(statement)
    for statement in TRIGGER_SQL:
        conn.execute(statement)


def _upgrade_legacy_schema(conn: sqlite3.Connection) -> None:
    _rebuild_phase15_schema(
        conn,
        callback_source_columns=LEGACY_CALLBACK_COLUMNS,
        confirmation_source_columns=LEGACY_CONFIRMATION_COLUMNS,
        include_claim_state=False,
        drop_d827_device_owner_index=False,
    )


def _upgrade_d827_schema(conn: sqlite3.Connection) -> None:
    _rebuild_phase15_schema(
        conn,
        callback_source_columns=CALLBACK_COLUMNS,
        confirmation_source_columns=CONFIRMATION_COLUMNS,
        include_claim_state=True,
        drop_d827_device_owner_index=True,
    )


def _rebuild_phase15_schema(
    conn: sqlite3.Connection,
    *,
    callback_source_columns: tuple[str, ...],
    confirmation_source_columns: tuple[str, ...],
    include_claim_state: bool,
    drop_d827_device_owner_index: bool,
) -> None:
    if conn.in_transaction:
        raise RuntimeError("phase15 bootstrap upgrade requires no active transaction")

    foreign_keys_enabled = int(conn.execute("PRAGMA foreign_keys").fetchone()[0])
    try:
        conn.execute("PRAGMA foreign_keys = OFF")
        conn.execute("BEGIN IMMEDIATE")
        if drop_d827_device_owner_index:
            _validate_exact_d827_predecessor_shape(conn)
        callback_count, confirmation_count = _prevalidate_rows(
            conn,
            include_claim_state=include_claim_state,
        )

        for index_name in (
            "idx_protocol_issuance_confirmations_owner_passport",
            "idx_protocol_issuance_confirmations_selection_handle",
            "idx_protocol_issuance_confirmations_expires_at",
            "idx_telegram_callback_handles_owner_passport",
            "idx_telegram_callback_handles_expires_at",
        ):
            conn.execute(f"DROP INDEX IF EXISTS {index_name}")
        if drop_d827_device_owner_index:
            conn.execute("DROP INDEX uq_device_passports_device_owner")
            _validate_d827_index_drop(conn)

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

        callback_columns = ", ".join(callback_source_columns)
        confirmation_columns = ", ".join(confirmation_source_columns)
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
        _ensure_phase15_objects(conn)

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


def _prevalidate_rows(
    conn: sqlite3.Connection, *, include_claim_state: bool
) -> tuple[int, int]:
    callback_count = int(
        conn.execute("SELECT COUNT(*) FROM telegram_callback_handles").fetchone()[0]
    )
    confirmation_count = int(
        conn.execute(
            "SELECT COUNT(*) FROM protocol_issuance_confirmations"
        ).fetchone()[0]
    )
    callback_claim_predicate = ""
    confirmation_claim_predicate = ""
    if include_claim_state:
        callback_claim_predicate = """
               OR NOT (
                    (callback.claim_id_digest IS NULL
                     AND callback.claimed_at IS NULL
                     AND callback.claim_expires_at IS NULL)
                    OR (
                        callback.claim_id_digest IS NOT NULL
                        AND length(callback.claim_id_digest) = 64
                        AND callback.claim_id_digest NOT GLOB '*[^0-9a-f]*'
                        AND callback.claimed_at IS NOT NULL
                        AND callback.claim_expires_at IS NOT NULL
                        AND callback.claim_expires_at > callback.claimed_at
                    )
               )
        """
        confirmation_claim_predicate = """
               OR NOT (
                    (confirmation.claim_id_digest IS NULL
                     AND confirmation.claimed_at IS NULL
                     AND confirmation.claim_expires_at IS NULL)
                    OR (
                        confirmation.claim_id_digest IS NOT NULL
                        AND length(confirmation.claim_id_digest) = 64
                        AND confirmation.claim_id_digest NOT GLOB '*[^0-9a-f]*'
                        AND confirmation.claimed_at IS NOT NULL
                        AND confirmation.claim_expires_at IS NOT NULL
                        AND confirmation.claim_expires_at > confirmation.claimed_at
                    )
               )
        """

    invalid_callbacks = int(
        conn.execute(
            f"""
            SELECT COUNT(*)
            FROM telegram_callback_handles AS callback
            LEFT JOIN users AS owner ON owner.id = callback.owner_user_id
            LEFT JOIN device_passports AS passport
              ON passport.device_id = callback.passport_device_id
             AND passport.owner_user_id = callback.owner_user_id
            WHERE callback.handle_digest IS NULL
               OR length(callback.handle_digest) != 64
               OR callback.handle_digest GLOB '*[^0-9a-f]*'
               OR owner.id IS NULL
               OR passport.device_id IS NULL
               OR ((callback.consumed_at IS NULL)
                   <> (callback.terminal_reason IS NULL))
               {callback_claim_predicate}
            """
        ).fetchone()[0]
    )
    invalid_confirmations = int(
        conn.execute(
            f"""
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
            WHERE confirmation.token_digest IS NULL
               OR length(confirmation.token_digest) != 64
               OR confirmation.token_digest GLOB '*[^0-9a-f]*'
               OR confirmation.selection_handle_digest IS NULL
               OR length(confirmation.selection_handle_digest) != 64
               OR confirmation.selection_handle_digest GLOB '*[^0-9a-f]*'
               OR owner.id IS NULL
               OR passport.device_id IS NULL
               OR callback.handle_digest IS NULL
               OR ((confirmation.consumed_at IS NULL)
                   <> (confirmation.terminal_reason IS NULL))
               {confirmation_claim_predicate}
            """
        ).fetchone()[0]
    )
    if invalid_callbacks or invalid_confirmations:
        raise RuntimeError("phase15 legacy rows are incompatible with lease schema")
    return callback_count, confirmation_count


def _is_exact_d827_predecessor_shape(conn: sqlite3.Connection) -> bool:
    expected_phase15_indexes = {
        _normalize_sql(statement.replace(" IF NOT EXISTS", ""))
        for statement in INDEX_SQL
    }
    actual_phase15_indexes = {
        _normalize_sql(str(row[0]))
        for row in conn.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'index' "
            "AND tbl_name IN (?, ?) AND sql IS NOT NULL",
            ("telegram_callback_handles", "protocol_issuance_confirmations"),
        )
    }
    phase15_triggers = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'trigger' "
        "AND tbl_name IN (?, ?) LIMIT 1",
        ("telegram_callback_handles", "protocol_issuance_confirmations"),
    ).fetchone()
    predecessor_index = conn.execute(
        "SELECT tbl_name, sql FROM sqlite_master "
        "WHERE type = 'index' AND name = ?",
        ("uq_device_passports_device_owner",),
    ).fetchone()
    return (
        _table_sql(conn, "telegram_callback_handles")
        == _normalize_sql(D827_CALLBACK_TABLE_SQL)
        and _table_sql(conn, "protocol_issuance_confirmations")
        == _normalize_sql(D827_CONFIRMATION_TABLE_SQL)
        and actual_phase15_indexes == expected_phase15_indexes
        and phase15_triggers is None
        and predecessor_index is not None
        and str(predecessor_index[0]) == "device_passports"
        and _normalize_sql(str(predecessor_index[1]))
        == D827_DEVICE_OWNER_INDEX_SQL
    )


def _validate_exact_d827_predecessor_shape(conn: sqlite3.Connection) -> None:
    if not _is_exact_d827_predecessor_shape(conn):
        raise RuntimeError("phase15 d827 predecessor schema changed during migration")


def _validate_d827_index_drop(conn: sqlite3.Connection) -> None:
    predecessor_index = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = ?",
        ("uq_device_passports_device_owner",),
    ).fetchone()
    legacy_copy_exists = any(
        _table_exists(conn, table)
        for table in (
            "telegram_callback_handles_legacy",
            "protocol_issuance_confirmations_legacy",
        )
    )
    if (
        predecessor_index is not None
        or legacy_copy_exists
        or _table_sql(conn, "telegram_callback_handles")
        != _normalize_sql(D827_CALLBACK_TABLE_SQL)
        or _table_sql(conn, "protocol_issuance_confirmations")
        != _normalize_sql(D827_CONFIRMATION_TABLE_SQL)
    ):
        raise RuntimeError("phase15 d827 index drop changed unexpected schema")


def _table_sql(conn: sqlite3.Connection, table: str) -> str:
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table,),
    ).fetchone()
    return _normalize_sql(str(row[0])) if row is not None else ""


def _normalize_sql(statement: str) -> str:
    return " ".join(statement.split())


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
            "users",
            (("owner_user_id", "id"),),
        ),
        (
            "telegram_callback_handles",
            "device_passports",
            (("passport_device_id", "device_id"),),
        ),
        (
            "protocol_issuance_confirmations",
            "users",
            (("owner_user_id", "id"),),
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
            (("passport_device_id", "device_id"),),
        ),
    )
    if not all(
        _has_foreign_key(conn, table, target, columns)
        for table, target, columns in required_foreign_keys
    ):
        raise RuntimeError("unsupported phase15 owner binding constraints")
    required_triggers = {
        "trg_phase15_callback_owner_passport_insert",
        "trg_phase15_callback_owner_passport_update",
        "trg_phase15_confirmation_owner_passport_insert",
        "trg_phase15_confirmation_owner_passport_update",
    }
    actual_triggers = {
        str(row[0])
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'trigger' "
            "AND tbl_name IN (?, ?)",
            ("telegram_callback_handles", "protocol_issuance_confirmations"),
        )
    }
    if not required_triggers.issubset(actual_triggers):
        raise RuntimeError("unsupported phase15 owner binding triggers")
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
        ) or "claim_id_digest IS NOT NULL" not in table_sql:
            raise RuntimeError("unsupported phase15 digest constraints")
    not_null_columns = {
        table: {
            str(row[1]): int(row[3])
            for row in conn.execute(f"PRAGMA table_info({table})")
        }
        for table in (
            "telegram_callback_handles",
            "protocol_issuance_confirmations",
        )
    }
    if (
        not_null_columns["telegram_callback_handles"].get("handle_digest") != 1
        or not_null_columns["protocol_issuance_confirmations"].get("token_digest")
        != 1
    ):
        raise RuntimeError("unsupported phase15 nullable identity digest")


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
