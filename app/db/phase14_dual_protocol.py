import sqlite3


PHASE14_DUAL_PROTOCOL_SQL = """
CREATE TABLE IF NOT EXISTS awg3_control_state (
    singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
    runtime_accepted INTEGER NOT NULL DEFAULT 0 CHECK (runtime_accepted IN (0,1)),
    global_accepted INTEGER NOT NULL DEFAULT 0 CHECK (global_accepted IN (0,1)),
    issuance_enabled INTEGER NOT NULL DEFAULT 0 CHECK (issuance_enabled IN (0,1)),
    emergency_suspended INTEGER NOT NULL DEFAULT 0 CHECK (emergency_suspended IN (0,1)),
    runtime_receipt TEXT,
    actor_id INTEGER,
    reason TEXT,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (issuance_enabled = 0 OR (global_accepted = 1 AND emergency_suspended = 0))
);
INSERT OR IGNORE INTO awg3_control_state(singleton_id) VALUES (1);

CREATE TABLE IF NOT EXISTS client_build_acceptances (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    application TEXT NOT NULL,
    platform TEXT NOT NULL,
    client_version TEXT NOT NULL,
    client_build TEXT NOT NULL,
    protocol_version TEXT NOT NULL DEFAULT 'awg3' CHECK (protocol_version = 'awg3'),
    state TEXT NOT NULL CHECK (state IN (
        'candidate','accepted','superseded',
        'compatibility_rejected','security_revoked'
    )),
    evidence_ids_json TEXT NOT NULL,
    actor_id INTEGER NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(application, platform, client_version, client_build, protocol_version)
);

CREATE TABLE IF NOT EXISTS device_protocol_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    passport_device_id TEXT NOT NULL,
    protocol_version TEXT NOT NULL CHECK (protocol_version IN ('awg2','awg3')),
    local_device_id INTEGER NOT NULL UNIQUE,
    lifecycle_state TEXT NOT NULL CHECK (lifecycle_state IN (
        'active','pending_replacement','review_required',
        'temporarily_unavailable','revoked'
    )),
    replacement_device_id INTEGER,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(passport_device_id, protocol_version),
    FOREIGN KEY(passport_device_id) REFERENCES device_passports(device_id),
    FOREIGN KEY(local_device_id) REFERENCES devices(id),
    FOREIGN KEY(replacement_device_id) REFERENCES devices(id)
);

CREATE TABLE IF NOT EXISTS protocol_config_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    actor_kind TEXT NOT NULL CHECK (actor_kind IN ('user','admin','system')),
    actor_id INTEGER NOT NULL,
    reason TEXT NOT NULL,
    passport_device_id TEXT,
    protocol_version TEXT CHECK (protocol_version IS NULL OR protocol_version IN ('awg2','awg3')),
    local_device_id INTEGER,
    metadata_json TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS protocol_issuance_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_user_id INTEGER NOT NULL,
    intended_passport_device_id TEXT NOT NULL,
    passport_device_id TEXT,
    protocol_version TEXT NOT NULL CHECK (protocol_version IN ('awg2','awg3')),
    request_fingerprint TEXT NOT NULL CHECK (length(request_fingerprint) = 71),
    actor_kind TEXT NOT NULL CHECK (actor_kind IN ('user','admin','system')),
    actor_id INTEGER NOT NULL,
    client_application TEXT NOT NULL,
    client_platform TEXT NOT NULL,
    client_version TEXT NOT NULL,
    client_build TEXT,
    runtime_instance_id TEXT,
    compatibility_evidence_id TEXT,
    state TEXT NOT NULL DEFAULT 'reserved' CHECK (state IN (
        'reserved','completed','cancelled','recovery_required'
    )),
    local_device_id INTEGER,
    reason_code TEXT,
    reserved_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TEXT,
    cancelled_at TEXT,
    recovery_required_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(owner_user_id) REFERENCES users(id),
    FOREIGN KEY(passport_device_id) REFERENCES device_passports(device_id),
    FOREIGN KEY(local_device_id) REFERENCES devices(id)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_protocol_issuance_blocking_attempt
    ON protocol_issuance_attempts(intended_passport_device_id, protocol_version)
    WHERE state IN ('reserved','recovery_required');

CREATE TABLE IF NOT EXISTS protocol_issuance_user_barriers (
    user_id INTEGER PRIMARY KEY,
    state TEXT NOT NULL CHECK (state IN ('blocking','blocked')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
);
"""


def ensure_phase14_dual_protocol_schema(conn: sqlite3.Connection) -> None:
    columns = {
        str(row[1])
        for row in conn.execute("PRAGMA table_info(client_compatibility_evidence)")
    }
    if "client_build" not in columns:
        conn.execute(
            "ALTER TABLE client_compatibility_evidence "
            "ADD COLUMN client_build TEXT"
        )
    if "release_kind" not in columns:
        conn.execute(
            "ALTER TABLE client_compatibility_evidence "
            "ADD COLUMN release_kind TEXT "
            "CHECK (release_kind IS NULL OR release_kind IN "
            "('stable','prerelease','unreleased'))"
        )
    receipt_columns = {
        str(row[1])
        for row in conn.execute("PRAGMA table_info(admin_config_issuance_receipts)")
    }
    if receipt_columns and "client_build" not in receipt_columns:
        conn.execute(
            "ALTER TABLE admin_config_issuance_receipts "
            "ADD COLUMN client_build TEXT"
        )
    _migrate_protocol_issuance_attempts(conn)
    conn.executescript(PHASE14_DUAL_PROTOCOL_SQL)


def _migrate_protocol_issuance_attempts(conn: sqlite3.Connection) -> None:
    columns = {
        str(row[1]): int(row[3])
        for row in conn.execute("PRAGMA table_info(protocol_issuance_attempts)")
    }
    legacy_exists = conn.execute(
        "SELECT 1 FROM sqlite_master "
        "WHERE type = 'table' AND name = 'protocol_issuance_attempts_legacy'"
    ).fetchone() is not None
    canonical_exists = bool(columns) and (
        "owner_user_id" in columns
        and "intended_passport_device_id" in columns
        and columns.get("passport_device_id") == 0
    )
    if canonical_exists and not legacy_exists:
        return
    if columns and not canonical_exists:
        if legacy_exists:
            raise RuntimeError("protocol issuance attempt migration is ambiguous")
        conn.execute("DROP INDEX IF EXISTS uq_protocol_issuance_blocking_attempt")
        conn.execute(
            "ALTER TABLE protocol_issuance_attempts "
            "RENAME TO protocol_issuance_attempts_legacy"
        )
        legacy_exists = True
    if not legacy_exists:
        return
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS protocol_issuance_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_user_id INTEGER NOT NULL,
            intended_passport_device_id TEXT NOT NULL,
            passport_device_id TEXT,
            protocol_version TEXT NOT NULL CHECK (protocol_version IN ('awg2','awg3')),
            request_fingerprint TEXT NOT NULL CHECK (length(request_fingerprint) = 71),
            actor_kind TEXT NOT NULL CHECK (actor_kind IN ('user','admin','system')),
            actor_id INTEGER NOT NULL,
            client_application TEXT NOT NULL,
            client_platform TEXT NOT NULL,
            client_version TEXT NOT NULL,
            client_build TEXT,
            runtime_instance_id TEXT,
            compatibility_evidence_id TEXT,
            state TEXT NOT NULL DEFAULT 'reserved' CHECK (state IN (
                'reserved','completed','cancelled','recovery_required'
            )),
            local_device_id INTEGER,
            reason_code TEXT,
            reserved_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            completed_at TEXT,
            cancelled_at TEXT,
            recovery_required_at TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(owner_user_id) REFERENCES users(id),
            FOREIGN KEY(passport_device_id) REFERENCES device_passports(device_id),
            FOREIGN KEY(local_device_id) REFERENCES devices(id)
        );
        """
    )
    legacy = int(
        conn.execute(
            "SELECT COUNT(*) FROM protocol_issuance_attempts_legacy"
        ).fetchone()[0]
    )
    mappable = int(
        conn.execute(
            """
            SELECT COUNT(*)
            FROM protocol_issuance_attempts_legacy AS legacy
            JOIN device_passports AS passports
              ON passports.device_id = legacy.passport_device_id
            """
        ).fetchone()[0]
    )
    if mappable != legacy:
        raise RuntimeError("protocol issuance attempt migration lost legacy rows")
    conn.execute(
        """
        INSERT OR IGNORE INTO protocol_issuance_attempts (
            id, owner_user_id, intended_passport_device_id, passport_device_id,
            protocol_version, request_fingerprint, actor_kind, actor_id,
            client_application, client_platform, client_version, client_build,
            runtime_instance_id, compatibility_evidence_id, state,
            local_device_id, reason_code, reserved_at, completed_at,
            cancelled_at, recovery_required_at, created_at, updated_at
        )
        SELECT
            legacy.id,
            passports.owner_user_id,
            legacy.passport_device_id,
            legacy.passport_device_id,
            legacy.protocol_version,
            legacy.request_fingerprint,
            legacy.actor_kind,
            legacy.actor_id,
            legacy.client_application,
            legacy.client_platform,
            legacy.client_version,
            legacy.client_build,
            legacy.runtime_instance_id,
            legacy.compatibility_evidence_id,
            legacy.state,
            legacy.local_device_id,
            legacy.reason_code,
            legacy.reserved_at,
            legacy.completed_at,
            legacy.cancelled_at,
            legacy.recovery_required_at,
            legacy.created_at,
            legacy.updated_at
        FROM protocol_issuance_attempts_legacy AS legacy
        JOIN device_passports AS passports
          ON passports.device_id = legacy.passport_device_id
        ORDER BY legacy.id
        """
    )
    mismatched = int(
        conn.execute(
            """
            SELECT COUNT(*) FROM (
                SELECT
                    legacy.id,
                    passports.owner_user_id,
                    legacy.passport_device_id,
                    legacy.passport_device_id,
                    legacy.protocol_version,
                    legacy.request_fingerprint,
                    legacy.actor_kind,
                    legacy.actor_id,
                    legacy.client_application,
                    legacy.client_platform,
                    legacy.client_version,
                    legacy.client_build,
                    legacy.runtime_instance_id,
                    legacy.compatibility_evidence_id,
                    legacy.state,
                    legacy.local_device_id,
                    legacy.reason_code,
                    legacy.reserved_at,
                    legacy.completed_at,
                    legacy.cancelled_at,
                    legacy.recovery_required_at,
                    legacy.created_at,
                    legacy.updated_at
                FROM protocol_issuance_attempts_legacy AS legacy
                JOIN device_passports AS passports
                  ON passports.device_id = legacy.passport_device_id
                EXCEPT
                SELECT
                    id, owner_user_id, intended_passport_device_id,
                    passport_device_id, protocol_version, request_fingerprint,
                    actor_kind, actor_id, client_application, client_platform,
                    client_version, client_build, runtime_instance_id,
                    compatibility_evidence_id, state, local_device_id,
                    reason_code, reserved_at, completed_at, cancelled_at,
                    recovery_required_at, created_at, updated_at
                FROM protocol_issuance_attempts
            )
            """
        ).fetchone()[0]
    )
    if mismatched:
        raise RuntimeError("protocol issuance attempt migration mismatched legacy rows")
    conn.execute("DROP TABLE protocol_issuance_attempts_legacy")
