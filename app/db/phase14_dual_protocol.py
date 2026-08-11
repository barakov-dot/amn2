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
    passport_device_id TEXT NOT NULL,
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
    FOREIGN KEY(passport_device_id) REFERENCES device_passports(device_id),
    FOREIGN KEY(local_device_id) REFERENCES devices(id)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_protocol_issuance_blocking_attempt
    ON protocol_issuance_attempts(passport_device_id, protocol_version)
    WHERE state IN ('reserved','recovery_required');
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
    conn.executescript(PHASE14_DUAL_PROTOCOL_SQL)
