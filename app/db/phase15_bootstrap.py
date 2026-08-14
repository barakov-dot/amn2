import sqlite3


PHASE15_BOOTSTRAP_SQL = """
CREATE TABLE IF NOT EXISTS telegram_callback_handles (
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
CREATE INDEX IF NOT EXISTS idx_telegram_callback_handles_owner_passport
    ON telegram_callback_handles(owner_user_id, passport_device_id);
CREATE INDEX IF NOT EXISTS idx_telegram_callback_handles_expires_at
    ON telegram_callback_handles(expires_at);

CREATE TABLE IF NOT EXISTS protocol_issuance_confirmations (
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
CREATE INDEX IF NOT EXISTS idx_protocol_issuance_confirmations_owner_passport
    ON protocol_issuance_confirmations(owner_user_id, passport_device_id);
CREATE INDEX IF NOT EXISTS idx_protocol_issuance_confirmations_selection_handle
    ON protocol_issuance_confirmations(selection_handle_digest);
CREATE INDEX IF NOT EXISTS idx_protocol_issuance_confirmations_expires_at
    ON protocol_issuance_confirmations(expires_at);
"""


def ensure_phase15_bootstrap_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(PHASE15_BOOTSTRAP_SQL)
