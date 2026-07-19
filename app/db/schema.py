import sqlite3


def initialize_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            telegram_id INTEGER UNIQUE,
            operator_label TEXT,
            username TEXT,
            first_name TEXT,
            last_name TEXT,
            status TEXT NOT NULL DEFAULT 'active'
                CHECK (status IN ('active', 'blocked', 'deleted')),
            locale TEXT NOT NULL DEFAULT 'ru'
                CHECK (locale IN ('ru', 'en')),
            is_admin INTEGER NOT NULL DEFAULT 0
                CHECK (is_admin IN (0, 1)),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CHECK (telegram_id IS NOT NULL OR length(trim(operator_label)) > 0)
        );

        CREATE TABLE IF NOT EXISTS servers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            host TEXT,
            ssh_port INTEGER CHECK (ssh_port BETWEEN 1 AND 65535),
            endpoint_host TEXT,
            vpn_port INTEGER CHECK (vpn_port BETWEEN 1 AND 65535),
            vpn_network_cidr TEXT NOT NULL,
            server_address TEXT,
            server_public_key TEXT,
            runtime TEXT,
            firewall TEXT,
            status TEXT NOT NULL DEFAULT 'active'
                CHECK (status IN ('active', 'degraded', 'disabled')),
            max_devices INTEGER CHECK (max_devices >= 0),
            current_devices INTEGER NOT NULL DEFAULT 0
                CHECK (current_devices >= 0),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS server_health_checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            server_id INTEGER NOT NULL,
            status TEXT NOT NULL
                CHECK (status IN ('online', 'degraded', 'offline', 'unknown')),
            latency_ms INTEGER,
            ssh_ok INTEGER NOT NULL DEFAULT 0 CHECK (ssh_ok IN (0, 1)),
            awg_ok INTEGER NOT NULL DEFAULT 0 CHECK (awg_ok IN (0, 1)),
            udp_port_ok INTEGER NOT NULL DEFAULT 0 CHECK (udp_port_ok IN (0, 1)),
            error TEXT,
            checked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS plans (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            duration_days INTEGER NOT NULL CHECK (duration_days > 0),
            max_devices INTEGER CHECK (max_devices > 0),
            price INTEGER NOT NULL DEFAULT 0 CHECK (price >= 0),
            currency TEXT NOT NULL DEFAULT 'RUB',
            is_free INTEGER NOT NULL DEFAULT 1 CHECK (is_free IN (0, 1)),
            is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            server_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            activated_at TEXT,
            expires_at TEXT,
            duration_days INTEGER NOT NULL CHECK (duration_days > 0),
            status TEXT NOT NULL DEFAULT 'active'
                CHECK (status IN ('pending', 'active', 'disabled', 'expired', 'revoked', 'failed')),
            vpn_ip TEXT NOT NULL,
            peer_public_key TEXT NOT NULL,
            peer_private_key_encrypted TEXT NOT NULL,
            preshared_key_encrypted TEXT NOT NULL,
            config_version TEXT NOT NULL,
            config_material_status TEXT NOT NULL DEFAULT 'available'
                CHECK (config_material_status IN ('available', 'external_only')),
            assignment_mode TEXT NOT NULL DEFAULT 'dedicated_device'
                CHECK (assignment_mode IN ('dedicated_device', 'owner_shared')),
            last_config_sent_at TEXT,
            first_connected_at TEXT,
            last_connected_at TEXT,
            revoked_at TEXT,
            revoke_reason TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (server_id) REFERENCES servers(id),
            UNIQUE (server_id, peer_public_key)
        );

        CREATE TABLE IF NOT EXISTS device_passports (
            device_id TEXT PRIMARY KEY,
            local_device_id INTEGER UNIQUE,
            owner_user_id INTEGER NOT NULL,
            platform TEXT NOT NULL,
            official_client_type TEXT NOT NULL,
            client_version TEXT,
            import_method TEXT NOT NULL,
            config_schema_version TEXT NOT NULL,
            config_fingerprint TEXT NOT NULL,
            last_seen_at TEXT,
            acceptance_evidence_json TEXT,
            revoked_at TEXT,
            revoke_reason TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (local_device_id) REFERENCES devices(id) ON DELETE SET NULL,
            FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS device_enrollment_tickets (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            token_prefix TEXT NOT NULL,
            platform TEXT NOT NULL,
            config_schema_version TEXT NOT NULL,
            single_use INTEGER NOT NULL DEFAULT 1 CHECK (single_use = 1),
            expires_at TEXT NOT NULL,
            revoked_at TEXT,
            revoke_reason TEXT,
            claimed_at TEXT,
            claimed_device_id TEXT,
            claim_idempotency_hash TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (claimed_device_id) REFERENCES device_passports(device_id)
                ON DELETE SET NULL DEFERRABLE INITIALLY DEFERRED
        );

        CREATE TABLE IF NOT EXISTS device_lifecycle_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id TEXT,
            passport_device_id TEXT,
            stage TEXT NOT NULL
                CHECK (
                    stage IN (
                        'issued',
                        'claimed',
                        'config_ready',
                        'delivered',
                        'acceptance_verified'
                    )
                ),
            status TEXT NOT NULL CHECK (status IN ('completed', 'failed')),
            occurred_at TEXT NOT NULL,
            duration_ms INTEGER NOT NULL CHECK (duration_ms >= 0),
            failure_stage TEXT
                CHECK (
                    failure_stage IS NULL
                    OR failure_stage IN (
                        'issued',
                        'claimed',
                        'config_ready',
                        'delivered',
                        'acceptance_verified'
                    )
                ),
            evidence_json TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CHECK (ticket_id IS NOT NULL OR passport_device_id IS NOT NULL),
            CHECK (
                (status = 'completed' AND failure_stage IS NULL)
                OR (status = 'failed' AND failure_stage = stage)
            ),
            FOREIGN KEY (ticket_id) REFERENCES device_enrollment_tickets(id)
                ON DELETE CASCADE,
            FOREIGN KEY (passport_device_id) REFERENCES device_passports(device_id)
                ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            device_id INTEGER,
            plan_id TEXT,
            requested_config_version TEXT NOT NULL DEFAULT 'amneziawg_v2',
            status TEXT NOT NULL DEFAULT 'manual_review'
                CHECK (
                    status IN (
                        'draft',
                        'payment_pending',
                        'manual_review',
                        'approved',
                        'rejected',
                        'fulfilled'
                    )
                ),
            payment_mode TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            approved_at TEXT,
            fulfilled_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (device_id) REFERENCES devices(id)
        );

        CREATE TABLE IF NOT EXISTS admin_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_telegram_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            target_user_id INTEGER,
            target_device_id INTEGER,
            metadata_json TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (target_user_id) REFERENCES users(id),
            FOREIGN KEY (target_device_id) REFERENCES devices(id)
        );

        CREATE TABLE IF NOT EXISTS device_traffic_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            server_id INTEGER NOT NULL,
            peer_public_key TEXT NOT NULL,
            rx_bytes INTEGER NOT NULL CHECK (rx_bytes >= 0),
            tx_bytes INTEGER NOT NULL CHECK (tx_bytes >= 0),
            source TEXT NOT NULL,
            collected_at TEXT NOT NULL,
            FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE,
            FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS message_templates (
            key TEXT PRIMARY KEY,
            text TEXT NOT NULL,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS email_recovery_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            email TEXT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            purpose TEXT NOT NULL
                CHECK (purpose IN ('verify_email', 'recover_config')),
            device_id INTEGER,
            expires_at TEXT NOT NULL,
            used_at TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS api_tokens (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            owner_user_id INTEGER,
            owner_label TEXT NOT NULL,
            integration_kind TEXT NOT NULL DEFAULT 'operator_automation',
            purpose TEXT NOT NULL DEFAULT 'legacy-api-access',
            token_hash TEXT NOT NULL UNIQUE,
            scopes_json TEXT NOT NULL,
            expires_at TEXT,
            revoked_at TEXT,
            revoke_reason TEXT,
            last_used_at TEXT,
            rotated_from_token_id TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE SET NULL,
            FOREIGN KEY (rotated_from_token_id) REFERENCES api_tokens(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS ignored_remote_peers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            server_id INTEGER NOT NULL,
            peer_public_key TEXT NOT NULL,
            allowed_ips TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE,
            UNIQUE (server_id, peer_public_key)
        );

        CREATE INDEX IF NOT EXISTS idx_devices_user_status
            ON devices(user_id, status);
        CREATE INDEX IF NOT EXISTS idx_devices_server_status
            ON devices(server_id, status);
        CREATE INDEX IF NOT EXISTS idx_device_passports_owner
            ON device_passports(owner_user_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_device_enrollment_tickets_user
            ON device_enrollment_tickets(user_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_device_enrollment_tickets_expiry
            ON device_enrollment_tickets(expires_at, claimed_at, revoked_at);
        CREATE INDEX IF NOT EXISTS idx_device_lifecycle_ticket
            ON device_lifecycle_events(ticket_id, occurred_at, id);
        CREATE INDEX IF NOT EXISTS idx_device_lifecycle_passport
            ON device_lifecycle_events(passport_device_id, occurred_at, id);
        CREATE INDEX IF NOT EXISTS idx_orders_user_status
            ON orders(user_id, status);
        CREATE INDEX IF NOT EXISTS idx_server_health_latest
            ON server_health_checks(server_id, checked_at DESC, id DESC);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_reserved_ip_unique
            ON devices(server_id, vpn_ip)
            WHERE status IN ('pending', 'active', 'disabled');
        CREATE INDEX IF NOT EXISTS idx_device_traffic_device_collected
            ON device_traffic_snapshots(device_id, collected_at DESC);
        CREATE INDEX IF NOT EXISTS idx_device_traffic_server_collected
            ON device_traffic_snapshots(server_id, collected_at DESC);
        CREATE INDEX IF NOT EXISTS idx_email_recovery_tokens_user
            ON email_recovery_tokens(user_id, purpose, expires_at);
        CREATE INDEX IF NOT EXISTS idx_api_tokens_owner
            ON api_tokens(owner_user_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_ignored_remote_peers_server
            ON ignored_remote_peers(server_id, created_at DESC);
        """
    )
    _ensure_column(conn, "users", "email", "TEXT")
    _ensure_column(conn, "users", "email_verified_at", "TEXT")
    _ensure_column(
        conn,
        "users",
        "locale",
        "TEXT NOT NULL DEFAULT 'ru' CHECK (locale IN ('ru', 'en'))",
    )
    _migrate_users_operator_identity(conn)
    conn.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_users_operator_label_unique
            ON users(lower(trim(operator_label)))
            WHERE operator_label IS NOT NULL
        """
    )
    _ensure_column(
        conn,
        "orders",
        "requested_config_version",
        "TEXT NOT NULL DEFAULT 'amneziawg_v2'",
    )
    _ensure_column(conn, "plans", "max_devices", "INTEGER CHECK (max_devices > 0)")
    _ensure_column(conn, "devices", "first_connected_at", "TEXT")
    _ensure_column(conn, "devices", "last_connected_at", "TEXT")
    _ensure_column(conn, "api_tokens", "revoke_reason", "TEXT")
    _ensure_column(conn, "api_tokens", "rotated_from_token_id", "TEXT")
    _ensure_column(
        conn,
        "api_tokens",
        "integration_kind",
        "TEXT NOT NULL DEFAULT 'operator_automation'",
    )
    _ensure_column(
        conn,
        "api_tokens",
        "purpose",
        "TEXT NOT NULL DEFAULT 'legacy-api-access'",
    )
    _migrate_devices_disabled_status(conn)
    _ensure_column(
        conn,
        "devices",
        "config_material_status",
        "TEXT NOT NULL DEFAULT 'available' CHECK (config_material_status IN ('available', 'external_only'))",
    )
    _ensure_column(
        conn,
        "devices",
        "assignment_mode",
        "TEXT NOT NULL DEFAULT 'dedicated_device' CHECK (assignment_mode IN ('dedicated_device', 'owner_shared'))",
    )
    _ensure_column(conn, "device_passports", "revoked_at", "TEXT")
    _ensure_column(conn, "device_passports", "revoke_reason", "TEXT")
    conn.commit()


def _ensure_column(
    conn: sqlite3.Connection,
    table_name: str,
    column_name: str,
    column_definition: str,
) -> None:
    columns = {
        row["name"] if isinstance(row, sqlite3.Row) else row[1]
        for row in conn.execute(f"PRAGMA table_info({table_name})")
    }
    if column_name not in columns:
        conn.execute(
            f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_definition}"
        )


def _migrate_users_operator_identity(conn: sqlite3.Connection) -> None:
    columns = {
        row["name"] if isinstance(row, sqlite3.Row) else row[1]: row
        for row in conn.execute("PRAGMA table_info(users)")
    }
    telegram_column = columns.get("telegram_id")
    telegram_not_null = bool(
        telegram_column["notnull"]
        if isinstance(telegram_column, sqlite3.Row)
        else telegram_column[3]
    )
    if "operator_label" in columns and not telegram_not_null:
        return

    foreign_keys_row = conn.execute("PRAGMA foreign_keys").fetchone()
    foreign_keys_enabled = int(foreign_keys_row[0])
    if conn.in_transaction:
        conn.commit()

    try:
        conn.execute("PRAGMA foreign_keys = OFF")
        conn.executescript(
            """
            BEGIN;
            CREATE TABLE users_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                telegram_id INTEGER UNIQUE,
                operator_label TEXT,
                username TEXT,
                first_name TEXT,
                last_name TEXT,
                status TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'blocked', 'deleted')),
                locale TEXT NOT NULL DEFAULT 'ru'
                    CHECK (locale IN ('ru', 'en')),
                is_admin INTEGER NOT NULL DEFAULT 0
                    CHECK (is_admin IN (0, 1)),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                email TEXT,
                email_verified_at TEXT,
                CHECK (telegram_id IS NOT NULL OR length(trim(operator_label)) > 0)
            );

            INSERT INTO users_new (
                id,
                telegram_id,
                operator_label,
                username,
                first_name,
                last_name,
                status,
                locale,
                is_admin,
                created_at,
                updated_at,
                email,
                email_verified_at
            )
            SELECT
                id,
                telegram_id,
                NULL,
                username,
                first_name,
                last_name,
                status,
                locale,
                is_admin,
                created_at,
                updated_at,
                email,
                email_verified_at
            FROM users;

            DROP TABLE users;
            ALTER TABLE users_new RENAME TO users;
            """
        )
        violations = conn.execute("PRAGMA foreign_key_check").fetchall()
        if violations:
            raise sqlite3.IntegrityError(
                f"foreign key violations after users migration: {violations!r}"
            )
        conn.commit()
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise
    finally:
        conn.execute(f"PRAGMA foreign_keys = {foreign_keys_enabled}")


def _migrate_devices_disabled_status(conn: sqlite3.Connection) -> None:
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'devices'"
    ).fetchone()
    table_sql = str(row["sql"] if isinstance(row, sqlite3.Row) else row[0])

    conn.execute("DROP INDEX IF EXISTS idx_devices_reserved_ip_unique")
    if "'disabled'" not in table_sql:
        conn.execute("PRAGMA foreign_keys=OFF")
        conn.executescript(
            """
            CREATE TABLE devices_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                server_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                activated_at TEXT,
                expires_at TEXT,
                duration_days INTEGER NOT NULL CHECK (duration_days > 0),
                status TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('pending', 'active', 'disabled', 'expired', 'revoked', 'failed')),
                vpn_ip TEXT NOT NULL,
                peer_public_key TEXT NOT NULL,
                peer_private_key_encrypted TEXT NOT NULL,
                preshared_key_encrypted TEXT NOT NULL,
                config_version TEXT NOT NULL,
                last_config_sent_at TEXT,
                first_connected_at TEXT,
                last_connected_at TEXT,
                revoked_at TEXT,
                revoke_reason TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (server_id) REFERENCES servers(id),
                UNIQUE (server_id, peer_public_key)
            );

            INSERT INTO devices_new (
                id,
                user_id,
                server_id,
                name,
                created_at,
                activated_at,
                expires_at,
                duration_days,
                status,
                vpn_ip,
                peer_public_key,
                peer_private_key_encrypted,
                preshared_key_encrypted,
                config_version,
                last_config_sent_at,
                first_connected_at,
                last_connected_at,
                revoked_at,
                revoke_reason
            )
            SELECT
                id,
                user_id,
                server_id,
                name,
                created_at,
                activated_at,
                expires_at,
                duration_days,
                status,
                vpn_ip,
                peer_public_key,
                peer_private_key_encrypted,
                preshared_key_encrypted,
                config_version,
                last_config_sent_at,
                first_connected_at,
                last_connected_at,
                revoked_at,
                revoke_reason
            FROM devices;

            DROP TABLE devices;
            ALTER TABLE devices_new RENAME TO devices;
            """
        )
        conn.execute("PRAGMA foreign_keys=ON")

    conn.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_reserved_ip_unique
            ON devices(server_id, vpn_ip)
            WHERE status IN ('pending', 'active', 'disabled')
        """
    )
