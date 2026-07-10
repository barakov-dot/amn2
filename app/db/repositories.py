import ipaddress
import json
import re
import sqlite3
from contextlib import contextmanager
from collections.abc import Iterator
from typing import Any

DEFAULT_PLAN_DAYS = (3, 7, 10, 14, 30, 60, 90, 180)
USER_STATUSES = {"active", "blocked", "deleted"}
USER_LOCALES = {"ru", "en"}
SERVER_STATUSES = {"active", "degraded", "disabled"}
DEVICE_STATUSES = {"pending", "active", "disabled", "expired", "revoked", "failed"}


class Repository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        self._transaction_depth = 0

    @contextmanager
    def transaction(self) -> Iterator[None]:
        is_outermost = self._transaction_depth == 0
        if is_outermost:
            self._conn.execute("BEGIN")

        self._transaction_depth += 1
        try:
            yield
        except Exception:
            self._transaction_depth -= 1
            if is_outermost:
                self._conn.rollback()
            raise
        else:
            self._transaction_depth -= 1
            if is_outermost:
                self._conn.commit()

    def upsert_user(
        self,
        *,
        telegram_id: int,
        username: str | None,
        first_name: str | None,
        last_name: str | None,
    ) -> int:
        self._conn.execute(
            """
            INSERT INTO users (telegram_id, username, first_name, last_name)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(telegram_id) DO UPDATE SET
                username = excluded.username,
                first_name = excluded.first_name,
                last_name = excluded.last_name,
                updated_at = CURRENT_TIMESTAMP
            """,
            (telegram_id, username, first_name, last_name),
        )
        self._commit()
        row = self._conn.execute(
            "SELECT id FROM users WHERE telegram_id = ?",
            (telegram_id,),
        ).fetchone()
        return int(row["id"])

    def get_user_by_telegram_id(self, telegram_id: int) -> sqlite3.Row | None:
        return self._conn.execute(
            "SELECT * FROM users WHERE telegram_id = ?",
            (telegram_id,),
        ).fetchone()

    def get_user(self, user_id: int) -> sqlite3.Row:
        return self._fetch_one("SELECT * FROM users WHERE id = ?", (user_id,))

    def get_user_locale(self, telegram_id: int) -> str:
        user = self.get_user_by_telegram_id(telegram_id)
        if user is None:
            return "ru"
        return str(user["locale"])

    def set_user_locale(self, *, telegram_id: int, locale: str) -> bool:
        _validate_user_locale(locale)
        cursor = self._conn.execute(
            """
            UPDATE users
            SET locale = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE telegram_id = ?
            """,
            (locale, telegram_id),
        )
        self._commit()
        return cursor.rowcount > 0

    def update_user_email(self, user_id: int, email: str | None) -> None:
        user = self.get_user(user_id)
        email_verified_at = user["email_verified_at"]
        if user["email"] != email:
            email_verified_at = None

        self._conn.execute(
            """
            UPDATE users
            SET email = ?,
                email_verified_at = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (email, email_verified_at, user_id),
        )
        self._commit()

    def create_user_for_admin(
        self,
        *,
        telegram_id: int,
        username: str | None,
        first_name: str | None,
        last_name: str | None,
        email: str | None,
        status: str,
        is_admin: bool,
    ) -> int:
        _validate_user_status(status)
        if self.get_user_by_telegram_id(telegram_id) is not None:
            raise ValueError("telegram_id already exists")

        cursor = self._conn.execute(
            """
            INSERT INTO users (
                telegram_id,
                username,
                first_name,
                last_name,
                email,
                status,
                is_admin
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                telegram_id,
                username,
                first_name,
                last_name,
                email,
                status,
                int(is_admin),
            ),
        )
        self._commit()
        return int(cursor.lastrowid)

    def update_user_for_admin(
        self,
        *,
        user_id: int,
        telegram_id: int,
        username: str | None,
        first_name: str | None,
        last_name: str | None,
        email: str | None,
        status: str,
        is_admin: bool,
    ) -> None:
        _validate_user_status(status)
        user = self.get_user(user_id)
        email_verified_at = user["email_verified_at"]
        if user["email"] != email:
            email_verified_at = None

        self._conn.execute(
            """
            UPDATE users
            SET telegram_id = ?,
                username = ?,
                first_name = ?,
                last_name = ?,
                email = ?,
                email_verified_at = ?,
                status = ?,
                is_admin = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (
                telegram_id,
                username,
                first_name,
                last_name,
                email,
                email_verified_at,
                status,
                int(is_admin),
                user_id,
            ),
        )
        self._commit()

    def set_user_status_for_admin(self, user_id: int, status: str) -> None:
        _validate_user_status(status)
        self._conn.execute(
            """
            UPDATE users
            SET status = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (status, user_id),
        )
        self._commit()

    def mark_user_email_verified(self, user_id: int, verified_at: str) -> None:
        self._conn.execute(
            """
            UPDATE users
            SET email_verified_at = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (verified_at, user_id),
        )
        self._commit()

    def set_user_admin(
        self,
        *,
        telegram_id: int,
        is_admin: bool,
        granted_by_admin_telegram_id: int,
    ) -> bool:
        user = self.get_user_by_telegram_id(telegram_id)
        if user is None:
            return False
        self._conn.execute(
            """
            UPDATE users
            SET is_admin = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE telegram_id = ?
            """,
            (int(is_admin), telegram_id),
        )
        self.record_admin_action(
            admin_telegram_id=granted_by_admin_telegram_id,
            action="grant_admin" if is_admin else "revoke_admin",
            target_user_id=int(user["id"]),
            metadata={"target_telegram_id": telegram_id},
        )
        self._commit()
        return True

    def ensure_default_server(self, *, name: str, network_cidr: str) -> int:
        self._conn.execute(
            """
            INSERT INTO servers (
                name,
                host,
                ssh_port,
                endpoint_host,
                vpn_port,
                vpn_network_cidr,
                server_address,
                server_public_key,
                runtime,
                firewall,
                max_devices
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(name) DO NOTHING
            """,
            (
                name,
                "local",
                22,
                "127.0.0.1",
                30001,
                network_cidr,
                _first_host_address(network_cidr),
                "local-server-public-key",
                "host_systemd",
                "ufw",
                254,
            ),
        )
        self._commit()
        row = self._conn.execute(
            "SELECT id FROM servers WHERE name = ?",
            (name,),
        ).fetchone()
        return int(row["id"])

    def upsert_server_config(
        self,
        *,
        name: str,
        host: str,
        ssh_port: int,
        endpoint_host: str,
        vpn_port: int,
        vpn_network_cidr: str,
        server_address: str,
        server_public_key: str,
        runtime: str,
        firewall: str,
        max_devices: int,
    ) -> int:
        normalized_server_address = _host_address(server_address)
        self._conn.execute(
            """
            INSERT INTO servers (
                name,
                host,
                ssh_port,
                endpoint_host,
                vpn_port,
                vpn_network_cidr,
                server_address,
                server_public_key,
                runtime,
                firewall,
                max_devices
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
                host = excluded.host,
                ssh_port = excluded.ssh_port,
                endpoint_host = excluded.endpoint_host,
                vpn_port = excluded.vpn_port,
                vpn_network_cidr = excluded.vpn_network_cidr,
                server_address = excluded.server_address,
                server_public_key = excluded.server_public_key,
                runtime = excluded.runtime,
                firewall = excluded.firewall,
                max_devices = excluded.max_devices,
                updated_at = CURRENT_TIMESTAMP
            """,
            (
                name,
                host,
                ssh_port,
                endpoint_host,
                vpn_port,
                vpn_network_cidr,
                normalized_server_address,
                server_public_key,
                runtime,
                firewall,
                max_devices,
            ),
        )
        self._commit()
        row = self._conn.execute(
            "SELECT id FROM servers WHERE name = ?",
            (name,),
        ).fetchone()
        return int(row["id"])

    def create_server_for_admin(
        self,
        *,
        name: str,
        host: str,
        ssh_port: int,
        endpoint_host: str,
        vpn_port: int,
        vpn_network_cidr: str,
        server_address: str,
        server_public_key: str,
        runtime: str,
        firewall: str,
        status: str,
        max_devices: int,
    ) -> int:
        _validate_server_status(status)
        _validate_server_fields(
            name=name,
            host=host,
            ssh_port=ssh_port,
            endpoint_host=endpoint_host,
            vpn_port=vpn_port,
            vpn_network_cidr=vpn_network_cidr,
            server_address=server_address,
            runtime=runtime,
            firewall=firewall,
            max_devices=max_devices,
        )
        cursor = self._conn.execute(
            """
            INSERT INTO servers (
                name,
                host,
                ssh_port,
                endpoint_host,
                vpn_port,
                vpn_network_cidr,
                server_address,
                server_public_key,
                runtime,
                firewall,
                status,
                max_devices
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                name,
                host,
                ssh_port,
                endpoint_host,
                vpn_port,
                vpn_network_cidr,
                _host_address(server_address),
                server_public_key,
                runtime,
                firewall,
                status,
                max_devices,
            ),
        )
        self._commit()
        return int(cursor.lastrowid)

    def update_server_for_admin(
        self,
        *,
        server_id: int,
        name: str,
        host: str,
        ssh_port: int,
        endpoint_host: str,
        vpn_port: int,
        vpn_network_cidr: str,
        server_address: str,
        server_public_key: str,
        runtime: str,
        firewall: str,
        status: str,
        max_devices: int,
    ) -> None:
        self.get_server(server_id)
        _validate_server_status(status)
        _validate_server_fields(
            name=name,
            host=host,
            ssh_port=ssh_port,
            endpoint_host=endpoint_host,
            vpn_port=vpn_port,
            vpn_network_cidr=vpn_network_cidr,
            server_address=server_address,
            runtime=runtime,
            firewall=firewall,
            max_devices=max_devices,
        )
        self._conn.execute(
            """
            UPDATE servers
            SET name = ?,
                host = ?,
                ssh_port = ?,
                endpoint_host = ?,
                vpn_port = ?,
                vpn_network_cidr = ?,
                server_address = ?,
                server_public_key = ?,
                runtime = ?,
                firewall = ?,
                status = ?,
                max_devices = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (
                name,
                host,
                ssh_port,
                endpoint_host,
                vpn_port,
                vpn_network_cidr,
                _host_address(server_address),
                server_public_key,
                runtime,
                firewall,
                status,
                max_devices,
                server_id,
            ),
        )
        self._commit()

    def set_server_status_for_admin(self, server_id: int, status: str) -> None:
        self.get_server(server_id)
        _validate_server_status(status)
        self._conn.execute(
            """
            UPDATE servers
            SET status = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (status, server_id),
        )
        self._commit()

    def seed_default_plans(self) -> None:
        for duration_days in DEFAULT_PLAN_DAYS:
            self.upsert_plan(
                plan_id=f"days_{duration_days}",
                name=f"{duration_days} days",
                duration_days=duration_days,
                price=0,
                currency="RUB",
                is_free=True,
                is_active=True,
            )

    def upsert_plan(
        self,
        *,
        plan_id: str,
        name: str,
        duration_days: int,
        price: int = 0,
        currency: str = "RUB",
        is_free: bool = True,
        is_active: bool = True,
    ) -> None:
        self._conn.execute(
            """
            INSERT INTO plans (
                id,
                name,
                duration_days,
                price,
                currency,
                is_free,
                is_active
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                name = excluded.name,
                duration_days = excluded.duration_days,
                price = excluded.price,
                currency = excluded.currency,
                is_free = excluded.is_free,
                is_active = excluded.is_active,
                updated_at = CURRENT_TIMESTAMP
            """,
            (
                plan_id,
                name,
                duration_days,
                price,
                currency,
                int(is_free),
                int(is_active),
            ),
        )
        self._commit()

    def get_plan(self, plan_id: str) -> sqlite3.Row:
        return self._fetch_one("SELECT * FROM plans WHERE id = ?", (plan_id,))

    def list_active_plans(self) -> list[sqlite3.Row]:
        return self._conn.execute(
            """
            SELECT *
            FROM plans
            WHERE is_active = 1
            ORDER BY duration_days ASC
            """
        ).fetchall()

    def create_order(
        self,
        *,
        user_id: int,
        plan_id: str | None,
        payment_mode: str,
        requested_config_version: str = "amneziawg_v2",
    ) -> int:
        cursor = self._conn.execute(
            """
            INSERT INTO orders (
                user_id,
                plan_id,
                payment_mode,
                requested_config_version
            )
            VALUES (?, ?, ?, ?)
            """,
            (user_id, plan_id, payment_mode, requested_config_version),
        )
        self._commit()
        return int(cursor.lastrowid)

    def get_order(self, order_id: int) -> sqlite3.Row:
        return self._fetch_one("SELECT * FROM orders WHERE id = ?", (order_id,))

    def create_device(
        self,
        *,
        user_id: int,
        server_id: int,
        name: str,
        duration_days: int,
        vpn_ip: str,
        peer_public_key: str,
        peer_private_key_encrypted: str,
        preshared_key_encrypted: str,
        config_version: str,
        config_material_status: str = "available",
    ) -> int:
        cursor = self._conn.execute(
            """
            INSERT INTO devices (
                user_id,
                server_id,
                name,
                activated_at,
                expires_at,
                duration_days,
                vpn_ip,
                peer_public_key,
                peer_private_key_encrypted,
                preshared_key_encrypted,
                config_version,
                config_material_status
            )
            VALUES (
                ?,
                ?,
                ?,
                CURRENT_TIMESTAMP,
                datetime(CURRENT_TIMESTAMP, ?),
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?
            )
            """,
            (
                user_id,
                server_id,
                name,
                f"+{duration_days} days",
                duration_days,
                vpn_ip,
                peer_public_key,
                peer_private_key_encrypted,
                preshared_key_encrypted,
                config_version,
                config_material_status,
            ),
        )
        self._commit()
        return int(cursor.lastrowid)

    def create_external_device(
        self,
        *,
        user_id: int,
        server_id: int,
        name: str,
        duration_days: int,
        vpn_ip: str,
        peer_public_key: str,
        config_version: str,
        status: str = "active",
        expires_at: str | None = None,
        revoked_at: str | None = None,
        revoke_reason: str | None = None,
    ) -> int:
        if status not in DEVICE_STATUSES:
            raise ValueError(f"Unsupported device status: {status}")
        if duration_days <= 0:
            raise ValueError("duration_days must be positive")
        cursor = self._conn.execute(
            """
            INSERT INTO devices (
                user_id,
                server_id,
                name,
                activated_at,
                expires_at,
                duration_days,
                status,
                vpn_ip,
                peer_public_key,
                peer_private_key_encrypted,
                preshared_key_encrypted,
                config_version,
                config_material_status,
                revoked_at,
                revoke_reason
            )
            VALUES (
                ?,
                ?,
                ?,
                CURRENT_TIMESTAMP,
                COALESCE(?, datetime(CURRENT_TIMESTAMP, ?)),
                ?,
                ?,
                ?,
                ?,
                'external-only-client-private-key-unavailable',
                'external-only-preshared-key-unavailable',
                ?,
                'external_only',
                ?,
                ?
            )
            """,
            (
                user_id,
                server_id,
                name,
                expires_at,
                f"+{duration_days} days",
                duration_days,
                status,
                vpn_ip,
                peer_public_key,
                config_version,
                revoked_at,
                revoke_reason,
            ),
        )
        self._commit()
        return int(cursor.lastrowid)

    def next_device_sequence(self, prefix: str, *, minimum_sequence: int = 0) -> int:
        clean_prefix = prefix.strip()
        if not clean_prefix:
            raise ValueError("prefix must be non-blank")
        max_sequence = max(0, int(minimum_sequence))
        pattern = re.compile(rf"^{re.escape(clean_prefix)}-(\d+)$")
        rows = self._conn.execute(
            """
            SELECT name
            FROM devices
            WHERE name LIKE ?
            """,
            (f"{clean_prefix}-%",),
        ).fetchall()
        for row in rows:
            match = pattern.fullmatch(str(row["name"]))
            if match is not None:
                max_sequence = max(max_sequence, int(match.group(1)))
        return max_sequence + 1

    def get_device(self, device_id: int) -> sqlite3.Row:
        return self._fetch_one("SELECT * FROM devices WHERE id = ?", (device_id,))

    def get_user_device(self, *, user_id: int, device_id: int) -> sqlite3.Row | None:
        return self._conn.execute(
            """
            SELECT *
            FROM devices
            WHERE id = ?
              AND user_id = ?
            """,
            (device_id, user_id),
        ).fetchone()

    def get_user_device_for_admin(
        self,
        *,
        user_id: int,
        device_id: int,
    ) -> sqlite3.Row | None:
        return self._conn.execute(
            """
            SELECT
                devices.*,
                servers.name AS server_name
            FROM devices
            JOIN servers ON servers.id = devices.server_id
            WHERE devices.id = ?
              AND devices.user_id = ?
            """,
            (device_id, user_id),
        ).fetchone()

    def list_user_devices(
        self,
        user_id: int,
        *,
        statuses: tuple[str, ...] = ("active",),
        limit: int = 20,
    ) -> list[sqlite3.Row]:
        if not statuses:
            return []
        placeholders = ", ".join("?" for _ in statuses)
        return self._conn.execute(
            f"""
            SELECT *
            FROM devices
            WHERE user_id = ?
              AND status IN ({placeholders})
            ORDER BY id DESC
            LIMIT ?
            """,
            (user_id, *statuses, limit),
        ).fetchall()

    def revoke_device(
        self,
        device_id: int,
        *,
        reason: str,
        revoked_at: str,
    ) -> bool:
        cursor = self._conn.execute(
            """
            UPDATE devices
            SET status = 'revoked',
                revoked_at = ?,
                revoke_reason = ?
            WHERE id = ?
              AND status IN ('pending', 'active')
            """,
            (revoked_at, reason, device_id),
        )
        self._commit()
        return cursor.rowcount > 0

    def revoke_user_devices(
        self,
        user_id: int,
        *,
        reason: str,
        revoked_at: str,
    ) -> int:
        cursor = self._conn.execute(
            """
            UPDATE devices
            SET status = 'revoked',
                revoked_at = ?,
                revoke_reason = ?
            WHERE user_id = ?
              AND status IN ('pending', 'active')
            """,
            (revoked_at, reason, user_id),
        )
        self._commit()
        return int(cursor.rowcount)

    def disable_user_devices(
        self,
        user_id: int,
        *,
        reason: str,
        disabled_at: str,
    ) -> int:
        cursor = self._conn.execute(
            """
            UPDATE devices
            SET status = 'disabled',
                revoked_at = ?,
                revoke_reason = ?
            WHERE user_id = ?
              AND status IN ('pending', 'active')
            """,
            (disabled_at, reason, user_id),
        )
        self._commit()
        return int(cursor.rowcount)

    def enable_user_devices(self, user_id: int) -> int:
        cursor = self._conn.execute(
            """
            UPDATE devices
            SET status = 'active',
                revoked_at = NULL,
                revoke_reason = NULL,
                activated_at = COALESCE(activated_at, CURRENT_TIMESTAMP)
            WHERE user_id = ?
              AND status = 'disabled'
            """,
            (user_id,),
        )
        self._commit()
        return int(cursor.rowcount)

    def get_device_by_server_peer_public_key(
        self,
        server_id: int,
        peer_public_key: str,
    ) -> sqlite3.Row | None:
        return self._conn.execute(
            """
            SELECT *
            FROM devices
            WHERE server_id = ?
              AND peer_public_key = ?
            """,
            (server_id, peer_public_key),
        ).fetchone()

    def count_active_devices(self, user_id: int) -> int:
        row = self._conn.execute(
            """
            SELECT COUNT(*) AS device_count
            FROM devices
            WHERE user_id = ?
              AND status = 'active'
            """,
            (user_id,),
        ).fetchone()
        return int(row["device_count"])

    def list_allocated_ips(self, server_id: int) -> list[str]:
        rows = self._conn.execute(
            """
            SELECT vpn_ip
            FROM devices
            WHERE server_id = ?
              AND status IN ('pending', 'active', 'disabled')
            ORDER BY id
            """,
            (server_id,),
        ).fetchall()
        return [str(row["vpn_ip"]) for row in rows]

    def get_server(self, server_id: int) -> sqlite3.Row:
        return self._fetch_one("SELECT * FROM servers WHERE id = ?", (server_id,))

    def record_server_health(
        self,
        *,
        server_id: int,
        status: str,
        latency_ms: int | None,
        ssh_ok: bool,
        awg_ok: bool,
        udp_port_ok: bool,
        error: str | None,
    ) -> int:
        cursor = self._conn.execute(
            """
            INSERT INTO server_health_checks (
                server_id,
                status,
                latency_ms,
                ssh_ok,
                awg_ok,
                udp_port_ok,
                error
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                server_id,
                status,
                latency_ms,
                int(ssh_ok),
                int(awg_ok),
                int(udp_port_ok),
                error,
            ),
        )
        self._commit()
        return int(cursor.lastrowid)

    def get_latest_server_health(self, server_id: int) -> sqlite3.Row | None:
        return self._conn.execute(
            """
            SELECT *
            FROM server_health_checks
            WHERE server_id = ?
            ORDER BY checked_at DESC, id DESC
            LIMIT 1
            """,
            (server_id,),
        ).fetchone()

    def mark_order_fulfilled(self, order_id: int, device_id: int) -> None:
        order = self.get_order(order_id)
        device = self.get_device(device_id)
        if order["user_id"] != device["user_id"]:
            raise ValueError("Order and device must belong to the same user")

        self._conn.execute(
            """
            UPDATE orders
            SET device_id = ?,
                status = 'fulfilled',
                fulfilled_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (device_id, order_id),
        )
        self._commit()

    def record_admin_action(
        self,
        *,
        admin_telegram_id: int,
        action: str,
        target_user_id: int | None = None,
        target_device_id: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> int:
        cursor = self._conn.execute(
            """
            INSERT INTO admin_actions (
                admin_telegram_id,
                action,
                target_user_id,
                target_device_id,
                metadata_json
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                admin_telegram_id,
                action,
                target_user_id,
                target_device_id,
                json.dumps(metadata, sort_keys=True) if metadata is not None else None,
            ),
        )
        self._commit()
        return int(cursor.lastrowid)

    def list_admin_actions_for_target_user(self, target_user_id: int):
        return self._conn.execute(
            """
            SELECT *
            FROM admin_actions
            WHERE target_user_id = ?
            ORDER BY id DESC
            """,
            (target_user_id,),
        ).fetchall()

    def list_admin_actions_for_server(
        self,
        server_id: int,
        *,
        limit: int = 20,
    ) -> list[sqlite3.Row]:
        return self._conn.execute(
            """
            SELECT *
            FROM admin_actions
            WHERE metadata_json LIKE ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (f'%"server_id": {server_id}%', limit),
        ).fetchall()

    def get_user_for_admin(self, user_id: int) -> sqlite3.Row:
        return self._fetch_one(
            """
            SELECT
                users.*,
                COUNT(devices.id) AS total_device_count,
                COALESCE(
                    SUM(CASE WHEN devices.status = 'active' THEN 1 ELSE 0 END),
                    0
                ) AS active_device_count
            FROM users
            LEFT JOIN devices ON devices.user_id = users.id
            WHERE users.id = ?
            GROUP BY users.id
            """,
            (user_id,),
        )

    def list_users_for_admin(self, *, limit: int = 50) -> list[sqlite3.Row]:
        return self._conn.execute(
            """
            SELECT
                users.*,
                COUNT(devices.id) AS total_device_count,
                COALESCE(
                    SUM(CASE WHEN devices.status = 'active' THEN 1 ELSE 0 END),
                    0
                ) AS active_device_count
            FROM users
            LEFT JOIN devices ON devices.user_id = users.id
            GROUP BY users.id
            ORDER BY users.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    def list_user_devices_for_admin(
        self,
        user_id: int,
        *,
        limit: int = 50,
    ) -> list[sqlite3.Row]:
        return self._conn.execute(
            """
            SELECT
                devices.id,
                devices.name,
                devices.status,
                devices.expires_at,
                devices.vpn_ip,
                devices.config_material_status,
                servers.name AS server_name
            FROM devices
            JOIN servers ON servers.id = devices.server_id
            WHERE devices.user_id = ?
            ORDER BY devices.id DESC
            LIMIT ?
            """,
            (user_id, limit),
        ).fetchall()

    def list_user_devices_for_vpn_removal(self, user_id: int) -> list[sqlite3.Row]:
        return self._conn.execute(
            """
            SELECT
                devices.id,
                devices.server_id,
                devices.name,
                devices.status,
                devices.vpn_ip,
                devices.peer_public_key,
                servers.name AS server_name
            FROM devices
            JOIN servers ON servers.id = devices.server_id
            WHERE devices.user_id = ?
              AND devices.status IN ('pending', 'active')
            ORDER BY devices.id ASC
            """,
            (user_id,),
        ).fetchall()

    def list_user_devices_for_vpn_enable(self, user_id: int) -> list[sqlite3.Row]:
        return self._conn.execute(
            """
            SELECT
                devices.id,
                devices.server_id,
                devices.name,
                devices.status,
                devices.vpn_ip,
                devices.peer_public_key,
                devices.peer_private_key_encrypted,
                devices.preshared_key_encrypted,
                servers.name AS server_name
            FROM devices
            JOIN servers ON servers.id = devices.server_id
            WHERE devices.user_id = ?
              AND devices.status = 'disabled'
              AND devices.config_material_status = 'available'
            ORDER BY devices.id ASC
            """,
            (user_id,),
        ).fetchall()

    def hard_delete_user_for_admin(self, user_id: int) -> None:
        self.get_user(user_id)
        device_rows = self._conn.execute(
            "SELECT id FROM devices WHERE user_id = ?",
            (user_id,),
        ).fetchall()
        device_ids = [int(row["id"]) for row in device_rows]

        if device_ids:
            placeholders = ", ".join("?" for _ in device_ids)
            self._conn.execute(
                f"""
                DELETE FROM admin_actions
                WHERE target_user_id = ?
                   OR target_device_id IN ({placeholders})
                """,
                (user_id, *device_ids),
            )
            self._conn.execute(
                f"DELETE FROM device_traffic_snapshots WHERE device_id IN ({placeholders})",
                tuple(device_ids),
            )
            self._conn.execute(
                f"""
                DELETE FROM email_recovery_tokens
                WHERE user_id = ?
                   OR device_id IN ({placeholders})
                """,
                (user_id, *device_ids),
            )
            self._conn.execute(
                f"""
                DELETE FROM orders
                WHERE user_id = ?
                   OR device_id IN ({placeholders})
                """,
                (user_id, *device_ids),
            )
        else:
            self._conn.execute(
                "DELETE FROM admin_actions WHERE target_user_id = ?",
                (user_id,),
            )
            self._conn.execute(
                "DELETE FROM email_recovery_tokens WHERE user_id = ?",
                (user_id,),
            )
            self._conn.execute("DELETE FROM orders WHERE user_id = ?", (user_id,))

        self._conn.execute("DELETE FROM devices WHERE user_id = ?", (user_id,))
        self._conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        self._commit()

    def hard_delete_device_for_admin(self, *, user_id: int, device_id: int) -> None:
        device = self.get_user_device(user_id=user_id, device_id=device_id)
        if device is None:
            raise LookupError("record not found")

        self._conn.execute(
            "UPDATE admin_actions SET target_device_id = NULL WHERE target_device_id = ?",
            (device_id,),
        )
        self._conn.execute(
            "UPDATE orders SET device_id = NULL WHERE device_id = ?",
            (device_id,),
        )
        self._conn.execute(
            "DELETE FROM device_traffic_snapshots WHERE device_id = ?",
            (device_id,),
        )
        self._conn.execute(
            "DELETE FROM email_recovery_tokens WHERE device_id = ?",
            (device_id,),
        )
        self._conn.execute(
            "DELETE FROM devices WHERE id = ? AND user_id = ?",
            (device_id, user_id),
        )
        self._commit()

    def ignore_remote_peer(
        self,
        *,
        server_id: int,
        peer_public_key: str,
        allowed_ips: str,
    ) -> None:
        self.get_server(server_id)
        self._conn.execute(
            """
            INSERT INTO ignored_remote_peers (
                server_id,
                peer_public_key,
                allowed_ips
            )
            VALUES (?, ?, ?)
            ON CONFLICT(server_id, peer_public_key) DO UPDATE SET
                allowed_ips = excluded.allowed_ips
            """,
            (server_id, peer_public_key, allowed_ips),
        )
        self._commit()

    def list_ignored_remote_peer_keys(self, server_id: int) -> set[str]:
        rows = self._conn.execute(
            """
            SELECT peer_public_key
            FROM ignored_remote_peers
            WHERE server_id = ?
            """,
            (server_id,),
        ).fetchall()
        return {str(row["peer_public_key"]) for row in rows}

    def list_ignored_remote_peers(self, server_id: int) -> list[sqlite3.Row]:
        return self._conn.execute(
            """
            SELECT peer_public_key, allowed_ips, created_at
            FROM ignored_remote_peers
            WHERE server_id = ?
            ORDER BY created_at DESC, id DESC
            """,
            (server_id,),
        ).fetchall()

    def unignore_remote_peer(self, *, server_id: int, peer_public_key: str) -> bool:
        cursor = self._conn.execute(
            """
            DELETE FROM ignored_remote_peers
            WHERE server_id = ?
              AND peer_public_key = ?
            """,
            (server_id, peer_public_key),
        )
        self._commit()
        return cursor.rowcount > 0

    def list_user_orders_for_admin(
        self,
        user_id: int,
        *,
        limit: int = 50,
    ) -> list[sqlite3.Row]:
        return self._conn.execute(
            """
            SELECT
                orders.*,
                plans.name AS plan_name,
                devices.name AS device_name
            FROM orders
            LEFT JOIN plans ON plans.id = orders.plan_id
            LEFT JOIN devices ON devices.id = orders.device_id
            WHERE orders.user_id = ?
            ORDER BY orders.created_at DESC, orders.id DESC
            LIMIT ?
            """,
            (user_id, limit),
        ).fetchall()

    def list_servers_for_admin(self, *, limit: int = 100) -> list[sqlite3.Row]:
        return self._conn.execute(
            """
            SELECT
                servers.*,
                COUNT(devices.id) AS total_device_count,
                COALESCE(
                    SUM(CASE WHEN devices.status = 'active' THEN 1 ELSE 0 END),
                    0
                ) AS active_device_count,
                latest_health.status AS health_status,
                latest_health.latency_ms AS health_latency_ms,
                latest_health.checked_at AS health_checked_at,
                latest_health.error AS health_error
            FROM servers
            LEFT JOIN devices ON devices.server_id = servers.id
            LEFT JOIN server_health_checks AS latest_health
                ON latest_health.id = (
                    SELECT id
                    FROM server_health_checks
                    WHERE server_id = servers.id
                    ORDER BY checked_at DESC, id DESC
                    LIMIT 1
                )
            GROUP BY servers.id
            ORDER BY servers.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    def list_api_server_summaries(self, *, limit: int = 100) -> list[sqlite3.Row]:
        return self._conn.execute(
            """
            SELECT
                servers.name,
                servers.status,
                servers.runtime,
                COUNT(devices.id) AS total_device_count,
                COALESCE(
                    SUM(CASE WHEN devices.status = 'active' THEN 1 ELSE 0 END),
                    0
                ) AS active_device_count,
                latest_health.status AS health_status,
                latest_health.latency_ms AS health_latency_ms,
                latest_health.checked_at AS health_checked_at,
                latest_health.ssh_ok AS health_ssh_ok,
                latest_health.awg_ok AS health_awg_ok,
                latest_health.udp_port_ok AS health_udp_port_ok
            FROM servers
            LEFT JOIN devices ON devices.server_id = servers.id
            LEFT JOIN server_health_checks AS latest_health
                ON latest_health.id = (
                    SELECT id
                    FROM server_health_checks
                    WHERE server_id = servers.id
                    ORDER BY checked_at DESC, id DESC
                    LIMIT 1
                )
            GROUP BY servers.id
            ORDER BY servers.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    def get_api_server_summary(self, name: str) -> sqlite3.Row | None:
        return self._conn.execute(
            """
            SELECT
                servers.name,
                servers.status,
                servers.runtime,
                COUNT(devices.id) AS total_device_count,
                COALESCE(
                    SUM(CASE WHEN devices.status = 'active' THEN 1 ELSE 0 END),
                    0
                ) AS active_device_count,
                latest_health.status AS health_status,
                latest_health.latency_ms AS health_latency_ms,
                latest_health.checked_at AS health_checked_at,
                latest_health.ssh_ok AS health_ssh_ok,
                latest_health.awg_ok AS health_awg_ok,
                latest_health.udp_port_ok AS health_udp_port_ok
            FROM servers
            LEFT JOIN devices ON devices.server_id = servers.id
            LEFT JOIN server_health_checks AS latest_health
                ON latest_health.id = (
                    SELECT id
                    FROM server_health_checks
                    WHERE server_id = servers.id
                    ORDER BY checked_at DESC, id DESC
                    LIMIT 1
                )
            WHERE servers.name = ?
            GROUP BY servers.id
            """,
            (name,),
        ).fetchone()

    def get_api_metrics_summary(self) -> dict[str, int]:
        counts = self._conn.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM users) AS users_total,
                (SELECT COUNT(*) FROM users WHERE status = 'active') AS users_active,
                (SELECT COUNT(*) FROM users WHERE status = 'blocked') AS users_blocked,
                (SELECT COUNT(*) FROM users WHERE status = 'deleted') AS users_deleted,
                (SELECT COUNT(*) FROM servers) AS servers_total,
                (SELECT COUNT(*) FROM servers WHERE status = 'active') AS servers_active,
                (SELECT COUNT(*) FROM servers WHERE status = 'degraded') AS servers_degraded,
                (SELECT COUNT(*) FROM servers WHERE status = 'disabled') AS servers_disabled,
                (SELECT COUNT(*) FROM devices) AS devices_total,
                (SELECT COUNT(*) FROM devices WHERE status = 'active') AS devices_active,
                (SELECT COUNT(*) FROM devices WHERE status = 'disabled') AS devices_disabled,
                (SELECT COUNT(*) FROM devices WHERE status = 'revoked') AS devices_revoked
            """
        ).fetchone()
        traffic = self._conn.execute(
            """
            SELECT
                COALESCE(SUM(latest.rx_bytes), 0) AS traffic_rx_bytes,
                COALESCE(SUM(latest.tx_bytes), 0) AS traffic_tx_bytes
            FROM device_traffic_snapshots AS latest
            WHERE latest.id = (
                SELECT id
                FROM device_traffic_snapshots AS candidate
                WHERE candidate.device_id = latest.device_id
                ORDER BY candidate.collected_at DESC, candidate.id DESC
                LIMIT 1
            )
            """
        ).fetchone()

        return {
            "users_total": int(counts["users_total"]),
            "users_active": int(counts["users_active"]),
            "users_blocked": int(counts["users_blocked"]),
            "users_deleted": int(counts["users_deleted"]),
            "servers_total": int(counts["servers_total"]),
            "servers_active": int(counts["servers_active"]),
            "servers_degraded": int(counts["servers_degraded"]),
            "servers_disabled": int(counts["servers_disabled"]),
            "devices_total": int(counts["devices_total"]),
            "devices_active": int(counts["devices_active"]),
            "devices_disabled": int(counts["devices_disabled"]),
            "devices_revoked": int(counts["devices_revoked"]),
            "traffic_rx_bytes": int(traffic["traffic_rx_bytes"]),
            "traffic_tx_bytes": int(traffic["traffic_tx_bytes"]),
        }

    def get_operator_status_summary(
        self,
        *,
        now: str,
        rotation_notice_at: str,
    ) -> dict[str, int]:
        row = self._conn.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM users WHERE status = 'active') AS users_active,
                (SELECT COUNT(*) FROM users WHERE status = 'blocked') AS users_blocked,
                (SELECT COUNT(*) FROM servers WHERE status = 'active') AS servers_active,
                (SELECT COUNT(*) FROM servers WHERE status = 'degraded') AS servers_degraded,
                (SELECT COUNT(*) FROM devices WHERE status = 'active') AS devices_active,
                (SELECT COUNT(*) FROM devices WHERE status = 'disabled') AS devices_disabled,
                (
                    SELECT COUNT(*) FROM orders
                    WHERE status IN ('manual_review', 'approved')
                      AND device_id IS NULL
                ) AS pending_orders,
                (
                    SELECT COUNT(*) FROM api_tokens
                    WHERE revoked_at IS NULL
                      AND (expires_at IS NULL OR julianday(expires_at) > julianday(?))
                ) AS credentials_active,
                (
                    SELECT COUNT(*) FROM api_tokens
                    WHERE revoked_at IS NULL
                      AND julianday(expires_at) > julianday(?)
                      AND julianday(expires_at) <= julianday(?)
                ) AS credentials_rotation_due,
                (
                    SELECT COUNT(*) FROM api_tokens
                    WHERE revoked_at IS NULL
                      AND expires_at IS NOT NULL
                      AND julianday(expires_at) <= julianday(?)
                ) AS credentials_expired,
                (
                    SELECT COUNT(*) FROM api_tokens
                    WHERE revoked_at IS NOT NULL
                ) AS credentials_revoked
            """,
            (rotation_notice_at, now, rotation_notice_at, now),
        ).fetchone()
        return {key: int(row[key]) for key in row.keys()}

    def get_api_users_summary(self) -> dict[str, int]:
        counts = self._conn.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM users) AS users_total,
                (SELECT COUNT(*) FROM users WHERE status = 'active') AS users_active,
                (SELECT COUNT(*) FROM users WHERE status = 'blocked') AS users_blocked,
                (SELECT COUNT(*) FROM users WHERE status = 'deleted') AS users_deleted,
                (SELECT COUNT(*) FROM users WHERE is_admin = 1) AS users_admins,
                (
                    SELECT COUNT(*)
                    FROM users
                    WHERE EXISTS (
                        SELECT 1
                        FROM devices
                        WHERE devices.user_id = users.id
                    )
                ) AS users_with_devices,
                (
                    SELECT COUNT(*)
                    FROM users
                    WHERE NOT EXISTS (
                        SELECT 1
                        FROM devices
                        WHERE devices.user_id = users.id
                    )
                ) AS users_without_devices,
                (SELECT COUNT(*) FROM orders) AS orders_total,
                (SELECT COUNT(*) FROM orders WHERE status = 'manual_review') AS orders_manual_review,
                (SELECT COUNT(*) FROM orders WHERE status = 'approved') AS orders_approved,
                (SELECT COUNT(*) FROM orders WHERE status = 'fulfilled') AS orders_fulfilled,
                (SELECT COUNT(*) FROM orders WHERE status = 'payment_pending') AS orders_payment_pending,
                (SELECT COUNT(*) FROM orders WHERE status = 'rejected') AS orders_rejected
            """
        ).fetchone()

        return {
            "users_total": int(counts["users_total"]),
            "users_active": int(counts["users_active"]),
            "users_blocked": int(counts["users_blocked"]),
            "users_deleted": int(counts["users_deleted"]),
            "users_admins": int(counts["users_admins"]),
            "users_with_devices": int(counts["users_with_devices"]),
            "users_without_devices": int(counts["users_without_devices"]),
            "orders_total": int(counts["orders_total"]),
            "orders_manual_review": int(counts["orders_manual_review"]),
            "orders_approved": int(counts["orders_approved"]),
            "orders_fulfilled": int(counts["orders_fulfilled"]),
            "orders_payment_pending": int(counts["orders_payment_pending"]),
            "orders_rejected": int(counts["orders_rejected"]),
        }

    def get_server_for_admin(self, server_id: int) -> sqlite3.Row:
        return self._fetch_one(
            """
            SELECT
                servers.*,
                COUNT(devices.id) AS total_device_count,
                COALESCE(
                    SUM(CASE WHEN devices.status = 'active' THEN 1 ELSE 0 END),
                    0
                ) AS active_device_count,
                latest_health.status AS health_status,
                latest_health.latency_ms AS health_latency_ms,
                latest_health.checked_at AS health_checked_at,
                latest_health.error AS health_error
            FROM servers
            LEFT JOIN devices ON devices.server_id = servers.id
            LEFT JOIN server_health_checks AS latest_health
                ON latest_health.id = (
                    SELECT id
                    FROM server_health_checks
                    WHERE server_id = servers.id
                    ORDER BY checked_at DESC, id DESC
                    LIMIT 1
                )
            WHERE servers.id = ?
            GROUP BY servers.id
            """,
            (server_id,),
        )

    def list_orders_for_admin(self, *, limit: int = 100) -> list[sqlite3.Row]:
        return self._conn.execute(
            """
            SELECT
                orders.*,
                users.telegram_id,
                users.username,
                users.first_name,
                users.last_name
            FROM orders
            JOIN users ON users.id = orders.user_id
            ORDER BY orders.created_at DESC, orders.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    def list_pending_orders(self, *, limit: int = 20) -> list[sqlite3.Row]:
        return self._conn.execute(
            """
            SELECT
                orders.*,
                users.telegram_id,
                users.username,
                users.first_name,
                users.last_name
            FROM orders
            JOIN users ON users.id = orders.user_id
            WHERE orders.status IN ('manual_review', 'approved')
              AND orders.device_id IS NULL
            ORDER BY orders.created_at ASC, orders.id ASC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    def list_active_devices_with_users(self, *, limit: int = 50) -> list[sqlite3.Row]:
        return self._conn.execute(
            """
            SELECT
                devices.id,
                devices.name,
                devices.config_version,
                devices.status,
                devices.expires_at,
                devices.first_connected_at,
                devices.last_connected_at,
                devices.vpn_ip,
                users.telegram_id,
                users.username,
                users.first_name,
                users.last_name
            FROM devices
            JOIN users ON users.id = devices.user_id
            WHERE devices.status = 'active'
            ORDER BY devices.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    def list_disabled_devices_with_users(
        self,
        *,
        limit: int = 100,
    ) -> list[sqlite3.Row]:
        return self._conn.execute(
            """
            SELECT
                devices.id,
                devices.name,
                devices.config_version,
                devices.status,
                devices.vpn_ip,
                devices.expires_at,
                devices.revoked_at,
                devices.revoke_reason,
                users.id AS user_id,
                users.telegram_id,
                users.username,
                users.first_name,
                users.last_name,
                servers.name AS server_name
            FROM devices
            JOIN users ON users.id = devices.user_id
            JOIN servers ON servers.id = devices.server_id
            WHERE devices.status = 'disabled'
            ORDER BY devices.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    def list_active_devices_for_server(
        self,
        server_id: int,
        *,
        limit: int = 1000,
    ) -> list[sqlite3.Row]:
        return self._conn.execute(
            """
            SELECT
                devices.id,
                devices.user_id,
                devices.name,
                devices.config_version,
                devices.vpn_ip,
                devices.peer_public_key,
                devices.status,
                users.telegram_id,
                users.username,
                users.first_name,
                users.last_name
            FROM devices
            JOIN users ON users.id = devices.user_id
            WHERE server_id = ?
              AND devices.status = 'active'
            ORDER BY devices.id ASC
            LIMIT ?
            """,
            (server_id, limit),
        ).fetchall()

    def record_device_traffic_snapshot(
        self,
        *,
        device_id: int,
        server_id: int,
        peer_public_key: str,
        rx_bytes: int,
        tx_bytes: int,
        source: str,
        collected_at: str,
    ) -> int:
        cursor = self._conn.execute(
            """
            INSERT INTO device_traffic_snapshots (
                device_id,
                server_id,
                peer_public_key,
                rx_bytes,
                tx_bytes,
                source,
                collected_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                device_id,
                server_id,
                peer_public_key,
                rx_bytes,
                tx_bytes,
                source,
                collected_at,
            ),
        )
        self._commit()
        return int(cursor.lastrowid)

    def get_latest_device_traffic(self, device_id: int) -> sqlite3.Row | None:
        return self._conn.execute(
            """
            SELECT *
            FROM device_traffic_snapshots
            WHERE device_id = ?
            ORDER BY collected_at DESC, id DESC
            LIMIT 1
            """,
            (device_id,),
        ).fetchone()

    def mark_device_connected(self, device_id: int, *, connected_at: str) -> None:
        self._conn.execute(
            """
            UPDATE devices
            SET first_connected_at = COALESCE(first_connected_at, ?),
                last_connected_at = ?
            WHERE id = ?
            """,
            (connected_at, connected_at, device_id),
        )
        self._commit()

    def get_message_template(self, key: str, *, default_text: str) -> str:
        row = self._conn.execute(
            "SELECT text FROM message_templates WHERE key = ?",
            (key,),
        ).fetchone()
        if row is None:
            return default_text
        return str(row["text"])

    def set_message_template(self, key: str, text: str) -> None:
        self._conn.execute(
            """
            INSERT INTO message_templates (key, text)
            VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET
                text = excluded.text,
                updated_at = CURRENT_TIMESTAMP
            """,
            (key, text),
        )
        self._commit()

    def create_email_recovery_token(
        self,
        *,
        user_id: int,
        email: str,
        token_hash: str,
        purpose: str,
        expires_at: str,
        device_id: int | None = None,
    ) -> int:
        cursor = self._conn.execute(
            """
            INSERT INTO email_recovery_tokens (
                user_id,
                email,
                token_hash,
                purpose,
                device_id,
                expires_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (user_id, email, token_hash, purpose, device_id, expires_at),
        )
        self._commit()
        return int(cursor.lastrowid)

    def get_valid_email_recovery_token(
        self,
        *,
        token_hash: str,
        purpose: str,
        now: str,
    ) -> sqlite3.Row | None:
        return self._conn.execute(
            """
            SELECT *
            FROM email_recovery_tokens
            WHERE token_hash = ?
              AND purpose = ?
              AND used_at IS NULL
              AND expires_at > ?
            """,
            (token_hash, purpose, now),
        ).fetchone()

    def mark_email_recovery_token_used(self, token_id: int, used_at: str) -> bool:
        cursor = self._conn.execute(
            """
            UPDATE email_recovery_tokens
            SET used_at = ?
            WHERE id = ?
              AND used_at IS NULL
            """,
            (used_at, token_id),
        )
        self._commit()
        return cursor.rowcount > 0

    def create_api_token(
        self,
        *,
        token_id: str,
        name: str,
        owner_user_id: int | None,
        owner_label: str,
        token_hash: str,
        scopes: list[str],
        expires_at: str | None,
        integration_kind: str = "operator_automation",
        purpose: str = "legacy-api-access",
        rotated_from_token_id: str | None = None,
    ) -> None:
        if not token_id.strip():
            raise ValueError("token_id is required")
        if not name.strip():
            raise ValueError("name is required")
        if not owner_label.strip():
            raise ValueError("owner_label is required")
        if not integration_kind.strip():
            raise ValueError("integration_kind is required")
        if not purpose.strip():
            raise ValueError("purpose is required")
        if not token_hash.strip():
            raise ValueError("token_hash is required")
        if not scopes:
            raise ValueError("scopes are required")

        self._conn.execute(
            """
            INSERT INTO api_tokens (
                id,
                name,
                owner_user_id,
                owner_label,
                integration_kind,
                purpose,
                token_hash,
                scopes_json,
                expires_at,
                rotated_from_token_id
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                token_id,
                name,
                owner_user_id,
                owner_label,
                integration_kind,
                purpose,
                token_hash,
                json.dumps(scopes),
                expires_at,
                rotated_from_token_id,
            ),
        )
        self._commit()

    def get_valid_api_token(self, *, token_hash: str, now: str) -> sqlite3.Row | None:
        return self._conn.execute(
            """
            SELECT api_tokens.*, users.status AS owner_status
            FROM api_tokens
            LEFT JOIN users ON users.id = api_tokens.owner_user_id
            WHERE token_hash = ?
              AND revoked_at IS NULL
              AND (expires_at IS NULL OR expires_at > ?)
            """,
            (token_hash, now),
        ).fetchone()

    def mark_api_token_used(self, token_id: str, used_at: str) -> bool:
        cursor = self._conn.execute(
            """
            UPDATE api_tokens
            SET last_used_at = ?
            WHERE id = ?
            """,
            (used_at, token_id),
        )
        self._commit()
        return cursor.rowcount > 0

    def list_api_tokens_for_admin(self, *, limit: int = 100) -> list[sqlite3.Row]:
        return self._conn.execute(
            """
            SELECT
                id,
                name,
                owner_user_id,
                owner_label,
                integration_kind,
                purpose,
                scopes_json,
                expires_at,
                revoked_at,
                revoke_reason,
                last_used_at,
                rotated_from_token_id,
                created_at
            FROM api_tokens
            ORDER BY created_at DESC, id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    def get_api_token_for_admin(self, token_id: str) -> sqlite3.Row | None:
        return self._conn.execute(
            """
            SELECT api_tokens.*, users.status AS owner_status
            FROM api_tokens
            LEFT JOIN users ON users.id = api_tokens.owner_user_id
            WHERE api_tokens.id = ?
            """,
            (token_id,),
        ).fetchone()

    def revoke_api_token(
        self,
        token_id: str,
        revoked_at: str,
        reason: str | None = None,
    ) -> bool:
        cursor = self._conn.execute(
            """
            UPDATE api_tokens
            SET revoked_at = ?,
                revoke_reason = ?
            WHERE id = ?
              AND revoked_at IS NULL
            """,
            (revoked_at, reason, token_id),
        )
        self._commit()
        return cursor.rowcount > 0

    def _commit(self) -> None:
        if self._transaction_depth == 0:
            self._conn.commit()

    def _fetch_one(self, query: str, params: tuple[Any, ...]) -> sqlite3.Row:
        row = self._conn.execute(query, params).fetchone()
        if row is None:
            raise LookupError("record not found")
        return row


def _first_host_address(network_cidr: str) -> str:
    network = ipaddress.ip_network(network_cidr, strict=False)
    return str(next(network.hosts(), network.network_address))


def _host_address(value: str) -> str:
    try:
        return str(ipaddress.ip_interface(value).ip)
    except ValueError:
        return str(ipaddress.ip_address(value))


def _validate_user_status(status: str) -> None:
    if status not in USER_STATUSES:
        raise ValueError(f"unsupported user status: {status}")


def _validate_user_locale(locale: str) -> None:
    if locale not in USER_LOCALES:
        raise ValueError(f"unsupported user locale: {locale}")


def _validate_server_status(status: str) -> None:
    if status not in SERVER_STATUSES:
        raise ValueError(f"unsupported server status: {status}")


def _validate_server_fields(
    *,
    name: str,
    host: str,
    ssh_port: int,
    endpoint_host: str,
    vpn_port: int,
    vpn_network_cidr: str,
    server_address: str,
    runtime: str,
    firewall: str,
    max_devices: int,
) -> None:
    for field_name, value in {
        "name": name,
        "host": host,
        "endpoint_host": endpoint_host,
        "vpn_network_cidr": vpn_network_cidr,
        "server_address": server_address,
        "runtime": runtime,
        "firewall": firewall,
    }.items():
        if not value.strip():
            raise ValueError(f"{field_name} is required")
    _validate_port("ssh_port", ssh_port)
    _validate_port("vpn_port", vpn_port)
    if max_devices < 0:
        raise ValueError("max_devices must be non-negative")
    ipaddress.ip_network(vpn_network_cidr, strict=False)
    _host_address(server_address)


def _validate_port(field_name: str, value: int) -> None:
    if not 1 <= value <= 65535:
        raise ValueError(f"{field_name} must be in 1..65535")
