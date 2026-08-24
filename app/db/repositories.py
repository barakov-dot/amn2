import ipaddress
import json
import re
import sqlite3
from contextlib import contextmanager
from collections.abc import Iterator, Mapping
from datetime import datetime
from typing import Any

from app.config_assignment import (
    DEDICATED_DEVICE,
    validate_config_assignment_mode,
)

DEFAULT_PLAN_DAYS = (3, 7, 10, 14, 30, 60, 90, 180)
USER_STATUSES = {"active", "blocked", "deleted"}
USER_LOCALES = {"ru", "en"}
SERVER_STATUSES = {"active", "degraded", "disabled"}
DEVICE_STATUSES = {"pending", "active", "disabled", "expired", "revoked", "failed"}
PHASE13_PROTOCOL_VERSIONS = {"awg2", "awg3"}
RUNTIME_LIFECYCLE_STATES = {
    "planned",
    "candidate",
    "accepted",
    "rollback_pending",
    "retired",
}
COMPATIBILITY_EVIDENCE_STATUSES = {"claimed", "passed", "failed", "superseded"}
SHA256_DIGEST_PATTERN = re.compile(r"[0-9a-f]{64}\Z")


def _ascii_lower(text: str) -> str:
    return "".join(
        chr(ord(character) + 32)
        if "A" <= character <= "Z"
        else character
        for character in text
    )


def _require_sha256_digest(value: object, field_name: str) -> None:
    if (
        not isinstance(value, str)
        or SHA256_DIGEST_PATTERN.fullmatch(value) is None
    ):
        raise ValueError(f"{field_name} must be a lowercase SHA-256 digest")


class ProtocolIssuanceExecutionBlocked(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def user_display_label(row: Mapping[str, Any]) -> str:
    operator_label = str(_mapping_value(row, "operator_label") or "").strip()
    if operator_label:
        return operator_label
    username = str(_mapping_value(row, "username") or "").strip()
    if username:
        return f"@{username}"
    name = " ".join(
        part
        for part in (
            str(_mapping_value(row, "first_name") or "").strip(),
            str(_mapping_value(row, "last_name") or "").strip(),
        )
        if part
    )
    if name:
        return name
    telegram_id = _mapping_value(row, "telegram_id")
    if telegram_id is not None:
        return f"telegram_id={telegram_id}"
    return "operator recipient"


def _mapping_value(
    row: Mapping[str, Any], key: str, default: Any = None
) -> Any:
    get = getattr(row, "get", None)
    if get is not None:
        return get(key, default)
    try:
        return row[key]
    except (KeyError, IndexError):
        return default


class Repository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        self._transaction_depth = 0
        self._active_outer_transaction_identity: object | None = None
        self._protocol_issuance_execution_leases: dict[object, dict[str, Any]] = {}
        self._active_phase15_claims: set[tuple[str, str, str]] = set()

    @contextmanager
    def transaction(self) -> Iterator[None]:
        is_outermost = self._transaction_depth == 0
        savepoint: str | None = None
        transaction_identity = self._active_outer_transaction_identity
        if is_outermost:
            self._conn.execute("BEGIN IMMEDIATE")
            transaction_identity = object()
            self._active_outer_transaction_identity = transaction_identity
        else:
            sequence = getattr(self, "_transaction_savepoint_sequence", 0)
            self._transaction_savepoint_sequence = sequence + 1
            savepoint = f"repository_transaction_{sequence}"
            self._conn.execute(f"SAVEPOINT {savepoint}")

        self._transaction_depth += 1
        try:
            yield
        except BaseException:
            self._transaction_depth -= 1
            if is_outermost:
                try:
                    self._conn.rollback()
                finally:
                    self._discard_leases_created_in_transaction(transaction_identity)
                    self._active_outer_transaction_identity = None
            else:
                assert savepoint is not None
                self._conn.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
                self._conn.execute(f"RELEASE SAVEPOINT {savepoint}")
            raise
        else:
            self._transaction_depth -= 1
            if is_outermost:
                try:
                    self._conn.commit()
                except BaseException:
                    try:
                        self._conn.rollback()
                    finally:
                        self._discard_leases_created_in_transaction(
                            transaction_identity
                        )
                        self._active_outer_transaction_identity = None
                    raise
                self._active_outer_transaction_identity = None
            else:
                assert savepoint is not None
                self._conn.execute(f"RELEASE SAVEPOINT {savepoint}")

    def _discard_leases_created_in_transaction(
        self, transaction_identity: object | None
    ) -> None:
        if transaction_identity is None:
            return
        stale = [
            lease
            for lease, state in self._protocol_issuance_execution_leases.items()
            if state["created_transaction"] is transaction_identity
        ]
        for lease in stale:
            self._protocol_issuance_execution_leases.pop(lease, None)

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

    def create_operator_recipient(self, *, operator_label: str) -> int:
        label = operator_label.strip()
        if not label:
            raise ValueError("operator_label must not be blank")
        if self.get_user_by_operator_label(label) is not None:
            raise ValueError("operator_label already exists")
        try:
            cursor = self._conn.execute(
                "INSERT INTO users (telegram_id, operator_label) VALUES (NULL, ?)",
                (label,),
            )
        except sqlite3.IntegrityError as exc:
            raise ValueError("operator_label already exists") from exc
        self._commit()
        return int(cursor.lastrowid)

    def get_user_by_operator_label(
        self, operator_label: str
    ) -> sqlite3.Row | None:
        label = operator_label.strip()
        if not label:
            return None
        return self._conn.execute(
            """
            SELECT * FROM users
            WHERE lower(trim(operator_label)) = lower(trim(?))
            """,
            (label,),
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

    def create_vpn_runtime_instance(
        self,
        *,
        runtime_instance_id: str,
        server_id: int,
        protocol_version: str,
        runtime_version: str,
        interface_name: str,
        udp_port: int,
        vpn_cidr: str,
        container_name: str | None,
        service_name: str | None,
        config_path: str,
        lifecycle_state: str,
        acceptance_receipt: str | None,
    ) -> sqlite3.Row:
        runtime_instance_id = _validate_phase13_text(
            "runtime_instance_id", runtime_instance_id
        )
        runtime_version = _validate_phase13_text("runtime_version", runtime_version)
        interface_name = _validate_phase13_text("interface_name", interface_name)
        vpn_cidr = _validate_phase13_text("vpn_cidr", vpn_cidr)
        config_path = _validate_phase13_text("config_path", config_path, max_length=512)
        container_name = _validate_optional_phase13_text(
            "container_name", container_name
        )
        service_name = _validate_optional_phase13_text("service_name", service_name)
        _validate_phase13_protocol(protocol_version)
        if lifecycle_state not in RUNTIME_LIFECYCLE_STATES:
            raise ValueError("unsupported lifecycle_state")
        _validate_port("udp_port", udp_port)
        try:
            ipaddress.ip_network(vpn_cidr, strict=False)
        except ValueError as exc:
            raise ValueError("vpn_cidr must be a valid network") from exc
        if acceptance_receipt is not None and not re.fullmatch(
            r"sha256:[0-9a-f]{64}", acceptance_receipt
        ):
            raise ValueError("acceptance_receipt must be a sha256 fingerprint")
        if lifecycle_state == "accepted" and acceptance_receipt is None:
            raise ValueError("accepted runtime requires acceptance_receipt")

        self._conn.execute(
            """
            INSERT INTO vpn_runtime_instances (
                runtime_instance_id, server_id, protocol_version, runtime_version,
                interface_name, udp_port, vpn_cidr, container_name, service_name,
                config_path, lifecycle_state, acceptance_receipt
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                runtime_instance_id,
                server_id,
                protocol_version,
                runtime_version,
                interface_name,
                udp_port,
                vpn_cidr,
                container_name,
                service_name,
                config_path,
                lifecycle_state,
                acceptance_receipt,
            ),
        )
        self._commit()
        row = self.get_vpn_runtime_instance(runtime_instance_id)
        assert row is not None
        return row

    def get_vpn_runtime_instance(
        self, runtime_instance_id: str
    ) -> sqlite3.Row | None:
        return self._conn.execute(
            "SELECT * FROM vpn_runtime_instances WHERE runtime_instance_id = ?",
            (runtime_instance_id,),
        ).fetchone()

    def list_vpn_runtime_instances_for_server(
        self, server_id: int
    ) -> list[sqlite3.Row]:
        return self._conn.execute(
            """
            SELECT *
            FROM vpn_runtime_instances
            WHERE server_id = ?
            ORDER BY runtime_instance_id
            LIMIT 100
            """,
            (server_id,),
        ).fetchall()

    def create_client_compatibility_evidence(
        self,
        *,
        evidence_id: str,
        application: str,
        platform: str,
        client_version: str,
        protocol_version: str,
        source_kind: str,
        status: str,
        observed_at: str,
        safe_reference: str,
        scope: str,
    ) -> sqlite3.Row:
        values = {
            "evidence_id": _validate_phase13_text("evidence_id", evidence_id),
            "application": _validate_phase13_text("application", application),
            "platform": _validate_phase13_text("platform", platform),
            "client_version": _validate_phase13_text(
                "client_version", client_version, max_length=64
            ),
            "source_kind": _validate_phase13_text("source_kind", source_kind),
            "safe_reference": _validate_phase13_text(
                "safe_reference", safe_reference, max_length=512
            ),
            "scope": _validate_phase13_text("scope", scope, max_length=512),
        }
        _validate_phase13_protocol(protocol_version)
        if status not in COMPATIBILITY_EVIDENCE_STATUSES:
            raise ValueError("unsupported compatibility evidence status")
        _validate_phase13_timestamp("observed_at", observed_at)
        self._conn.execute(
            """
            INSERT INTO client_compatibility_evidence (
                evidence_id, application, platform, client_version,
                protocol_version, source_kind, status, observed_at,
                safe_reference, scope
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                values["evidence_id"],
                values["application"],
                values["platform"],
                values["client_version"],
                protocol_version,
                values["source_kind"],
                status,
                observed_at,
                values["safe_reference"],
                values["scope"],
            ),
        )
        self._commit()
        row = self._conn.execute(
            "SELECT * FROM client_compatibility_evidence WHERE evidence_id = ?",
            (values["evidence_id"],),
        ).fetchone()
        assert row is not None
        return row

    def find_client_compatibility_evidence(
        self,
        *,
        application: str,
        platform: str,
        client_version: str,
        protocol_version: str,
    ) -> list[sqlite3.Row]:
        _validate_phase13_protocol(protocol_version)
        application = _validate_phase13_text("application", application)
        platform = _validate_phase13_text("platform", platform)
        client_version = _validate_phase13_text(
            "client_version", client_version, max_length=64
        )
        return self._conn.execute(
            """
            SELECT *
            FROM client_compatibility_evidence
            WHERE application = ?
              AND platform = ?
              AND client_version = ?
              AND protocol_version = ?
            ORDER BY observed_at DESC, evidence_id
            LIMIT 100
            """,
            (application, platform, client_version, protocol_version),
        ).fetchall()

    def get_awg3_control_state(self) -> sqlite3.Row:
        return self._fetch_one(
            "SELECT * FROM awg3_control_state WHERE singleton_id = 1",
            (),
        )

    def update_awg3_control_state(
        self,
        *,
        runtime_accepted: bool,
        global_accepted: bool,
        issuance_enabled: bool,
        emergency_suspended: bool,
        runtime_receipt: str | None,
        actor_id: int,
        reason: str,
    ) -> None:
        self._conn.execute(
            """
            UPDATE awg3_control_state
            SET runtime_accepted = ?,
                global_accepted = ?,
                issuance_enabled = ?,
                emergency_suspended = ?,
                runtime_receipt = ?,
                actor_id = ?,
                reason = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE singleton_id = 1
            """,
            (
                int(runtime_accepted),
                int(global_accepted),
                int(issuance_enabled),
                int(emergency_suspended),
                runtime_receipt,
                actor_id,
                reason,
            ),
        )
        self._commit()

    def upsert_client_build_acceptance(
        self,
        *,
        application: str,
        platform: str,
        client_version: str,
        client_build: str,
        state: str,
        evidence_ids: tuple[str, ...],
        actor_id: int,
        reason: str,
    ) -> None:
        self._conn.execute(
            """
            INSERT INTO client_build_acceptances (
                application,
                platform,
                client_version,
                client_build,
                state,
                evidence_ids_json,
                actor_id,
                reason
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(
                application,
                platform,
                client_version,
                client_build,
                protocol_version
            ) DO UPDATE SET
                state = excluded.state,
                evidence_ids_json = excluded.evidence_ids_json,
                actor_id = excluded.actor_id,
                reason = excluded.reason,
                updated_at = CURRENT_TIMESTAMP
            """,
            (
                application,
                platform,
                client_version,
                client_build,
                state,
                json.dumps(
                    evidence_ids,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                actor_id,
                reason,
            ),
        )
        self._commit()

    def get_client_build_acceptance(
        self,
        *,
        application: str,
        platform: str,
        client_version: str,
        client_build: str,
    ) -> sqlite3.Row | None:
        return self._conn.execute(
            """
            SELECT *
            FROM client_build_acceptances
            WHERE application = ?
              AND platform = ?
              AND client_version = ?
              AND client_build = ?
              AND protocol_version = 'awg3'
            """,
            (application, platform, client_version, client_build),
        ).fetchone()

    def create_callback_handle(
        self,
        *,
        handle_digest: str,
        purpose: str,
        owner_user_id: int,
        passport_device_id: str,
        client_platform: str | None,
        client_application: str | None,
        client_version: str | None,
        client_build: str | None,
        request_fingerprint: str,
        created_at: str,
        expires_at: str,
    ) -> sqlite3.Row:
        _require_sha256_digest(handle_digest, "handle_digest")
        with self.transaction():
            self._conn.execute(
                """
                INSERT INTO telegram_callback_handles (
                    handle_digest,
                    purpose,
                    owner_user_id,
                    passport_device_id,
                    client_platform,
                    client_application,
                    client_version,
                    client_build,
                    request_fingerprint,
                    created_at,
                    expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    handle_digest,
                    purpose,
                    owner_user_id,
                    passport_device_id,
                    client_platform,
                    client_application,
                    client_version,
                    client_build,
                    request_fingerprint,
                    created_at,
                    expires_at,
                ),
            )
            row = self._conn.execute(
                "SELECT * FROM telegram_callback_handles WHERE handle_digest = ?",
                (handle_digest,),
            ).fetchone()
            assert row is not None
            return row

    def claim_callback_handle(
        self,
        handle_digest: str,
        owner_user_id: int,
        now: str,
        *,
        claim_id_digest: str,
        claim_expires_at: str,
    ) -> sqlite3.Row | None:
        _require_sha256_digest(handle_digest, "handle_digest")
        _require_sha256_digest(claim_id_digest, "claim_id_digest")
        if claim_expires_at <= now:
            raise ValueError("claim_expires_at must be later than now")
        with self.transaction():
            cursor = self._conn.execute(
                """
                UPDATE telegram_callback_handles
                SET claim_id_digest = ?,
                    claimed_at = ?,
                    claim_expires_at = ?
                WHERE handle_digest = ?
                  AND owner_user_id = ?
                  AND consumed_at IS NULL
                  AND expires_at > ?
                  AND (
                      claim_id_digest IS NULL
                      OR claim_expires_at <= ?
                  )
                """,
                (
                    claim_id_digest,
                    now,
                    claim_expires_at,
                    handle_digest,
                    owner_user_id,
                    now,
                    now,
                ),
            )
            if cursor.rowcount != 1:
                return None
            row = self._conn.execute(
                "SELECT * FROM telegram_callback_handles WHERE handle_digest = ?",
                (handle_digest,),
            ).fetchone()
            assert row is not None
        self._active_phase15_claims.add(
            ("callback", handle_digest, claim_id_digest)
        )
        return row

    def release_callback_handle_claim(
        self,
        handle_digest: str,
        owner_user_id: int,
        now: str,
        *,
        claim_id_digest: str,
    ) -> sqlite3.Row | None:
        _require_sha256_digest(handle_digest, "handle_digest")
        _require_sha256_digest(claim_id_digest, "claim_id_digest")
        with self.transaction():
            cursor = self._conn.execute(
                """
                UPDATE telegram_callback_handles
                SET claim_id_digest = NULL,
                    claimed_at = NULL,
                    claim_expires_at = NULL
                WHERE handle_digest = ?
                  AND owner_user_id = ?
                  AND consumed_at IS NULL
                  AND expires_at > ?
                  AND claim_id_digest = ?
                """,
                (handle_digest, owner_user_id, now, claim_id_digest),
            )
            if cursor.rowcount != 1:
                return None
            row = self._conn.execute(
                "SELECT * FROM telegram_callback_handles WHERE handle_digest = ?",
                (handle_digest,),
            ).fetchone()
            assert row is not None
        self._active_phase15_claims.discard(
            ("callback", handle_digest, claim_id_digest)
        )
        return row

    def consume_callback_handle(
        self,
        handle_digest: str,
        owner_user_id: int,
        now: str,
        terminal_reason: str,
        *,
        claim_id_digest: str,
    ) -> sqlite3.Row | None:
        _require_sha256_digest(handle_digest, "handle_digest")
        _require_sha256_digest(claim_id_digest, "claim_id_digest")
        with self.transaction():
            cursor = self._conn.execute(
                """
                UPDATE telegram_callback_handles
                SET consumed_at = ?, terminal_reason = ?
                WHERE handle_digest = ?
                  AND owner_user_id = ?
                  AND consumed_at IS NULL
                  AND claim_id_digest = ?
                """,
                (
                    now,
                    terminal_reason,
                    handle_digest,
                    owner_user_id,
                    claim_id_digest,
                ),
            )
            if cursor.rowcount != 1:
                return None
            row = self._conn.execute(
                "SELECT * FROM telegram_callback_handles WHERE handle_digest = ?",
                (handle_digest,),
            ).fetchone()
            assert row is not None
        self._active_phase15_claims.discard(
            ("callback", handle_digest, claim_id_digest)
        )
        return row

    def consume_expired_callback_handle(
        self,
        handle_digest: str,
        owner_user_id: int,
        now: str,
        *,
        expected_purpose: str,
    ) -> sqlite3.Row | None:
        _require_sha256_digest(handle_digest, "handle_digest")
        if not expected_purpose:
            raise ValueError("expected_purpose")
        with self.transaction():
            current = self._conn.execute(
                "SELECT * FROM telegram_callback_handles WHERE handle_digest = ?",
                (handle_digest,),
            ).fetchone()
            if (
                current is None
                or int(current["owner_user_id"]) != owner_user_id
                or str(current["purpose"]) != expected_purpose
                or current["consumed_at"] is not None
                or str(current["expires_at"]) > now
                or not self._phase15_claim_is_abandoned(
                    "callback",
                    handle_digest,
                    current,
                    now,
                )
            ):
                return None
            cursor = self._conn.execute(
                """
                UPDATE telegram_callback_handles
                SET consumed_at = ?, terminal_reason = 'expired'
                WHERE handle_digest = ?
                  AND owner_user_id = ?
                  AND purpose = ?
                  AND consumed_at IS NULL
                  AND expires_at <= ?
                  AND claim_id_digest IS ?
                  AND claimed_at IS ?
                  AND claim_expires_at IS ?
                """,
                (
                    now,
                    handle_digest,
                    owner_user_id,
                    expected_purpose,
                    now,
                    current["claim_id_digest"],
                    current["claimed_at"],
                    current["claim_expires_at"],
                ),
            )
            if cursor.rowcount != 1:
                return None
            row = self._conn.execute(
                "SELECT * FROM telegram_callback_handles WHERE handle_digest = ?",
                (handle_digest,),
            ).fetchone()
            assert row is not None
        claim_digest = current["claim_id_digest"]
        if claim_digest is not None:
            self._active_phase15_claims.discard(
                ("callback", handle_digest, str(claim_digest))
            )
        return row

    def create_issuance_confirmation(
        self,
        *,
        token_digest: str,
        selection_handle_digest: str,
        owner_user_id: int,
        passport_device_id: str,
        client_platform: str,
        client_application: str,
        client_version: str,
        client_build: str,
        request_fingerprint: str,
        created_at: str,
        expires_at: str,
    ) -> sqlite3.Row:
        _require_sha256_digest(token_digest, "token_digest")
        _require_sha256_digest(
            selection_handle_digest, "selection_handle_digest"
        )
        with self.transaction():
            self._conn.execute(
                """
                INSERT INTO protocol_issuance_confirmations (
                    token_digest,
                    selection_handle_digest,
                    owner_user_id,
                    passport_device_id,
                    client_platform,
                    client_application,
                    client_version,
                    client_build,
                    request_fingerprint,
                    created_at,
                    expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    token_digest,
                    selection_handle_digest,
                    owner_user_id,
                    passport_device_id,
                    client_platform,
                    client_application,
                    client_version,
                    client_build,
                    request_fingerprint,
                    created_at,
                    expires_at,
                ),
            )
            row = self._conn.execute(
                "SELECT * FROM protocol_issuance_confirmations "
                "WHERE token_digest = ?",
                (token_digest,),
            ).fetchone()
            assert row is not None
            return row

    def claim_issuance_confirmation(
        self,
        token_digest: str,
        owner_user_id: int,
        now: str,
        *,
        claim_id_digest: str,
        claim_expires_at: str,
    ) -> sqlite3.Row | None:
        _require_sha256_digest(token_digest, "token_digest")
        _require_sha256_digest(claim_id_digest, "claim_id_digest")
        if claim_expires_at <= now:
            raise ValueError("claim_expires_at must be later than now")
        with self.transaction():
            confirmation_columns = {
                _ascii_lower(str(row[1]))
                for row in self._conn.execute(
                    "PRAGMA table_info(protocol_issuance_confirmations)"
                )
            }
            durable_attempt_guard = ""
            if "issuance_attempt_id" in confirmation_columns:
                durable_attempt_guard = """
                  AND NOT EXISTS (
                      SELECT 1
                      FROM protocol_issuance_attempts AS attempt
                      WHERE attempt.id =
                                protocol_issuance_confirmations.issuance_attempt_id
                        AND attempt.owner_user_id =
                                protocol_issuance_confirmations.owner_user_id
                        AND attempt.intended_passport_device_id =
                                protocol_issuance_confirmations.passport_device_id
                        AND attempt.request_fingerprint =
                                protocol_issuance_confirmations.request_fingerprint
                        AND attempt.state IN ('reserved', 'recovery_required')
                  )
                """
            cursor = self._conn.execute(
                f"""
                UPDATE protocol_issuance_confirmations
                SET claim_id_digest = ?,
                    claimed_at = ?,
                    claim_expires_at = ?
                WHERE token_digest = ?
                  AND owner_user_id = ?
                  AND consumed_at IS NULL
                  AND expires_at > ?
                  AND (
                      claim_id_digest IS NULL
                      OR claim_expires_at <= ?
                  )
                  {durable_attempt_guard}
                """,
                (
                    claim_id_digest,
                    now,
                    claim_expires_at,
                    token_digest,
                    owner_user_id,
                    now,
                    now,
                ),
            )
            if cursor.rowcount != 1:
                return None
            row = self._conn.execute(
                "SELECT * FROM protocol_issuance_confirmations "
                "WHERE token_digest = ?",
                (token_digest,),
            ).fetchone()
            assert row is not None
        self._active_phase15_claims.add(
            ("confirmation", token_digest, claim_id_digest)
        )
        return row

    def release_issuance_confirmation_claim(
        self,
        token_digest: str,
        owner_user_id: int,
        now: str,
        *,
        claim_id_digest: str,
    ) -> sqlite3.Row | None:
        _require_sha256_digest(token_digest, "token_digest")
        _require_sha256_digest(claim_id_digest, "claim_id_digest")
        with self.transaction():
            cursor = self._conn.execute(
                """
                UPDATE protocol_issuance_confirmations
                SET claim_id_digest = NULL,
                    claimed_at = NULL,
                    claim_expires_at = NULL
                WHERE token_digest = ?
                  AND owner_user_id = ?
                  AND consumed_at IS NULL
                  AND expires_at > ?
                  AND claim_id_digest = ?
                """,
                (token_digest, owner_user_id, now, claim_id_digest),
            )
            if cursor.rowcount != 1:
                return None
            row = self._conn.execute(
                "SELECT * FROM protocol_issuance_confirmations "
                "WHERE token_digest = ?",
                (token_digest,),
            ).fetchone()
            assert row is not None
        self._active_phase15_claims.discard(
            ("confirmation", token_digest, claim_id_digest)
        )
        return row

    def renew_issuance_confirmation_claim(
        self,
        token_digest: str,
        owner_user_id: int,
        now: str,
        *,
        claim_id_digest: str,
        claim_expires_at: str,
    ) -> sqlite3.Row | None:
        _require_sha256_digest(token_digest, "token_digest")
        _require_sha256_digest(claim_id_digest, "claim_id_digest")
        if claim_expires_at <= now:
            raise ValueError("claim_expires_at must be later than now")
        with self.transaction():
            cursor = self._conn.execute(
                """
                UPDATE protocol_issuance_confirmations
                SET claim_expires_at = ?
                WHERE token_digest = ?
                  AND owner_user_id = ?
                  AND consumed_at IS NULL
                  AND expires_at > ?
                  AND claim_id_digest = ?
                """,
                (
                    claim_expires_at,
                    token_digest,
                    owner_user_id,
                    now,
                    claim_id_digest,
                ),
            )
            if cursor.rowcount != 1:
                return None
            row = self._conn.execute(
                "SELECT * FROM protocol_issuance_confirmations "
                "WHERE token_digest = ?",
                (token_digest,),
            ).fetchone()
            assert row is not None
        self._active_phase15_claims.add(
            ("confirmation", token_digest, claim_id_digest)
        )
        return row

    def bind_issuance_confirmation_attempt(
        self,
        token_digest: str,
        owner_user_id: int,
        *,
        claim_id_digest: str,
        attempt_id: int,
    ) -> sqlite3.Row | None:
        _require_sha256_digest(token_digest, "token_digest")
        _require_sha256_digest(claim_id_digest, "claim_id_digest")
        with self.transaction():
            attempt = self.get_protocol_issuance_attempt(attempt_id)
            if (
                attempt is None
                or str(attempt["state"])
                not in {"reserved", "recovery_required"}
                or int(attempt["owner_user_id"]) != owner_user_id
            ):
                return None
            cursor = self._conn.execute(
                """
                UPDATE protocol_issuance_confirmations
                SET issuance_attempt_id = ?
                WHERE token_digest = ?
                  AND owner_user_id = ?
                  AND consumed_at IS NULL
                  AND claim_id_digest = ?
                  AND passport_device_id = ?
                  AND request_fingerprint = ?
                """,
                (
                    attempt_id,
                    token_digest,
                    owner_user_id,
                    claim_id_digest,
                    attempt["intended_passport_device_id"],
                    attempt["request_fingerprint"],
                ),
            )
            if cursor.rowcount != 1:
                return None
            row = self._conn.execute(
                "SELECT * FROM protocol_issuance_confirmations "
                "WHERE token_digest = ?",
                (token_digest,),
            ).fetchone()
            assert row is not None
            return row

    def consume_issuance_confirmation(
        self,
        token_digest: str,
        owner_user_id: int,
        now: str,
        terminal_reason: str,
        *,
        claim_id_digest: str,
    ) -> sqlite3.Row | None:
        _require_sha256_digest(token_digest, "token_digest")
        _require_sha256_digest(claim_id_digest, "claim_id_digest")
        with self.transaction():
            cursor = self._conn.execute(
                """
                UPDATE protocol_issuance_confirmations
                SET consumed_at = ?, terminal_reason = ?
                WHERE token_digest = ?
                  AND owner_user_id = ?
                  AND consumed_at IS NULL
                  AND claim_id_digest = ?
                """,
                (
                    now,
                    terminal_reason,
                    token_digest,
                    owner_user_id,
                    claim_id_digest,
                ),
            )
            if cursor.rowcount != 1:
                return None
            row = self._conn.execute(
                "SELECT * FROM protocol_issuance_confirmations "
                "WHERE token_digest = ?",
                (token_digest,),
            ).fetchone()
            assert row is not None
        self._active_phase15_claims.discard(
            ("confirmation", token_digest, claim_id_digest)
        )
        return row

    def consume_bound_issuance_confirmation(
        self,
        token_digest: str,
        owner_user_id: int,
        now: str,
        terminal_reason: str,
        *,
        claim_id_digest: str,
        attempt_id: int,
    ) -> sqlite3.Row | None:
        _require_sha256_digest(token_digest, "token_digest")
        _require_sha256_digest(claim_id_digest, "claim_id_digest")
        with self.transaction():
            attempt = self.get_protocol_issuance_attempt(attempt_id)
            if (
                attempt is None
                or str(attempt["state"]) != "completed"
                or int(attempt["owner_user_id"]) != owner_user_id
            ):
                return None
            cursor = self._conn.execute(
                """
                UPDATE protocol_issuance_confirmations
                SET consumed_at = ?, terminal_reason = ?
                WHERE token_digest = ?
                  AND owner_user_id = ?
                  AND consumed_at IS NULL
                  AND claim_id_digest = ?
                  AND issuance_attempt_id = ?
                  AND passport_device_id = ?
                  AND request_fingerprint = ?
                """,
                (
                    now,
                    terminal_reason,
                    token_digest,
                    owner_user_id,
                    claim_id_digest,
                    attempt_id,
                    attempt["intended_passport_device_id"],
                    attempt["request_fingerprint"],
                ),
            )
            if cursor.rowcount != 1:
                return None
            row = self._conn.execute(
                "SELECT * FROM protocol_issuance_confirmations "
                "WHERE token_digest = ?",
                (token_digest,),
            ).fetchone()
            assert row is not None
        self._active_phase15_claims.discard(
            ("confirmation", token_digest, claim_id_digest)
        )
        return row

    def consume_expired_issuance_confirmation(
        self,
        token_digest: str,
        owner_user_id: int,
        now: str,
    ) -> sqlite3.Row | None:
        _require_sha256_digest(token_digest, "token_digest")
        with self.transaction():
            current = self._conn.execute(
                "SELECT * FROM protocol_issuance_confirmations "
                "WHERE token_digest = ?",
                (token_digest,),
            ).fetchone()
            if (
                current is None
                or int(current["owner_user_id"]) != owner_user_id
                or current["consumed_at"] is not None
                or str(current["expires_at"]) > now
                or not self._phase15_claim_is_abandoned(
                    "confirmation",
                    token_digest,
                    current,
                    now,
                )
            ):
                return None
            cursor = self._conn.execute(
                """
                UPDATE protocol_issuance_confirmations
                SET consumed_at = ?, terminal_reason = 'expired'
                WHERE token_digest = ?
                  AND owner_user_id = ?
                  AND consumed_at IS NULL
                  AND expires_at <= ?
                  AND claim_id_digest IS ?
                  AND claimed_at IS ?
                  AND claim_expires_at IS ?
                """,
                (
                    now,
                    token_digest,
                    owner_user_id,
                    now,
                    current["claim_id_digest"],
                    current["claimed_at"],
                    current["claim_expires_at"],
                ),
            )
            if cursor.rowcount != 1:
                return None
            row = self._conn.execute(
                "SELECT * FROM protocol_issuance_confirmations "
                "WHERE token_digest = ?",
                (token_digest,),
            ).fetchone()
            assert row is not None
        claim_digest = current["claim_id_digest"]
        if claim_digest is not None:
            self._active_phase15_claims.discard(
                ("confirmation", token_digest, str(claim_digest))
            )
        return row

    def prune_expired_phase15_callback_state(self, now: str) -> int:
        pruned_claims: list[tuple[str, str, str]] = []
        deleted = 0
        with self.transaction():
            confirmation_rows = self._conn.execute(
                """
                SELECT * FROM protocol_issuance_confirmations
                WHERE expires_at <= ?
                """,
                (now,),
            ).fetchall()
            for row in confirmation_rows:
                token_digest = str(row["token_digest"])
                if (
                    row["consumed_at"] is None
                    and not self._phase15_claim_is_abandoned(
                        "confirmation",
                        token_digest,
                        row,
                        now,
                    )
                ):
                    continue
                cursor = self._conn.execute(
                    "DELETE FROM protocol_issuance_confirmations "
                    "WHERE token_digest = ?",
                    (token_digest,),
                )
                deleted += int(cursor.rowcount)
                if row["claim_id_digest"] is not None:
                    pruned_claims.append(
                        (
                            "confirmation",
                            token_digest,
                            str(row["claim_id_digest"]),
                        )
                    )
            callback_rows = self._conn.execute(
                """
                SELECT * FROM telegram_callback_handles
                WHERE expires_at <= ?
                  AND NOT EXISTS (
                      SELECT 1
                      FROM protocol_issuance_confirmations
                      WHERE selection_handle_digest = handle_digest
                  )
                """,
                (now,),
            ).fetchall()
            for row in callback_rows:
                handle_digest = str(row["handle_digest"])
                if (
                    row["consumed_at"] is None
                    and not self._phase15_claim_is_abandoned(
                        "callback",
                        handle_digest,
                        row,
                        now,
                    )
                ):
                    continue
                cursor = self._conn.execute(
                    "DELETE FROM telegram_callback_handles "
                    "WHERE handle_digest = ?",
                    (handle_digest,),
                )
                deleted += int(cursor.rowcount)
                if row["claim_id_digest"] is not None:
                    pruned_claims.append(
                        ("callback", handle_digest, str(row["claim_id_digest"]))
                    )
        for claim in pruned_claims:
            self._active_phase15_claims.discard(claim)
        return deleted

    def _phase15_claim_is_abandoned(
        self,
        row_kind: str,
        row_digest: str,
        row: Mapping[str, Any],
        now: str,
    ) -> bool:
        if row_kind == "confirmation" and self._confirmation_has_durable_attempt(row):
            return False
        claim_digest = row["claim_id_digest"]
        if claim_digest is None:
            return (
                row["claimed_at"] is None
                and row["claim_expires_at"] is None
            )
        claim_expires_at = row["claim_expires_at"]
        return (
            claim_expires_at is not None
            and str(claim_expires_at) <= now
            and (row_kind, row_digest, str(claim_digest))
            not in self._active_phase15_claims
        )

    def _confirmation_has_durable_attempt(self, row: Mapping[str, Any]) -> bool:
        attempt_id = row["issuance_attempt_id"]
        if attempt_id is None:
            return False
        return (
            self._conn.execute(
                """
                SELECT 1
                FROM protocol_issuance_attempts
                WHERE id = ?
                  AND owner_user_id = ?
                  AND intended_passport_device_id = ?
                  AND request_fingerprint = ?
                  AND state IN ('reserved', 'recovery_required')
                LIMIT 1
                """,
                (
                    attempt_id,
                    row["owner_user_id"],
                    row["passport_device_id"],
                    row["request_fingerprint"],
                ),
            ).fetchone()
            is not None
        )

    def reserve_protocol_issuance_attempt(
        self,
        *,
        passport_device_id: str | None,
        protocol_version: str,
        request_fingerprint: str,
        actor_kind: str,
        actor_id: int,
        client_application: str,
        client_platform: str,
        client_version: str,
        client_build: str | None,
        runtime_instance_id: str | None,
        compatibility_evidence_id: str | None,
        owner_user_id: int | None = None,
        intended_passport_device_id: str | None = None,
    ) -> sqlite3.Row | None:
        if intended_passport_device_id is None:
            intended_passport_device_id = passport_device_id
        if not intended_passport_device_id:
            raise ValueError("intended_passport_device_id is required")
        if owner_user_id is None:
            if passport_device_id is None:
                raise ValueError("owner_user_id is required for an unbound passport")
            passport = self.get_device_passport(passport_device_id)
            if passport is None:
                return None
            owner_user_id = int(passport["owner_user_id"])
        with self.transaction():
            try:
                cursor = self._conn.execute(
                    """
                    INSERT INTO protocol_issuance_attempts (
                        owner_user_id,
                        intended_passport_device_id,
                        passport_device_id,
                        protocol_version,
                        request_fingerprint,
                        actor_kind,
                        actor_id,
                        client_application,
                        client_platform,
                        client_version,
                        client_build,
                        runtime_instance_id,
                        compatibility_evidence_id
                    )
                    SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                    WHERE EXISTS (
                        SELECT 1 FROM users
                        WHERE id = ? AND status = 'active'
                    )
                      AND NOT EXISTS (
                        SELECT 1 FROM protocol_issuance_user_barriers
                        WHERE user_id = ?
                    )
                      AND (
                        ? IS NULL OR EXISTS (
                            SELECT 1 FROM device_passports
                            WHERE device_id = ?
                              AND owner_user_id = ?
                              AND revoked_at IS NULL
                        )
                      )
                      AND NOT EXISTS (
                        SELECT 1
                        FROM device_protocol_profiles
                        WHERE passport_device_id = ?
                          AND protocol_version = ?
                    )
                      AND NOT EXISTS (
                        SELECT 1
                        FROM protocol_issuance_attempts
                        WHERE intended_passport_device_id = ?
                          AND protocol_version = ?
                          AND state IN ('reserved','recovery_required')
                    )
                    """,
                    (
                        owner_user_id,
                        intended_passport_device_id,
                        passport_device_id,
                        protocol_version,
                        request_fingerprint,
                        actor_kind,
                        actor_id,
                        client_application,
                        client_platform,
                        client_version,
                        client_build,
                        runtime_instance_id,
                        compatibility_evidence_id,
                        owner_user_id,
                        owner_user_id,
                        passport_device_id,
                        passport_device_id,
                        owner_user_id,
                        intended_passport_device_id,
                        protocol_version,
                        intended_passport_device_id,
                        protocol_version,
                    ),
                )
            except sqlite3.IntegrityError:
                if (
                    self.get_device_protocol_profile(
                        passport_device_id=intended_passport_device_id,
                        protocol_version=protocol_version,
                    )
                    is not None
                    or self.get_blocking_protocol_issuance_attempt(
                        intended_passport_device_id=intended_passport_device_id,
                        protocol_version=protocol_version,
                    )
                    is not None
                ):
                    return None
                raise
            if cursor.rowcount != 1:
                return None
            attempt_id = int(cursor.lastrowid)
            attempt = self.get_protocol_issuance_attempt(attempt_id)
            assert attempt is not None
            return attempt

    def get_protocol_issuance_attempt(
        self, attempt_id: int
    ) -> sqlite3.Row | None:
        return self._conn.execute(
            "SELECT * FROM protocol_issuance_attempts WHERE id = ?",
            (attempt_id,),
        ).fetchone()

    def get_blocking_protocol_issuance_attempt(
        self,
        *,
        passport_device_id: str | None = None,
        intended_passport_device_id: str | None = None,
        protocol_version: str,
    ) -> sqlite3.Row | None:
        intended = intended_passport_device_id or passport_device_id
        if not intended:
            raise ValueError("intended passport identity is required")
        return self._conn.execute(
            """
            SELECT *
            FROM protocol_issuance_attempts
            WHERE intended_passport_device_id = ?
              AND protocol_version = ?
              AND state IN ('reserved','recovery_required')
            ORDER BY id DESC
            LIMIT 1
            """,
            (intended, protocol_version),
        ).fetchone()

    def list_protocol_issuance_attempts(
        self,
        *,
        passport_device_id: str,
        protocol_version: str | None = None,
    ) -> list[sqlite3.Row]:
        if protocol_version is None:
            return self._conn.execute(
                """
                SELECT *
            FROM protocol_issuance_attempts
            WHERE (passport_device_id = ? OR intended_passport_device_id = ?)
            ORDER BY id
            """,
                (passport_device_id, passport_device_id),
            ).fetchall()
        return self._conn.execute(
            """
            SELECT *
            FROM protocol_issuance_attempts
            WHERE (passport_device_id = ? OR intended_passport_device_id = ?)
              AND protocol_version = ?
            ORDER BY id
            """,
            (passport_device_id, passport_device_id, protocol_version),
        ).fetchall()

    def cancel_protocol_issuance_attempt(
        self, attempt_id: int, *, reason_code: str
    ) -> sqlite3.Row:
        with self.transaction():
            cursor = self._conn.execute(
                """
                UPDATE protocol_issuance_attempts
                SET state = 'cancelled',
                    reason_code = ?,
                    cancelled_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ? AND state = 'reserved'
                """,
                (reason_code, attempt_id),
            )
            if cursor.rowcount != 1:
                raise ValueError("issuance attempt is not reserved")
            attempt = self.get_protocol_issuance_attempt(attempt_id)
            assert attempt is not None
            return attempt

    def get_protocol_issuance_user_barrier(
        self, user_id: int
    ) -> sqlite3.Row | None:
        return self._conn.execute(
            "SELECT * FROM protocol_issuance_user_barriers WHERE user_id = ?",
            (user_id,),
        ).fetchone()

    def set_protocol_issuance_user_barrier(self, user_id: int, state: str) -> None:
        if state not in {"blocking", "blocked"}:
            raise ValueError("invalid protocol issuance barrier state")
        self._conn.execute(
            """
            INSERT INTO protocol_issuance_user_barriers(user_id, state)
            VALUES (?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                state = excluded.state,
                updated_at = CURRENT_TIMESTAMP
            """,
            (user_id, state),
        )
        self._commit()

    def delete_protocol_issuance_user_barrier(self, user_id: int) -> bool:
        cursor = self._conn.execute(
            "DELETE FROM protocol_issuance_user_barriers WHERE user_id = ?",
            (user_id,),
        )
        self._commit()
        return cursor.rowcount == 1

    def cancel_reserved_protocol_issuance_attempts_for_user(
        self, user_id: int, *, reason_code: str
    ) -> int:
        cursor = self._conn.execute(
            """
            UPDATE protocol_issuance_attempts
            SET state = 'cancelled',
                reason_code = ?,
                cancelled_at = CURRENT_TIMESTAMP,
                updated_at = CURRENT_TIMESTAMP
            WHERE owner_user_id = ? AND state = 'reserved'
            """,
            (reason_code, user_id),
        )
        self._commit()
        return int(cursor.rowcount)

    def list_recovery_protocol_issuance_attempts_for_user(
        self, user_id: int
    ) -> list[sqlite3.Row]:
        return self._conn.execute(
            """
            SELECT * FROM protocol_issuance_attempts
            WHERE owner_user_id = ? AND state = 'recovery_required'
            ORDER BY id
            """,
            (user_id,),
        ).fetchall()

    def reconcile_protocol_issuance_recovery(
        self, attempt_id: int, *, local_device_id: int, reason_code: str
    ) -> bool:
        cursor = self._conn.execute(
            """
            UPDATE protocol_issuance_attempts
            SET state = 'cancelled',
                reason_code = ?,
                cancelled_at = CURRENT_TIMESTAMP,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
              AND state = 'recovery_required'
              AND local_device_id = ?
            """,
            (reason_code, attempt_id, local_device_id),
        )
        self._commit()
        return cursor.rowcount == 1

    def create_protocol_issuance_execution_lease(self, attempt_id: int) -> object:
        if (
            self._transaction_depth != 1
            or self._active_outer_transaction_identity is None
        ):
            raise ValueError("execution lease requires phase-a outer transaction")
        attempt = self.get_protocol_issuance_attempt(attempt_id)
        if (
            attempt is None
            or str(attempt["state"]) != "recovery_required"
            or str(attempt["reason_code"]) != "issuer_in_progress"
        ):
            raise ValueError("execution lease requires issuer marker")
        lease = object()
        self._protocol_issuance_execution_leases[lease] = {
            "attempt_id": attempt_id,
            "owner_user_id": int(attempt["owner_user_id"]),
            "intended_passport_device_id": str(
                attempt["intended_passport_device_id"]
            ),
            "passport_device_id": attempt["passport_device_id"],
            "protocol_version": str(attempt["protocol_version"]),
            "created_transaction": self._active_outer_transaction_identity,
            "bound_transaction": None,
            "used": False,
        }
        return lease

    def bind_protocol_issuance_execution_lease(
        self, attempt_id: int, execution_lease: object
    ) -> sqlite3.Row:
        if (
            self._transaction_depth != 1
            or self._active_outer_transaction_identity is None
        ):
            raise ValueError("execution lease binding requires outer transaction")
        state = self._protocol_issuance_execution_leases.get(execution_lease)
        if state is None or int(state["attempt_id"]) != attempt_id:
            raise ValueError("invalid execution lease")
        if bool(state["used"]):
            raise ValueError("execution lease already used")
        if state["bound_transaction"] is not None:
            raise ValueError("execution lease is already bound")
        attempt = self.get_protocol_issuance_attempt(attempt_id)
        if attempt is None:
            raise LookupError("issuance attempt not found")
        if (
            str(attempt["state"]) != "recovery_required"
            or str(attempt["reason_code"]) != "issuer_in_progress"
            or int(attempt["owner_user_id"]) != int(state["owner_user_id"])
            or str(attempt["intended_passport_device_id"])
            != str(state["intended_passport_device_id"])
            or attempt["passport_device_id"] != state["passport_device_id"]
            or str(attempt["protocol_version"]) != str(state["protocol_version"])
        ):
            raise ValueError("issuance execution marker changed")
        owner = self.get_user(int(state["owner_user_id"]))
        if (
            str(owner["status"]) != "active"
            or self.get_protocol_issuance_user_barrier(int(state["owner_user_id"]))
            is not None
        ):
            raise ProtocolIssuanceExecutionBlocked("user_issuance_blocked")
        passport_device_id = state["passport_device_id"]
        intended_passport_device_id = str(state["intended_passport_device_id"])
        if passport_device_id is None:
            if self.get_device_passport(intended_passport_device_id) is not None:
                raise ProtocolIssuanceExecutionBlocked("passport_inactive")
        else:
            passport = self.get_device_passport(str(passport_device_id))
            if (
                str(passport_device_id) != intended_passport_device_id
                or passport is None
                or int(passport["owner_user_id"]) != int(state["owner_user_id"])
                or passport["revoked_at"] is not None
            ):
                raise ProtocolIssuanceExecutionBlocked("passport_inactive")
        state["bound_transaction"] = self._active_outer_transaction_identity
        return attempt

    def cancel_protocol_issuance_attempt_before_side_effect(
        self,
        attempt_id: int,
        *,
        reason_code: str,
        execution_lease: object,
    ) -> sqlite3.Row:
        if reason_code != "issuer_unavailable_before_side_effect":
            raise ValueError("invalid pre-side-effect cancellation reason")
        with self.transaction():
            lease_state = self._protocol_issuance_execution_leases.get(
                execution_lease
            )
            if (
                lease_state is None
                or int(lease_state["attempt_id"]) != attempt_id
            ):
                raise ValueError("invalid execution lease")
            if bool(lease_state["used"]):
                raise ValueError("execution lease already used")
            if (
                self._active_outer_transaction_identity is None
                or lease_state["bound_transaction"]
                is not self._active_outer_transaction_identity
            ):
                raise ValueError(
                    "execution lease is not bound to current outer transaction"
                )
            cursor = self._conn.execute(
                """
                UPDATE protocol_issuance_attempts
                SET state = 'cancelled',
                    reason_code = ?,
                    cancelled_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                  AND state = 'recovery_required'
                  AND reason_code = 'issuer_in_progress'
                """,
                (reason_code, attempt_id),
            )
            if cursor.rowcount != 1:
                raise ValueError("issuance execution marker changed")
            lease_state["used"] = True
            attempt = self.get_protocol_issuance_attempt(attempt_id)
            assert attempt is not None
            return attempt

    def complete_protocol_issuance_attempt(
        self,
        attempt_id: int,
        *,
        local_device_id: int,
        passport_device_id: str | None = None,
        execution_lease: object | None = None,
    ) -> sqlite3.Row:
        with self.transaction():
            current = self.get_protocol_issuance_attempt(attempt_id)
            if current is None:
                raise LookupError("issuance attempt not found")
            lease_state = (
                self._protocol_issuance_execution_leases.get(execution_lease)
                if execution_lease is not None
                else None
            )
            if lease_state is not None and bool(lease_state["used"]):
                raise ValueError("execution lease already used")
            completing_issuer_marker = (
                str(current["state"]) == "recovery_required"
                and str(current["reason_code"]) == "issuer_in_progress"
            )
            if completing_issuer_marker:
                if (
                    lease_state is None
                    or int(lease_state["attempt_id"]) != attempt_id
                ):
                    raise ValueError("issuer marker completion requires execution lease")
                if (
                    self._active_outer_transaction_identity is None
                    or lease_state["bound_transaction"]
                    is not self._active_outer_transaction_identity
                ):
                    raise ValueError(
                        "execution lease is not bound to current outer transaction"
                    )
            actual_passport = passport_device_id or current["passport_device_id"]
            if actual_passport is None:
                raise ValueError("completed issuance requires an actual passport")
            passport = self.get_device_passport(str(actual_passport))
            if (
                passport is None
                or int(passport["owner_user_id"]) != int(current["owner_user_id"])
                or passport["revoked_at"] is not None
                or self.get_user_device(
                    user_id=int(current["owner_user_id"]),
                    device_id=local_device_id,
                )
                is None
            ):
                raise ValueError("completed issuance owner graph is invalid")
            cursor = self._conn.execute(
                """
                UPDATE protocol_issuance_attempts
                SET state = 'completed',
                    passport_device_id = ?,
                    local_device_id = ?,
                    reason_code = 'issued',
                    completed_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                  AND (
                    state = 'reserved'
                    OR (state = 'recovery_required' AND reason_code = 'issuer_in_progress')
                  )
                """,
                (actual_passport, local_device_id, attempt_id),
            )
            if cursor.rowcount != 1:
                raise ValueError("issuance attempt is not reserved")
            if completing_issuer_marker:
                assert lease_state is not None
                lease_state["used"] = True
            attempt = self.get_protocol_issuance_attempt(attempt_id)
            assert attempt is not None
            return attempt

    def mark_protocol_issuance_attempt_recovery_required(
        self,
        attempt_id: int,
        *,
        local_device_id: int | None,
        reason_code: str,
        passport_device_id: str | None = None,
    ) -> sqlite3.Row:
        with self.transaction():
            current = self.get_protocol_issuance_attempt(attempt_id)
            if current is None:
                raise LookupError("issuance attempt not found")
            if str(current["state"]) == "recovery_required":
                if str(current["reason_code"]) != "issuer_in_progress":
                    return current
                cursor = self._conn.execute(
                    """
                    UPDATE protocol_issuance_attempts
                    SET passport_device_id = COALESCE(?, passport_device_id),
                        local_device_id = COALESCE(?, local_device_id),
                        reason_code = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                      AND state = 'recovery_required'
                      AND reason_code = 'issuer_in_progress'
                    """,
                    (
                        passport_device_id,
                        local_device_id,
                        reason_code,
                        attempt_id,
                    ),
                )
                if cursor.rowcount != 1:
                    raise ValueError("issuance recovery marker changed")
                attempt = self.get_protocol_issuance_attempt(attempt_id)
                assert attempt is not None
                return attempt
            cursor = self._conn.execute(
                """
                UPDATE protocol_issuance_attempts
                SET state = 'recovery_required',
                    passport_device_id = COALESCE(?, passport_device_id),
                    local_device_id = ?,
                    reason_code = ?,
                    recovery_required_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ? AND state = 'reserved'
                """,
                (passport_device_id, local_device_id, reason_code, attempt_id),
            )
            if cursor.rowcount != 1:
                raise ValueError("issuance attempt is not reserved")
            attempt = self.get_protocol_issuance_attempt(attempt_id)
            assert attempt is not None
            return attempt

    def create_device_protocol_profile(
        self,
        *,
        passport_device_id: str,
        protocol_version: str,
        local_device_id: int,
        lifecycle_state: str,
    ) -> int:
        cursor = self._conn.execute(
            """
            INSERT INTO device_protocol_profiles (
                passport_device_id,
                protocol_version,
                local_device_id,
                lifecycle_state
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                passport_device_id,
                protocol_version,
                local_device_id,
                lifecycle_state,
            ),
        )
        self._commit()
        return int(cursor.lastrowid)

    def get_device_protocol_profile(
        self,
        *,
        passport_device_id: str,
        protocol_version: str,
    ) -> sqlite3.Row | None:
        return self._conn.execute(
            """
            SELECT *
            FROM device_protocol_profiles
            WHERE passport_device_id = ?
              AND protocol_version = ?
            """,
            (passport_device_id, protocol_version),
        ).fetchone()

    def get_device_protocol_profile_by_id(
        self,
        profile_id: int,
    ) -> sqlite3.Row | None:
        return self._conn.execute(
            "SELECT * FROM device_protocol_profiles WHERE id = ?",
            (profile_id,),
        ).fetchone()

    def get_device_protocol_profile_by_local_device_id(
        self,
        local_device_id: int,
    ) -> sqlite3.Row | None:
        return self._conn.execute(
            "SELECT * FROM device_protocol_profiles WHERE local_device_id = ?",
            (local_device_id,),
        ).fetchone()

    def get_latest_protocol_profile_retirement(
        self,
        local_device_id: int,
    ) -> sqlite3.Row | None:
        return self._conn.execute(
            """
            SELECT *
            FROM protocol_config_events
            WHERE local_device_id = ?
              AND event_type IN (
                  'protocol_profile_retired',
                  'compromise_reissue_revoked'
              )
            ORDER BY id DESC
            LIMIT 1
            """,
            (local_device_id,),
        ).fetchone()

    def update_device_protocol_profile(
        self,
        *,
        profile_id: int,
        lifecycle_state: str,
        replacement_device_id: int | None,
    ) -> None:
        self._conn.execute(
            """
            UPDATE device_protocol_profiles
            SET lifecycle_state = ?,
                replacement_device_id = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (lifecycle_state, replacement_device_id, profile_id),
        )
        self._commit()

    def transition_device_protocol_profile(
        self,
        *,
        profile_id: int,
        expected_lifecycle_state: str,
        expected_local_device_id: int,
        expected_replacement_device_id: int | None,
        lifecycle_state: str,
        local_device_id: int,
        replacement_device_id: int | None,
    ) -> bool:
        cursor = self._conn.execute(
            """
            UPDATE device_protocol_profiles
            SET lifecycle_state = ?,
                local_device_id = ?,
                replacement_device_id = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
              AND lifecycle_state = ?
              AND local_device_id = ?
              AND replacement_device_id IS ?
            """,
            (
                lifecycle_state,
                local_device_id,
                replacement_device_id,
                profile_id,
                expected_lifecycle_state,
                expected_local_device_id,
                expected_replacement_device_id,
            ),
        )
        self._commit()
        return cursor.rowcount == 1

    def append_protocol_config_event(
        self,
        *,
        event_type: str,
        actor_kind: str,
        actor_id: int,
        reason: str,
        passport_device_id: str | None,
        protocol_version: str | None,
        local_device_id: int | None,
        metadata: dict[str, object],
    ) -> int:
        cursor = self._conn.execute(
            """
            INSERT INTO protocol_config_events (
                event_type,
                actor_kind,
                actor_id,
                reason,
                passport_device_id,
                protocol_version,
                local_device_id,
                metadata_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_type,
                actor_kind,
                actor_id,
                reason,
                passport_device_id,
                protocol_version,
                local_device_id,
                json.dumps(
                    metadata,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            ),
        )
        self._commit()
        return int(cursor.lastrowid)

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
        max_devices: int | None = None,
        price: int = 0,
        currency: str = "RUB",
        is_free: bool = True,
        is_active: bool = True,
    ) -> None:
        if max_devices is not None and max_devices <= 0:
            raise ValueError("max_devices must be positive when configured")
        self._conn.execute(
            """
            INSERT INTO plans (
                id,
                name,
                duration_days,
                max_devices,
                price,
                currency,
                is_free,
                is_active
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                name = excluded.name,
                duration_days = excluded.duration_days,
                max_devices = COALESCE(excluded.max_devices, plans.max_devices),
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
                max_devices,
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

    def list_plans_for_admin(self) -> list[sqlite3.Row]:
        return self._conn.execute(
            """
            SELECT *
            FROM plans
            ORDER BY is_active DESC, duration_days ASC, id ASC
            """
        ).fetchall()

    def set_plan_device_quota(
        self,
        plan_id: str,
        max_devices: int | None,
    ) -> None:
        self.get_plan(plan_id)
        if max_devices is not None and max_devices <= 0:
            raise ValueError("max_devices must be positive when configured")
        self._conn.execute(
            """
            UPDATE plans
            SET max_devices = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (max_devices, plan_id),
        )
        self._commit()

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
        duration_days: int | None,
        expires_at: str | None = None,
        expiry_policy: str = "duration",
        vpn_ip: str,
        peer_public_key: str,
        peer_private_key_encrypted: str,
        preshared_key_encrypted: str,
        config_version: str,
        config_material_status: str = "available",
        assignment_mode: str = DEDICATED_DEVICE,
        config_fingerprint: str | None = None,
        protocol_version: str | None = None,
        runtime_instance_id: str | None = None,
        compatibility_evidence_id: str | None = None,
        client_identity_evidence_status: str | None = None,
    ) -> int:
        assignment_mode = validate_config_assignment_mode(assignment_mode)
        if expiry_policy == "duration":
            if (
                isinstance(duration_days, bool)
                or not isinstance(duration_days, int)
                or duration_days <= 0
                or expires_at is not None
            ):
                raise ValueError("duration expiry requires positive duration_days")
        elif expiry_policy == "absolute":
            if duration_days is not None or not expires_at:
                raise ValueError("absolute expiry requires expires_at")
        elif expiry_policy == "indefinite":
            if duration_days is not None or expires_at is not None:
                raise ValueError("indefinite expiry cannot contain a deadline")
        else:
            raise ValueError("unsupported access expiry policy")
        cursor = self._conn.execute(
            """
            INSERT INTO devices (
                user_id,
                server_id,
                name,
                activated_at,
                expires_at,
                duration_days,
                expiry_policy,
                vpn_ip,
                peer_public_key,
                peer_private_key_encrypted,
                preshared_key_encrypted,
                config_version,
                config_material_status,
                assignment_mode,
                config_fingerprint,
                protocol_version,
                runtime_instance_id,
                compatibility_evidence_id,
                client_identity_evidence_status
            )
            VALUES (
                ?,
                ?,
                ?,
                CURRENT_TIMESTAMP,
                CASE
                    WHEN ? = 'duration' THEN datetime(CURRENT_TIMESTAMP, ?)
                    ELSE ?
                END,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
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
                expiry_policy,
                f"+{duration_days} days" if duration_days is not None else None,
                expires_at,
                duration_days,
                expiry_policy,
                vpn_ip,
                peer_public_key,
                peer_private_key_encrypted,
                preshared_key_encrypted,
                config_version,
                config_material_status,
                assignment_mode,
                config_fingerprint,
                protocol_version,
                runtime_instance_id,
                compatibility_evidence_id,
                client_identity_evidence_status,
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

    def create_device_passport(
        self,
        *,
        device_id: str,
        owner_user_id: int,
        local_device_id: int | None,
        platform: str,
        official_client_type: str,
        client_version: str | None,
        import_method: str,
        config_schema_version: str,
        config_fingerprint: str,
        last_seen_at: str | None,
        acceptance_evidence: dict[str, Any] | None,
        protocol_version: str | None = None,
        runtime_instance_id: str | None = None,
        client_identity_evidence_status: str | None = None,
        compatibility_evidence_id: str | None = None,
    ) -> None:
        if not device_id.strip():
            raise ValueError("device_id is required")
        if local_device_id is not None:
            local_device = self.get_user_device(
                user_id=owner_user_id,
                device_id=local_device_id,
            )
            if local_device is None:
                raise ValueError("local device does not belong to passport owner")

        self._conn.execute(
            """
            INSERT INTO device_passports (
                device_id,
                local_device_id,
                owner_user_id,
                platform,
                official_client_type,
                client_version,
                import_method,
                config_schema_version,
                config_fingerprint,
                last_seen_at,
                acceptance_evidence_json,
                protocol_version,
                runtime_instance_id,
                client_identity_evidence_status,
                compatibility_evidence_id
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                device_id,
                local_device_id,
                owner_user_id,
                platform,
                official_client_type,
                client_version,
                import_method,
                config_schema_version,
                config_fingerprint,
                last_seen_at,
                (
                    json.dumps(acceptance_evidence, sort_keys=True)
                    if acceptance_evidence is not None
                    else None
                ),
                protocol_version,
                runtime_instance_id,
                client_identity_evidence_status,
                compatibility_evidence_id,
            ),
        )
        self._commit()

    def get_device_passport(self, device_id: str) -> sqlite3.Row | None:
        return self._conn.execute(
            """
            SELECT
                device_id,
                local_device_id,
                owner_user_id,
                platform,
                official_client_type,
                client_version,
                import_method,
                config_schema_version,
                config_fingerprint,
                last_seen_at,
                acceptance_evidence_json,
                protocol_version,
                runtime_instance_id,
                client_identity_evidence_status,
                compatibility_evidence_id,
                revoked_at,
                revoke_reason,
                created_at,
                updated_at
            FROM device_passports
            WHERE device_id = ?
            """,
            (device_id,),
        ).fetchone()

    def get_device_passport_by_local_device_id(
        self,
        local_device_id: int,
    ) -> sqlite3.Row | None:
        return self._conn.execute(
            """
            SELECT device_id
            FROM device_passports
            WHERE local_device_id = ?
            """,
            (local_device_id,),
        ).fetchone()

    def list_device_passports_for_owner(
        self,
        owner_user_id: int,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[sqlite3.Row]:
        if offset < 0:
            raise ValueError("device passport offset must not be negative")
        return self._conn.execute(
            """
            SELECT
                device_id,
                local_device_id,
                owner_user_id,
                platform,
                official_client_type,
                client_version,
                import_method,
                config_schema_version,
                config_fingerprint,
                last_seen_at,
                acceptance_evidence_json,
                protocol_version,
                runtime_instance_id,
                client_identity_evidence_status,
                compatibility_evidence_id,
                revoked_at,
                revoke_reason,
                created_at,
                updated_at
            FROM device_passports
            WHERE owner_user_id = ?
            ORDER BY created_at DESC, device_id DESC
            LIMIT ? OFFSET ?
            """,
            (owner_user_id, limit, offset),
        ).fetchall()

    def list_device_passports(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[sqlite3.Row]:
        if not 1 <= limit <= 100:
            raise ValueError("device passport limit must be between 1 and 100")
        if offset < 0:
            raise ValueError("device passport offset must not be negative")
        return self._conn.execute(
            """
            SELECT
                device_id,
                local_device_id,
                owner_user_id,
                platform,
                official_client_type,
                client_version,
                import_method,
                config_schema_version,
                config_fingerprint,
                last_seen_at,
                acceptance_evidence_json,
                protocol_version,
                runtime_instance_id,
                client_identity_evidence_status,
                compatibility_evidence_id,
                revoked_at,
                revoke_reason,
                created_at,
                updated_at
            FROM device_passports
            ORDER BY updated_at DESC, device_id ASC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        ).fetchall()

    def update_device_passport_observation(
        self,
        *,
        device_id: str,
        last_seen_at: str,
        acceptance_evidence: dict[str, Any] | None,
    ) -> bool:
        cursor = self._conn.execute(
            """
            UPDATE device_passports
            SET last_seen_at = ?,
                acceptance_evidence_json = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE device_id = ?
              AND revoked_at IS NULL
            """,
            (
                last_seen_at,
                (
                    json.dumps(acceptance_evidence, sort_keys=True)
                    if acceptance_evidence is not None
                    else None
                ),
                device_id,
            ),
        )
        self._commit()
        return cursor.rowcount > 0

    def attach_device_passport_to_local_device(
        self,
        *,
        passport_device_id: str,
        local_device_id: int,
    ) -> bool:
        passport = self.get_device_passport(passport_device_id)
        if passport is None:
            raise LookupError("device passport not found")
        local_device = self.get_user_device(
            user_id=int(passport["owner_user_id"]),
            device_id=local_device_id,
        )
        if local_device is None:
            raise ValueError("local device does not belong to passport owner")
        cursor = self._conn.execute(
            """
            UPDATE device_passports
            SET local_device_id = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE device_id = ?
              AND revoked_at IS NULL
            """,
            (local_device_id, passport_device_id),
        )
        self._commit()
        return cursor.rowcount > 0

    def cascade_revoke_device_access(
        self,
        *,
        local_device_id: int,
        revoked_at: str,
        reason: str,
    ) -> dict[str, int | str | None]:
        device = self.get_device(local_device_id)
        passport = self.get_device_passport_by_local_device_id(local_device_id)
        passport_device_id = (
            str(passport["device_id"]) if passport is not None else None
        )

        enrollment_ticket_count = 0
        if passport_device_id is not None:
            enrollment_ticket_count = int(
                self._conn.execute(
                    """
                    UPDATE device_enrollment_tickets
                    SET revoked_at = COALESCE(revoked_at, ?),
                        revoke_reason = COALESCE(revoke_reason, ?)
                    WHERE claimed_device_id = ?
                      AND revoked_at IS NULL
                    """,
                    (revoked_at, reason, passport_device_id),
                ).rowcount
            )
            self._conn.execute(
                """
                UPDATE device_passports
                SET revoked_at = COALESCE(revoked_at, ?),
                    revoke_reason = COALESCE(revoke_reason, ?),
                    updated_at = CURRENT_TIMESTAMP
                WHERE device_id = ?
                """,
                (revoked_at, reason, passport_device_id),
            )

        delivery_link_count = int(
            self._conn.execute(
                """
                UPDATE email_recovery_tokens
                SET used_at = COALESCE(used_at, ?)
                WHERE device_id = ?
                  AND used_at IS NULL
                """,
                (revoked_at, local_device_id),
            ).rowcount
        )
        assignment_count = int(
            self._conn.execute(
                """
                UPDATE orders
                SET device_id = NULL
                WHERE device_id = ?
                """,
                (local_device_id,),
            ).rowcount
        )
        device_count = int(
            self._conn.execute(
                """
                UPDATE devices
                SET status = 'revoked',
                    revoked_at = COALESCE(revoked_at, ?),
                    revoke_reason = COALESCE(revoke_reason, ?)
                WHERE id = ?
                  AND status != 'revoked'
                """,
                (revoked_at, reason, local_device_id),
            ).rowcount
        )
        self._commit()
        return {
            "local_device_id": int(device["id"]),
            "passport_device_id": passport_device_id,
            "device_rows_revoked": device_count,
            "enrollment_tickets_revoked": enrollment_ticket_count,
            "delivery_links_closed": delivery_link_count,
            "assignments_closed": assignment_count,
        }

    def create_device_enrollment_ticket(
        self,
        *,
        ticket_id: str,
        user_id: int,
        token_hash: str,
        token_prefix: str,
        platform: str,
        config_schema_version: str,
        expires_at: str,
    ) -> None:
        self._conn.execute(
            """
            INSERT INTO device_enrollment_tickets (
                id,
                user_id,
                token_hash,
                token_prefix,
                platform,
                config_schema_version,
                expires_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ticket_id,
                user_id,
                token_hash,
                token_prefix,
                platform,
                config_schema_version,
                expires_at,
            ),
        )
        self._commit()

    def get_device_enrollment_ticket(self, ticket_id: str) -> sqlite3.Row | None:
        return self._conn.execute(
            """
            SELECT
                id,
                user_id,
                token_prefix,
                platform,
                config_schema_version,
                single_use,
                expires_at,
                revoked_at,
                revoke_reason,
                claimed_at,
                claimed_device_id,
                created_at
            FROM device_enrollment_tickets
            WHERE id = ?
            """,
            (ticket_id,),
        ).fetchone()

    def list_device_enrollment_tickets(
        self,
        *,
        user_id: int | None = None,
        limit: int = 100,
    ) -> list[sqlite3.Row]:
        where = "WHERE user_id = ?" if user_id is not None else ""
        params: tuple[Any, ...] = (user_id, limit) if user_id is not None else (limit,)
        return self._conn.execute(
            f"""
            SELECT
                id,
                user_id,
                token_prefix,
                platform,
                config_schema_version,
                single_use,
                expires_at,
                revoked_at,
                revoke_reason,
                claimed_at,
                claimed_device_id,
                created_at
            FROM device_enrollment_tickets
            {where}
            ORDER BY created_at DESC, id DESC
            LIMIT ?
            """,
            params,
        ).fetchall()

    def get_enrollment_ticket_by_claimed_device_id(
        self,
        passport_device_id: str,
    ) -> sqlite3.Row | None:
        return self._conn.execute(
            """
            SELECT id
            FROM device_enrollment_tickets
            WHERE claimed_device_id = ?
            ORDER BY claimed_at DESC, id DESC
            LIMIT 1
            """,
            (passport_device_id,),
        ).fetchone()

    def record_device_lifecycle_event(
        self,
        *,
        ticket_id: str | None,
        passport_device_id: str | None,
        stage: str,
        status: str,
        occurred_at: str,
        duration_ms: int,
        failure_stage: str | None,
        evidence: dict[str, Any],
    ) -> int:
        cursor = self._conn.execute(
            """
            INSERT INTO device_lifecycle_events (
                ticket_id,
                passport_device_id,
                stage,
                status,
                occurred_at,
                duration_ms,
                failure_stage,
                evidence_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ticket_id,
                passport_device_id,
                stage,
                status,
                occurred_at,
                duration_ms,
                failure_stage,
                json.dumps(evidence, sort_keys=True),
            ),
        )
        self._commit()
        return int(cursor.lastrowid)

    def list_device_lifecycle_events(
        self,
        *,
        ticket_id: str | None = None,
        passport_device_id: str | None = None,
    ) -> list[sqlite3.Row]:
        if ticket_id is None and passport_device_id is None:
            raise ValueError("ticket_id or passport_device_id is required")
        predicates: list[str] = []
        params: list[Any] = []
        if ticket_id is not None:
            predicates.append("ticket_id = ?")
            params.append(ticket_id)
        if passport_device_id is not None:
            predicates.append("passport_device_id = ?")
            params.append(passport_device_id)
        where = " OR ".join(predicates)
        return self._conn.execute(
            f"""
            SELECT
                id,
                ticket_id,
                passport_device_id,
                stage,
                status,
                occurred_at,
                duration_ms,
                failure_stage,
                evidence_json,
                created_at
            FROM device_lifecycle_events
            WHERE {where}
            ORDER BY occurred_at ASC, id ASC
            """,
            tuple(params),
        ).fetchall()

    def revoke_device_enrollment_ticket(
        self,
        *,
        ticket_id: str,
        revoked_at: str,
        reason: str,
    ) -> bool:
        cursor = self._conn.execute(
            """
            UPDATE device_enrollment_tickets
            SET revoked_at = ?,
                revoke_reason = ?
            WHERE id = ?
              AND revoked_at IS NULL
            """,
            (revoked_at, reason, ticket_id),
        )
        self._commit()
        return cursor.rowcount > 0

    def is_device_enrollment_claim_replay(
        self,
        *,
        token_hash: str,
        idempotency_hash: str,
    ) -> bool:
        row = self._conn.execute(
            """
            SELECT 1
            FROM device_enrollment_tickets
            WHERE token_hash = ?
              AND claim_idempotency_hash = ?
              AND claimed_device_id IS NOT NULL
            """,
            (token_hash, idempotency_hash),
        ).fetchone()
        return row is not None

    def claim_device_enrollment_ticket(
        self,
        *,
        token_hash: str,
        idempotency_hash: str,
        now: str,
        claimed_at: str,
        claimed_device_id: str,
        official_client_type: str,
        client_version: str | None,
        import_method: str,
        config_fingerprint: str,
        acceptance_evidence: dict[str, Any],
    ) -> sqlite3.Row | None:
        with self.transaction():
            cursor = self._conn.execute(
                """
                UPDATE device_enrollment_tickets
                SET claimed_at = ?,
                    claimed_device_id = ?,
                    claim_idempotency_hash = ?
                WHERE token_hash = ?
                  AND revoked_at IS NULL
                  AND claimed_at IS NULL
                  AND expires_at > ?
                  AND single_use = 1
                """,
                (
                    claimed_at,
                    claimed_device_id,
                    idempotency_hash,
                    token_hash,
                    now,
                ),
            )
            if cursor.rowcount == 1:
                ticket = self._conn.execute(
                    """
                    SELECT id, user_id, platform, config_schema_version
                    FROM device_enrollment_tickets
                    WHERE token_hash = ?
                    """,
                    (token_hash,),
                ).fetchone()
                if ticket is None:
                    raise RuntimeError("claimed enrollment ticket disappeared")
                self.create_device_passport(
                    device_id=claimed_device_id,
                    owner_user_id=int(ticket["user_id"]),
                    local_device_id=None,
                    platform=str(ticket["platform"]),
                    official_client_type=official_client_type,
                    client_version=client_version,
                    import_method=import_method,
                    config_schema_version=str(ticket["config_schema_version"]),
                    config_fingerprint=config_fingerprint,
                    last_seen_at=claimed_at,
                    acceptance_evidence=acceptance_evidence,
                )
                ticket_id = str(ticket["id"])
            else:
                replay = self._conn.execute(
                    """
                    SELECT id
                    FROM device_enrollment_tickets
                    WHERE token_hash = ?
                      AND claim_idempotency_hash = ?
                      AND claimed_at IS NOT NULL
                      AND claimed_device_id IS NOT NULL
                    """,
                    (token_hash, idempotency_hash),
                ).fetchone()
                if replay is None:
                    return None
                ticket_id = str(replay["id"])

            return self.get_device_enrollment_ticket(ticket_id)

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

    def count_active_physical_devices(self, user_id: int) -> int:
        row = self._conn.execute(
            """
            WITH unrevoked_passports AS (
                SELECT device_id, local_device_id
                FROM device_passports
                WHERE owner_user_id = ?
                  AND revoked_at IS NULL
            ),
            represented_devices AS (
                SELECT
                    passports.device_id AS passport_device_id,
                    passports.local_device_id
                FROM unrevoked_passports AS passports
                WHERE passports.local_device_id IS NOT NULL
                UNION
                SELECT
                    passports.device_id AS passport_device_id,
                    profiles.local_device_id
                FROM device_protocol_profiles AS profiles
                JOIN unrevoked_passports AS passports
                  ON passports.device_id = profiles.passport_device_id
            )
            SELECT
                (
                    SELECT COUNT(DISTINCT passport_device_id)
                    FROM represented_devices
                )
                + COUNT(*) AS physical_device_count
            FROM devices AS candidate
            WHERE candidate.user_id = ?
              AND candidate.status = 'active'
              AND NOT EXISTS (
                  SELECT 1
                  FROM represented_devices AS represented
                  WHERE represented.local_device_id = candidate.id
              )
            """,
            (user_id, user_id),
        ).fetchone()
        return int(row["physical_device_count"])

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

    def list_allocated_ips_for_runtime(
        self,
        server_id: int,
        runtime_instance_id: str,
    ) -> list[str]:
        rows = self._conn.execute(
            """
            SELECT vpn_ip
            FROM devices
            WHERE server_id = ?
              AND runtime_instance_id = ?
              AND status IN ('pending', 'active', 'disabled')
            ORDER BY id
            """,
            (server_id, runtime_instance_id),
        ).fetchall()
        return [str(row["vpn_ip"]) for row in rows]

    def get_server(self, server_id: int) -> sqlite3.Row:
        return self._fetch_one("SELECT * FROM servers WHERE id = ?", (server_id,))

    def get_server_by_name(self, name: str) -> sqlite3.Row:
        return self._fetch_one("SELECT * FROM servers WHERE name = ?", (name,))

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

    def get_admin_config_issuance_request(
        self,
        *,
        request_id: str,
    ) -> sqlite3.Row | None:
        return self._conn.execute(
            """
            SELECT *
            FROM admin_config_issuance_requests
            WHERE request_id = ?
            """,
            (request_id,),
        ).fetchone()

    def create_admin_config_issuance_request(
        self,
        *,
        request_id: str,
        request_fingerprint: str,
        item_count: int,
    ) -> sqlite3.Row:
        self._conn.execute(
            """
            INSERT INTO admin_config_issuance_requests (
                request_id,
                request_fingerprint,
                item_count
            )
            VALUES (?, ?, ?)
            """,
            (request_id, request_fingerprint, item_count),
        )
        self._commit()
        request = self.get_admin_config_issuance_request(request_id=request_id)
        assert request is not None
        return request

    def get_admin_config_issuance_receipt(
        self,
        *,
        request_id: str,
        item_index: int,
    ) -> sqlite3.Row | None:
        return self._conn.execute(
            """
            SELECT *
            FROM admin_config_issuance_receipts
            WHERE request_id = ? AND item_index = ?
            """,
            (request_id, item_index),
        ).fetchone()

    def get_completed_admin_config_issuance_receipt_by_device_id(
        self,
        *,
        device_id: int,
    ) -> sqlite3.Row | None:
        rows = self._conn.execute(
            """
            SELECT receipt.*
            FROM admin_config_issuance_receipts AS receipt
            INNER JOIN admin_config_issuance_requests AS request
                ON request.request_id = receipt.request_id
            WHERE receipt.device_id = ?
              AND receipt.status = 'completed'
              AND length(trim(receipt.config_filename)) > 0
            ORDER BY receipt.id DESC
            LIMIT 2
            """,
            (device_id,),
        ).fetchall()
        if len(rows) != 1:
            return None
        return rows[0]

    def list_completed_admin_config_filenames_for_recipient(
        self, recipient_user_id: int
    ) -> list[str]:
        return [
            str(row["config_filename"])
            for row in self._conn.execute(
                """
                SELECT config_filename
                FROM admin_config_issuance_receipts
                WHERE recipient_user_id = ?
                  AND status = 'completed'
                  AND length(trim(config_filename)) > 0
                """,
                (recipient_user_id,),
            ).fetchall()
        ]

    def create_admin_config_issuance_receipt(
        self,
        *,
        request_id: str,
        item_index: int,
        item_fingerprint: str,
        recipient_user_id: int,
        assignment_mode: str = "dedicated_device",
        slot_sequence: int = 1,
        expiry_policy: str = "duration",
        config_version: str | None = None,
        protocol_version: str | None = None,
        runtime_instance_id: str | None = None,
        compatibility_evidence_id: str | None = None,
        client_application: str | None = None,
        client_platform: str | None = None,
        client_version: str | None = None,
        client_build: str | None = None,
    ) -> sqlite3.Row:
        self._conn.execute(
            """
            INSERT INTO admin_config_issuance_receipts (
                request_id,
                item_index,
                item_fingerprint,
                recipient_user_id,
                assignment_mode,
                slot_sequence,
                expiry_policy,
                config_version,
                protocol_version,
                runtime_instance_id,
                compatibility_evidence_id,
                client_application,
                client_platform,
                client_version,
                client_build,
                status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'started')
            """,
            (
                request_id,
                item_index,
                item_fingerprint,
                recipient_user_id,
                assignment_mode,
                slot_sequence,
                expiry_policy,
                config_version,
                protocol_version,
                runtime_instance_id,
                compatibility_evidence_id,
                client_application,
                client_platform,
                client_version,
                client_build,
            ),
        )
        self._commit()
        receipt = self.get_admin_config_issuance_receipt(
            request_id=request_id,
            item_index=item_index,
        )
        assert receipt is not None
        return receipt

    def list_admin_config_issuance_receipts(
        self, request_id: str
    ) -> list[sqlite3.Row]:
        return self._conn.execute(
            """
            SELECT *
            FROM admin_config_issuance_receipts
            WHERE request_id = ?
            ORDER BY item_index
            LIMIT 100
            """,
            (request_id,),
        ).fetchall()

    def complete_admin_config_issuance_receipt(
        self,
        *,
        request_id: str,
        item_index: int,
        device_id: int,
        passport_device_id: str | None,
        config_filename: str,
    ) -> sqlite3.Row:
        self._conn.execute(
            """
            UPDATE admin_config_issuance_receipts
            SET device_id = ?,
                passport_device_id = ?,
                status = 'completed',
                config_filename = ?,
                error_code = NULL,
                updated_at = CURRENT_TIMESTAMP
            WHERE request_id = ? AND item_index = ? AND status = 'started'
            """,
            (
                device_id,
                passport_device_id,
                config_filename,
                request_id,
                item_index,
            ),
        )
        self._commit()
        receipt = self.get_admin_config_issuance_receipt(
            request_id=request_id,
            item_index=item_index,
        )
        assert receipt is not None
        return receipt

    def fail_admin_config_issuance_receipt(
        self,
        *,
        request_id: str,
        item_index: int,
        error_code: str,
        device_id: int | None = None,
        passport_device_id: str | None = None,
        config_filename: str | None = None,
    ) -> sqlite3.Row:
        self._conn.execute(
            """
            UPDATE admin_config_issuance_receipts
            SET device_id = ?,
                passport_device_id = ?,
                status = 'partial_failure',
                config_filename = ?,
                error_code = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE request_id = ? AND item_index = ? AND status = 'started'
            """,
            (
                device_id,
                passport_device_id,
                config_filename,
                error_code,
                request_id,
                item_index,
            ),
        )
        self._commit()
        receipt = self.get_admin_config_issuance_receipt(
            request_id=request_id,
            item_index=item_index,
        )
        assert receipt is not None
        return receipt

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

    def get_access_slot_assignment_request(self, request_id: str):
        return self._conn.execute(
            "SELECT * FROM access_slot_assignment_requests WHERE request_id = ?",
            (request_id,),
        ).fetchone()

    def get_access_slot_assignment_by_device(self, local_device_id: int):
        return self._conn.execute(
            "SELECT * FROM access_slot_assignment_requests WHERE local_device_id = ?",
            (local_device_id,),
        ).fetchone()

    def complete_access_slot_assignment(
        self,
        *,
        request_id: str,
        request_fingerprint: str,
        local_device_id: int,
        passport_device_id: str,
        display_name: str,
    ) -> None:
        cursor = self._conn.execute(
            """
            UPDATE devices
            SET assignment_mode = 'dedicated_device', name = ?
            WHERE id = ?
              AND assignment_mode = 'recipient_unassigned'
              AND status != 'revoked'
            """,
            (display_name, local_device_id),
        )
        if cursor.rowcount != 1:
            raise ValueError("access slot is already assigned or revoked")
        self._conn.execute(
            """
            INSERT INTO access_slot_assignment_requests (
                request_id, request_fingerprint, local_device_id, passport_device_id
            ) VALUES (?, ?, ?, ?)
            """,
            (request_id, request_fingerprint, local_device_id, passport_device_id),
        )
        self._commit()

    def disable_device(
        self,
        device_id: int,
        *,
        reason: str,
        disabled_at: str,
    ) -> bool:
        cursor = self._conn.execute(
            """
            UPDATE devices
            SET status = 'disabled', revoked_at = ?, revoke_reason = ?
            WHERE id = ? AND status IN ('pending', 'active')
            """,
            (disabled_at, reason, device_id),
        )
        self._commit()
        return cursor.rowcount > 0

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
                devices.expiry_policy,
                devices.vpn_ip,
                devices.config_material_status,
                devices.assignment_mode,
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
                devices.assignment_mode,
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
                devices.assignment_mode,
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
                users.operator_label,
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
                users.operator_label,
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
                devices.assignment_mode,
                users.telegram_id,
                users.operator_label,
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
                devices.assignment_mode,
                users.id AS user_id,
                users.telegram_id,
                users.operator_label,
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
                devices.assignment_mode,
                devices.protocol_version,
                devices.runtime_instance_id,
                devices.compatibility_evidence_id,
                devices.client_identity_evidence_status,
                vpn_runtime_instances.lifecycle_state AS runtime_state,
                users.telegram_id,
                users.operator_label,
                users.username,
                users.first_name,
                users.last_name
            FROM devices
            JOIN users ON users.id = devices.user_id
            LEFT JOIN vpn_runtime_instances
                ON vpn_runtime_instances.runtime_instance_id = devices.runtime_instance_id
            WHERE devices.server_id = ?
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
              AND status = 'active'
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


def _validate_phase13_text(
    field_name: str, value: str, *, max_length: int = 128
) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{field_name} must be exact non-blank text")
    if len(value) > max_length or any(ord(char) < 32 for char in value):
        raise ValueError(f"{field_name} must be bounded one-line text")
    return value


def _validate_optional_phase13_text(
    field_name: str, value: str | None, *, max_length: int = 128
) -> str | None:
    if value is None:
        return None
    return _validate_phase13_text(field_name, value, max_length=max_length)


def _validate_phase13_protocol(protocol_version: str) -> None:
    if protocol_version not in PHASE13_PROTOCOL_VERSIONS:
        raise ValueError("unsupported protocol_version")


def _validate_phase13_timestamp(field_name: str, value: str) -> None:
    value = _validate_phase13_text(field_name, value, max_length=64)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field_name} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field_name} must include a timezone")
