"""Deterministic read-only preview for the Phase 13 bot/web migration."""

from __future__ import annotations

from contextlib import ExitStack, contextmanager
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re
import sqlite3
from typing import Iterator, Mapping, Sequence


_MIGRATION_ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_IDENTIFIER_PATTERN = re.compile(r"[a-z_][a-z0-9_]*")


@dataclass(frozen=True)
class MigrationPolicy:
    allowed_tables: frozenset[str]
    excluded_tables: frozenset[str]
    preserved_target_tables: frozenset[str]

    @classmethod
    def default(cls) -> "MigrationPolicy":
        return cls(
            allowed_tables=frozenset(
                {"users", "plans", "orders", "devices", "message_templates"}
            ),
            excluded_tables=frozenset(
                {
                    "access_tokens",
                    "admin_actions",
                    "admin_sessions",
                    "api_tokens",
                    "device_enrollment_tickets",
                    "device_traffic_snapshots",
                    "email_recovery_tokens",
                    "ignored_remote_peers",
                    "server_health_checks",
                    "servers",
                    "sessions",
                }
            ),
            preserved_target_tables=frozenset(
                {
                    "access_slot_assignment_requests",
                    "admin_config_issuance_receipts",
                    "admin_config_issuance_requests",
                    "device_lifecycle_events",
                    "device_passports",
                }
            ),
        )


@dataclass(frozen=True)
class BotWebMigrationPreview:
    migration_id: str
    source_schema_sha256: str
    source_counts_sha256: str
    source_allowed_rows_sha256: str
    target_schema_sha256: str
    target_counts_sha256: str
    target_allowed_rows_sha256: str
    users_create: int
    users_preserve: int
    users_update: int
    target_privileged_users_preserved: int
    plans_create: int
    plans_preserve: int
    orders_create: int
    message_templates_create: int
    message_templates_preserve: int
    legacy_devices_external_only: int
    legacy_devices_revoked: int
    spain_devices_preserved: int
    spain_passports_preserved: int
    spain_issuance_requests_preserved: int
    spain_issuance_receipts_preserved: int
    spain_lifecycle_events_preserved: int
    api_tokens_reissue_required: int
    usable_secret_records_imported: int
    excluded_counts: tuple[tuple[str, int], ...]
    invariant_hashes: tuple[tuple[str, str], ...]
    stop_reasons: tuple[str, ...]
    conflict_count: int
    apply_allowed: bool

    def canonical_bytes(self) -> bytes:
        payload = asdict(self)
        payload["excluded_counts"] = dict(self.excluded_counts)
        payload["invariant_hashes"] = dict(self.invariant_hashes)
        return (
            json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


class MigrationPreconditionError(RuntimeError):
    """The supplied preview no longer describes the input databases."""


class MigrationApplyError(RuntimeError):
    """The copy-only transaction failed and its output was removed."""


@dataclass(frozen=True)
class BotWebMigrationResult:
    migration_id: str
    preview_sha256: str
    created_rows: int
    imported_users: int
    imported_plans: int
    imported_orders: int
    imported_legacy_devices: int
    imported_message_templates: int
    usable_secret_records_imported: int
    integrity_ok: bool
    foreign_key_issues: int
    spain_device_fingerprint_unchanged: bool
    spain_passport_fingerprint_unchanged: bool
    spain_issuance_fingerprints_unchanged: bool
    spain_lifecycle_fingerprint_unchanged: bool
    spain_server_fingerprint_unchanged: bool
    final_schema_sha256: str
    final_counts_sha256: str
    final_invariant_hashes: tuple[tuple[str, str], ...]

    def _stable_payload(self) -> dict[str, object]:
        return {
            "migration_id": self.migration_id,
            "preview_sha256": self.preview_sha256,
            "imported_users": self.imported_users,
            "imported_plans": self.imported_plans,
            "imported_orders": self.imported_orders,
            "imported_legacy_devices": self.imported_legacy_devices,
            "imported_message_templates": self.imported_message_templates,
            "usable_secret_records_imported": self.usable_secret_records_imported,
            "integrity_ok": self.integrity_ok,
            "foreign_key_issues": self.foreign_key_issues,
            "spain_device_fingerprint_unchanged": (
                self.spain_device_fingerprint_unchanged
            ),
            "spain_passport_fingerprint_unchanged": (
                self.spain_passport_fingerprint_unchanged
            ),
            "spain_issuance_fingerprints_unchanged": (
                self.spain_issuance_fingerprints_unchanged
            ),
            "spain_lifecycle_fingerprint_unchanged": (
                self.spain_lifecycle_fingerprint_unchanged
            ),
            "spain_server_fingerprint_unchanged": (
                self.spain_server_fingerprint_unchanged
            ),
            "final_schema_sha256": self.final_schema_sha256,
            "final_counts_sha256": self.final_counts_sha256,
            "final_invariant_hashes": dict(self.final_invariant_hashes),
        }

    @property
    def result_sha256(self) -> str:
        return _canonical_sha256(self._stable_payload())


class _StopReasons:
    def __init__(self) -> None:
        self._values: list[str] = []

    def add(self, value: str) -> None:
        if value not in self._values:
            self._values.append(value)

    def as_tuple(self) -> tuple[str, ...]:
        return tuple(self._values)


def build_bot_web_migration_preview(
    source_db: Path,
    target_db: Path,
    *,
    migration_id: str,
) -> BotWebMigrationPreview:
    """Describe a merge without creating, updating, or deleting any DB row."""

    _validate_migration_id(migration_id)
    source_path = _resolve_database_path(source_db)
    target_path = _resolve_database_path(target_db)
    if source_path == target_path:
        raise ValueError("source_db and target_db must be different files")

    policy = MigrationPolicy.default()
    reasons = _StopReasons()
    with ExitStack() as stack:
        source = stack.enter_context(_readonly_connection(source_path))
        target = stack.enter_context(_readonly_connection(target_path))
        _require_schema(source, policy.allowed_tables, "source")
        _require_schema(
            target,
            policy.allowed_tables | policy.preserved_target_tables,
            "target",
        )
        _record_database_health(source, "SOURCE", reasons)
        _record_database_health(target, "TARGET", reasons)

        source_users = _row_dicts(
            source,
            "SELECT id, telegram_id, operator_label, is_admin FROM users ORDER BY id",
        )
        target_users = _row_dicts(
            target,
            "SELECT id, telegram_id, operator_label, is_admin FROM users ORDER BY id",
        )
        users_create, users_preserve = _preview_users(
            source_users,
            target_users,
            reasons,
        )

        source_plans = _row_dicts(
            source,
            """
            SELECT id, name, duration_days, max_devices, price, currency,
                   is_free, is_active
            FROM plans ORDER BY id
            """,
        )
        target_plans = _row_dicts(
            target,
            """
            SELECT id, name, duration_days, max_devices, price, currency,
                   is_free, is_active
            FROM plans ORDER BY id
            """,
        )
        plans_create, plans_preserve = _preview_plans(
            source_plans,
            target_plans,
            reasons,
        )

        source_devices = _row_dicts(
            source,
            "SELECT id, user_id FROM devices ORDER BY id",
        )
        source_orders = _row_dicts(
            source,
            "SELECT id, user_id, device_id, plan_id FROM orders ORDER BY id",
        )
        orders_create = _preview_orders(
            source_orders,
            source_users,
            source_plans,
            source_devices,
            reasons,
        )

        source_templates = _row_dicts(
            source,
            "SELECT key, text FROM message_templates ORDER BY key",
        )
        target_templates = _row_dicts(
            target,
            "SELECT key, text FROM message_templates ORDER BY key",
        )
        templates_create, templates_preserve = _preview_templates(
            source_templates,
            target_templates,
            reasons,
        )

        excluded_counts = tuple(
            (table, _table_count(source, table))
            for table in sorted(policy.excluded_tables & _table_names(source))
        )
        target_counts = {
            "devices": _table_count(target, "devices"),
            "device_passports": _table_count(target, "device_passports"),
            "admin_config_issuance_requests": _table_count(
                target, "admin_config_issuance_requests"
            ),
            "admin_config_issuance_receipts": _table_count(
                target, "admin_config_issuance_receipts"
            ),
            "device_lifecycle_events": _table_count(
                target, "device_lifecycle_events"
            ),
        }
        invariant_hashes = _target_invariant_hashes(target)
        api_token_count = _table_count(source, "api_tokens")
        source_schema_sha256 = _database_schema_sha256(source)
        source_counts_sha256 = _database_counts_sha256(source)
        source_allowed_rows_sha256 = _source_allowed_rows_sha256(source)
        target_schema_sha256 = _database_schema_sha256(target)
        target_counts_sha256 = _database_counts_sha256(target)
        target_allowed_rows_sha256 = _source_allowed_rows_sha256(target)

    stop_reasons = reasons.as_tuple()
    return BotWebMigrationPreview(
        migration_id=migration_id,
        source_schema_sha256=source_schema_sha256,
        source_counts_sha256=source_counts_sha256,
        source_allowed_rows_sha256=source_allowed_rows_sha256,
        target_schema_sha256=target_schema_sha256,
        target_counts_sha256=target_counts_sha256,
        target_allowed_rows_sha256=target_allowed_rows_sha256,
        users_create=users_create,
        users_preserve=users_preserve,
        users_update=0,
        target_privileged_users_preserved=sum(
            1 for row in target_users if int(row["is_admin"]) == 1
        ),
        plans_create=plans_create,
        plans_preserve=plans_preserve,
        orders_create=orders_create,
        message_templates_create=templates_create,
        message_templates_preserve=templates_preserve,
        legacy_devices_external_only=len(source_devices),
        legacy_devices_revoked=len(source_devices),
        spain_devices_preserved=target_counts["devices"],
        spain_passports_preserved=target_counts["device_passports"],
        spain_issuance_requests_preserved=target_counts[
            "admin_config_issuance_requests"
        ],
        spain_issuance_receipts_preserved=target_counts[
            "admin_config_issuance_receipts"
        ],
        spain_lifecycle_events_preserved=target_counts[
            "device_lifecycle_events"
        ],
        api_tokens_reissue_required=api_token_count,
        usable_secret_records_imported=0,
        excluded_counts=excluded_counts,
        invariant_hashes=invariant_hashes,
        stop_reasons=stop_reasons,
        conflict_count=len(stop_reasons),
        apply_allowed=not stop_reasons,
    )


def apply_bot_web_migration_to_copy(
    preview: BotWebMigrationPreview,
    *,
    source_db: Path,
    target_copy_db: Path,
) -> BotWebMigrationResult:
    """Apply an approved preview only to an explicit disposable DB copy."""

    if not isinstance(preview, BotWebMigrationPreview) or not preview.apply_allowed:
        raise MigrationPreconditionError("migration preview is not applyable")
    source_path = _resolve_database_path(source_db)
    target_path = _resolve_database_path(target_copy_db)
    if source_path.samefile(target_path):
        raise ValueError("source_db and target_copy_db must be different files")
    if not target_path.name.endswith(".copy.sqlite3"):
        raise ValueError("target database must be an explicit .copy.sqlite3 file")
    if target_path.stat().st_nlink != 1:
        raise ValueError("target database must not be hard-linked")

    try:
        return _apply_verified_copy(preview, source_path, target_path)
    except MigrationPreconditionError:
        _remove_incomplete_copy(target_path)
        raise
    except Exception as error:
        _remove_incomplete_copy(target_path)
        if isinstance(error, MigrationApplyError):
            raise
        raise MigrationApplyError("copy-only migration apply failed") from error


def _apply_verified_copy(
    preview: BotWebMigrationPreview,
    source_path: Path,
    target_path: Path,
) -> BotWebMigrationResult:
    with ExitStack() as stack:
        source = stack.enter_context(_readonly_connection(source_path))
        target = sqlite3.connect(target_path)
        stack.callback(target.close)
        target.row_factory = sqlite3.Row
        target.execute("PRAGMA foreign_keys=ON")
        _verify_source_preconditions(source, preview)
        _verify_target_schema(target, preview)

        replay = _is_complete_replay(target, preview, source)
        if replay:
            return _build_result(preview, target, created_rows=0)

        target.execute("BEGIN IMMEDIATE")
        try:
            _verify_target_baseline(target, preview)
            baseline_counts = {
                str(item["table"]): int(item["count"])
                for item in _database_counts(target)
            }
            created_rows = _apply_rows(target, source, preview)
            _verify_source_preconditions(source, preview)
            _verify_target_schema(target, preview)
            if _target_invariant_hashes(target) != preview.invariant_hashes:
                raise MigrationPreconditionError("Spain invariants changed during apply")
            _verify_final_counts(target, baseline_counts, preview)
            result = _build_result(preview, target, created_rows=created_rows)
            if not result.integrity_ok or result.foreign_key_issues:
                raise MigrationApplyError("copy database health check failed")
            target.commit()
            return result
        except Exception:
            target.rollback()
            raise


def _verify_source_preconditions(
    source: sqlite3.Connection,
    preview: BotWebMigrationPreview,
) -> None:
    if _database_schema_sha256(source) != preview.source_schema_sha256:
        raise MigrationPreconditionError("source schema changed after preview")
    if _database_counts_sha256(source) != preview.source_counts_sha256:
        raise MigrationPreconditionError("source counts changed after preview")
    if _source_allowed_rows_sha256(source) != preview.source_allowed_rows_sha256:
        raise MigrationPreconditionError("source rows changed after preview")


def _verify_target_schema(
    target: sqlite3.Connection,
    preview: BotWebMigrationPreview,
) -> None:
    if _database_schema_sha256(target) != preview.target_schema_sha256:
        raise MigrationPreconditionError("target schema changed after preview")


def _verify_target_baseline(
    target: sqlite3.Connection,
    preview: BotWebMigrationPreview,
) -> None:
    _verify_target_schema(target, preview)
    if _database_counts_sha256(target) != preview.target_counts_sha256:
        raise MigrationPreconditionError("target counts changed after preview")
    if _source_allowed_rows_sha256(target) != preview.target_allowed_rows_sha256:
        raise MigrationPreconditionError("target merge rows changed after preview")
    if _target_invariant_hashes(target) != preview.invariant_hashes:
        raise MigrationPreconditionError("target invariants changed after preview")


def _is_complete_replay(
    target: sqlite3.Connection,
    preview: BotWebMigrationPreview,
    source: sqlite3.Connection,
) -> bool:
    rows = target.execute(
        """
        SELECT source_table, source_row_sha256, target_row_id
        FROM legacy_migration_records
        WHERE migration_id=?
        """,
        (preview.migration_id,),
    ).fetchall()
    if not rows:
        return False
    actual = {(str(row[0]), str(row[1])) for row in rows}
    expected = _expected_ledger_keys(preview, source)
    if actual != expected:
        raise MigrationPreconditionError("migration ledger is partial or invalid")
    complete_marker = next(
        str(row[2])
        for row in rows
        if str(row[0]) == "__preview__"
        and str(row[1]) == preview.sha256
    )
    if complete_marker != _replay_target_state_sha256(target, preview.migration_id):
        raise MigrationPreconditionError("migration replay target state changed")
    if _target_invariant_hashes(target) != preview.invariant_hashes:
        raise MigrationPreconditionError("Spain invariants changed after migration")
    return True


def _apply_rows(
    target: sqlite3.Connection,
    source: sqlite3.Connection,
    preview: BotWebMigrationPreview,
) -> int:
    rows = _source_allowed_rows(source)
    created = 0
    server_id, inserted = _ensure_legacy_server(target, preview)
    created += inserted

    user_map: dict[int, int] = {}
    for row in rows["users"]:
        telegram_id = int(row["telegram_id"])
        existing = target.execute(
            "SELECT id FROM users WHERE telegram_id=?", (telegram_id,)
        ).fetchone()
        if existing is None:
            cursor = target.execute(
                """
                INSERT INTO users(
                    telegram_id, operator_label, username, first_name, last_name,
                    status, locale, is_admin, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
                """,
                (
                    telegram_id, row["operator_label"], row["username"],
                    row["first_name"], row["last_name"], row["status"],
                    row["locale"], row["created_at"], row["updated_at"],
                ),
            )
            target_id = int(cursor.lastrowid)
            created += 1
        else:
            target_id = int(existing[0])
        user_map[int(row["id"])] = target_id
        _record_ledger(target, preview, "users", row, target_id)

    for row in rows["plans"]:
        existing = target.execute(
            "SELECT id FROM plans WHERE id=?", (str(row["id"]),)
        ).fetchone()
        if existing is None:
            target.execute(
                """
                INSERT INTO plans(
                    id, name, duration_days, max_devices, price, currency,
                    is_free, is_active, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                tuple(row[field] for field in (
                    "id", "name", "duration_days", "max_devices", "price",
                    "currency", "is_free", "is_active", "created_at", "updated_at",
                )),
            )
            created += 1
        _record_ledger(target, preview, "plans", row, str(row["id"]))

    device_map: dict[int, int] = {}
    for row in rows["devices"]:
        row_hash = _source_row_sha256("devices", row)
        cursor = target.execute(
            """
            INSERT INTO devices(
                user_id, server_id, name, created_at, activated_at, expires_at,
                duration_days, expiry_policy, status, vpn_ip, peer_public_key,
                peer_private_key_encrypted, preshared_key_encrypted,
                config_version, config_material_status, assignment_mode,
                config_fingerprint, last_config_sent_at, first_connected_at,
                last_connected_at, revoked_at, revoke_reason
            ) VALUES (?, ?, ?, ?, ?, NULL, NULL, 'indefinite', 'revoked',
                      '0.0.0.0/32', ?, ?, ?, ?, 'external_only', ?, NULL,
                      ?, ?, ?, ?, 'phase13_usa_legacy_migration')
            """,
            (
                user_map[int(row["user_id"])], server_id, row["name"],
                row["created_at"], row["activated_at"], f"legacy:{row_hash}",
                "unavailable:phase13-migration-redacted",
                "unavailable:phase13-migration-redacted", row["config_version"],
                row["assignment_mode"], row["last_config_sent_at"],
                row["first_connected_at"], row["last_connected_at"],
                row["revoked_at"] or row["created_at"],
            ),
        )
        target_id = int(cursor.lastrowid)
        device_map[int(row["id"])] = target_id
        created += 1
        _record_ledger(target, preview, "devices", row, target_id)

    for row in rows["orders"]:
        cursor = target.execute(
            """
            INSERT INTO orders(
                user_id, device_id, plan_id, requested_config_version, status,
                payment_mode, created_at, approved_at, fulfilled_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_map[int(row["user_id"])], device_map[int(row["device_id"])],
                row["plan_id"], row["requested_config_version"], row["status"],
                row["payment_mode"], row["created_at"], row["approved_at"],
                row["fulfilled_at"],
            ),
        )
        created += 1
        _record_ledger(target, preview, "orders", row, int(cursor.lastrowid))

    for row in rows["message_templates"]:
        existing = target.execute(
            "SELECT key FROM message_templates WHERE key=?", (row["key"],)
        ).fetchone()
        if existing is None:
            target.execute(
                "INSERT INTO message_templates(key, text, updated_at) VALUES (?, ?, ?)",
                (row["key"], row["text"], row["updated_at"]),
            )
            created += 1
        _record_ledger(target, preview, "message_templates", row, str(row["key"]))

    _record_ledger_hash(
        target,
        preview,
        "__preview__",
        preview.sha256,
        _replay_target_state_sha256(target, preview.migration_id),
    )
    return created


def _ensure_legacy_server(
    target: sqlite3.Connection,
    preview: BotWebMigrationPreview,
) -> tuple[int, int]:
    name = f"legacy-usa-history:{preview.migration_id}"
    cursor = target.execute(
        """
        INSERT INTO servers(
            name, host, ssh_port, endpoint_host, vpn_port, vpn_network_cidr,
            server_address, server_public_key, runtime, firewall, status,
            max_devices, current_devices
        ) VALUES (?, NULL, NULL, NULL, NULL, '0.0.0.0/32', NULL, NULL,
                  'legacy-metadata-only', NULL, 'disabled', 0, 0)
        """,
        (name,),
    )
    server_id = int(cursor.lastrowid)
    marker_hash = _canonical_sha256(
        {"kind": "legacy_server", "migration_id": preview.migration_id}
    )
    _record_ledger_hash(target, preview, "__legacy_server__", marker_hash, server_id)
    return server_id, 1


def _record_ledger(
    target: sqlite3.Connection,
    preview: BotWebMigrationPreview,
    source_table: str,
    source_row: Mapping[str, object],
    target_row_id: object,
) -> None:
    _record_ledger_hash(
        target,
        preview,
        source_table,
        _source_row_sha256(source_table, source_row),
        target_row_id,
    )


def _record_ledger_hash(
    target: sqlite3.Connection,
    preview: BotWebMigrationPreview,
    source_table: str,
    source_row_sha256: str,
    target_row_id: object,
) -> None:
    target.execute(
        """
        INSERT INTO legacy_migration_records(
            migration_id, source_table, source_row_sha256, target_row_id
        ) VALUES (?, ?, ?, ?)
        """,
        (preview.migration_id, source_table, source_row_sha256, str(target_row_id)),
    )


def _source_row_sha256(table: str, row: Mapping[str, object]) -> str:
    return _canonical_sha256({"source_table": table, "row": dict(row)})


def _expected_ledger_keys(
    preview: BotWebMigrationPreview,
    source: sqlite3.Connection,
) -> set[tuple[str, str]]:
    keys = {
        (table, _source_row_sha256(table, row))
        for table, rows in _source_allowed_rows(source).items()
        for row in rows
    }
    keys.add(("__preview__", preview.sha256))
    keys.add(
        (
            "__legacy_server__",
            _canonical_sha256(
                {"kind": "legacy_server", "migration_id": preview.migration_id}
            ),
        )
    )
    return keys


_REPLAY_TARGET_TABLES = {
    "users": ("users", "id"),
    "plans": ("plans", "id"),
    "devices": ("devices", "id"),
    "orders": ("orders", "id"),
    "message_templates": ("message_templates", "key"),
    "__legacy_server__": ("servers", "id"),
}


def _replay_target_state_sha256(
    target: sqlite3.Connection,
    migration_id: str,
) -> str:
    ledger_rows = target.execute(
        """
        SELECT source_table, source_row_sha256, target_row_id
        FROM legacy_migration_records
        WHERE migration_id=? AND source_table != '__preview__'
        ORDER BY source_table, source_row_sha256
        """,
        (migration_id,),
    ).fetchall()
    payload: list[dict[str, object]] = []
    for ledger_row in ledger_rows:
        source_table = str(ledger_row[0])
        target_spec = _REPLAY_TARGET_TABLES.get(source_table)
        if target_spec is None:
            raise MigrationPreconditionError("migration replay target state changed")
        target_table, target_key = target_spec
        target_row_id = str(ledger_row[2])
        target_row = target.execute(
            f"SELECT * FROM {_quote_identifier(target_table)} "
            f"WHERE {_quote_identifier(target_key)}=?",
            (target_row_id,),
        ).fetchone()
        if target_row is None:
            raise MigrationPreconditionError("migration replay target state changed")
        payload.append(
            {
                "source_table": source_table,
                "source_row_sha256": str(ledger_row[1]),
                "target_row_id": target_row_id,
                "target_row": {
                    key: _canonical_sqlite_value(target_row[key])
                    for key in target_row.keys()
                },
            }
        )
    return _canonical_sha256(payload)


def _verify_final_counts(
    target: sqlite3.Connection,
    baseline: Mapping[str, int],
    preview: BotWebMigrationPreview,
) -> None:
    expected = dict(baseline)
    increments = {
        "users": preview.users_create,
        "plans": preview.plans_create,
        "orders": preview.orders_create,
        "devices": preview.legacy_devices_external_only,
        "message_templates": preview.message_templates_create,
        "servers": 1,
        "legacy_migration_records": sum(
            (
                preview.users_create + preview.users_preserve,
                preview.plans_create + preview.plans_preserve,
                preview.orders_create,
                preview.legacy_devices_external_only,
                preview.message_templates_create + preview.message_templates_preserve,
                2,
            )
        ),
    }
    for table, increment in increments.items():
        expected[table] += increment
    actual = {str(item["table"]): int(item["count"]) for item in _database_counts(target)}
    if actual != expected:
        raise MigrationApplyError("target row counts do not match preview")


def _build_result(
    preview: BotWebMigrationPreview,
    target: sqlite3.Connection,
    *,
    created_rows: int,
) -> BotWebMigrationResult:
    final_invariants = _target_invariant_hashes(target)
    invariant_map = dict(final_invariants)
    expected = dict(preview.invariant_hashes)
    integrity = tuple(str(row[0]) for row in target.execute("PRAGMA integrity_check"))
    foreign_key_issues = len(target.execute("PRAGMA foreign_key_check").fetchall())
    return BotWebMigrationResult(
        migration_id=preview.migration_id,
        preview_sha256=preview.sha256,
        created_rows=created_rows,
        imported_users=preview.users_create,
        imported_plans=preview.plans_create,
        imported_orders=preview.orders_create,
        imported_legacy_devices=preview.legacy_devices_external_only,
        imported_message_templates=preview.message_templates_create,
        usable_secret_records_imported=0,
        integrity_ok=integrity == ("ok",),
        foreign_key_issues=foreign_key_issues,
        spain_device_fingerprint_unchanged=(
            invariant_map["devices"] == expected["devices"]
        ),
        spain_passport_fingerprint_unchanged=(
            invariant_map["passports"] == expected["passports"]
        ),
        spain_issuance_fingerprints_unchanged=(
            invariant_map["issuance_requests"] == expected["issuance_requests"]
            and invariant_map["issuance_receipts"] == expected["issuance_receipts"]
        ),
        spain_lifecycle_fingerprint_unchanged=(
            invariant_map["lifecycle_events"] == expected["lifecycle_events"]
        ),
        spain_server_fingerprint_unchanged=(
            invariant_map["servers"] == expected["servers"]
        ),
        final_schema_sha256=_database_schema_sha256(target),
        final_counts_sha256=_database_counts_sha256(target),
        final_invariant_hashes=final_invariants,
    )


def _remove_incomplete_copy(path: Path) -> None:
    for candidate in (
        path,
        Path(f"{path}-wal"),
        Path(f"{path}-shm"),
        Path(f"{path}-journal"),
    ):
        if candidate.exists() and not candidate.is_symlink():
            candidate.unlink()


def _validate_migration_id(value: str) -> None:
    if (
        not isinstance(value, str)
        or _MIGRATION_ID_PATTERN.fullmatch(value) is None
        or ".." in value
    ):
        raise ValueError("migration_id is invalid")


def _resolve_database_path(value: Path) -> Path:
    path = Path(value)
    if path.is_symlink():
        raise ValueError("database symlinks are not allowed")
    resolved = path.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError("database must be a regular file")
    return resolved


@contextmanager
def _readonly_connection(path: Path) -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA query_only=ON")
        yield connection
    finally:
        connection.close()


def _record_database_health(
    connection: sqlite3.Connection,
    prefix: str,
    reasons: _StopReasons,
) -> None:
    integrity = tuple(
        str(row[0]) for row in connection.execute("PRAGMA integrity_check")
    )
    if integrity != ("ok",):
        reasons.add(f"{prefix}_INTEGRITY_FAILED")
    if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
        reasons.add(f"{prefix}_FOREIGN_KEY_FAILED")


def _require_schema(
    connection: sqlite3.Connection,
    required_tables: frozenset[str],
    role: str,
) -> None:
    missing = sorted(required_tables - _table_names(connection))
    if missing:
        raise ValueError(f"{role} database schema is incomplete")


def _preview_users(
    source_rows: Sequence[Mapping[str, object]],
    target_rows: Sequence[Mapping[str, object]],
    reasons: _StopReasons,
) -> tuple[int, int]:
    target_by_telegram = {
        int(row["telegram_id"]): row
        for row in target_rows
        if row["telegram_id"] is not None
    }
    target_labels = {
        str(row["operator_label"]).strip()
        for row in target_rows
        if row["operator_label"] is not None
        and str(row["operator_label"]).strip()
    }
    proposed_labels: set[str] = set()
    create_count = 0
    preserve_count = 0
    for row in source_rows:
        telegram_id = row["telegram_id"]
        label = (
            str(row["operator_label"]).strip()
            if row["operator_label"] is not None
            else ""
        )
        if telegram_id is None:
            reasons.add("USER_TELEGRAM_ID_MISSING")
            continue
        if int(telegram_id) in target_by_telegram:
            preserve_count += 1
            continue
        if label and (label in target_labels or label in proposed_labels):
            reasons.add("USER_OPERATOR_LABEL_CONFLICT")
            continue
        proposed_labels.add(label)
        create_count += 1
    return create_count, preserve_count


_PLAN_SEMANTIC_FIELDS = (
    "name",
    "duration_days",
    "max_devices",
    "price",
    "currency",
    "is_free",
    "is_active",
)


def _preview_plans(
    source_rows: Sequence[Mapping[str, object]],
    target_rows: Sequence[Mapping[str, object]],
    reasons: _StopReasons,
) -> tuple[int, int]:
    target_by_id = {str(row["id"]): row for row in target_rows}
    create_count = 0
    preserve_count = 0
    for source_row in source_rows:
        target_row = target_by_id.get(str(source_row["id"]))
        if target_row is None:
            create_count += 1
            continue
        if any(
            source_row[field] != target_row[field]
            for field in _PLAN_SEMANTIC_FIELDS
        ):
            reasons.add("PLAN_SEMANTIC_CONFLICT")
        else:
            preserve_count += 1
    return create_count, preserve_count


def _preview_orders(
    orders: Sequence[Mapping[str, object]],
    users: Sequence[Mapping[str, object]],
    plans: Sequence[Mapping[str, object]],
    devices: Sequence[Mapping[str, object]],
    reasons: _StopReasons,
) -> int:
    user_ids = {int(row["id"]) for row in users if row["telegram_id"] is not None}
    plan_ids = {str(row["id"]) for row in plans}
    device_owners = {
        int(row["id"]): int(row["user_id"])
        for row in devices
    }
    create_count = 0
    for row in orders:
        resolvable = True
        if int(row["user_id"]) not in user_ids:
            reasons.add("ORDER_USER_MAPPING_AMBIGUOUS")
            resolvable = False
        if row["plan_id"] is None or str(row["plan_id"]) not in plan_ids:
            reasons.add("ORDER_PLAN_MAPPING_AMBIGUOUS")
            resolvable = False
        if row["device_id"] is None or int(row["device_id"]) not in device_owners:
            reasons.add("ORDER_DEVICE_MAPPING_AMBIGUOUS")
            resolvable = False
        elif device_owners[int(row["device_id"])] != int(row["user_id"]):
            reasons.add("ORDER_DEVICE_OWNER_MISMATCH")
            resolvable = False
        if resolvable:
            create_count += 1
    return create_count


def _preview_templates(
    source_rows: Sequence[Mapping[str, object]],
    target_rows: Sequence[Mapping[str, object]],
    reasons: _StopReasons,
) -> tuple[int, int]:
    target_by_key = {str(row["key"]): str(row["text"]) for row in target_rows}
    create_count = 0
    preserve_count = 0
    for row in source_rows:
        key = str(row["key"])
        if key not in target_by_key:
            create_count += 1
        elif target_by_key[key] == str(row["text"]):
            preserve_count += 1
        else:
            reasons.add("MESSAGE_TEMPLATE_CONFLICT")
    return create_count, preserve_count


def _target_invariant_hashes(
    connection: sqlite3.Connection,
) -> tuple[tuple[str, str], ...]:
    tables = {
        "access_slot_assignments": "access_slot_assignment_requests",
        "issuance_receipts": "admin_config_issuance_receipts",
        "issuance_requests": "admin_config_issuance_requests",
        "lifecycle_events": "device_lifecycle_events",
        "passports": "device_passports",
    }
    values = [
        (name, _table_fingerprint(connection, table))
        for name, table in sorted(tables.items())
    ]
    values.extend(
        (
            (
                "devices",
                _query_fingerprint(
                    connection,
                    """
                    SELECT * FROM devices
                    WHERE config_material_status != 'external_only'
                    """,
                ),
            ),
            (
                "servers",
                _query_fingerprint(
                    connection,
                    """
                    SELECT * FROM servers
                    WHERE runtime IS NULL OR runtime != 'legacy-metadata-only'
                    """,
                ),
            ),
        )
    )
    peer_rows = _row_dicts(
        connection,
        """
        SELECT peer_public_key FROM devices
        WHERE config_material_status != 'external_only'
        ORDER BY peer_public_key
        """,
    )
    values.append(("peer_public_key_set", _canonical_sha256(peer_rows)))
    return tuple(sorted(values))


def _table_names(connection: sqlite3.Connection) -> frozenset[str]:
    return frozenset(
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
        if not str(row[0]).startswith("sqlite_")
    )


def _table_count(connection: sqlite3.Connection, table: str) -> int:
    quoted = _quote_identifier(table)
    return int(connection.execute(f"SELECT count(*) FROM {quoted}").fetchone()[0])


def _table_fingerprint(connection: sqlite3.Connection, table: str) -> str:
    quoted = _quote_identifier(table)
    return _query_fingerprint(connection, f"SELECT * FROM {quoted}")


def _query_fingerprint(connection: sqlite3.Connection, query: str) -> str:
    rows = _row_dicts(connection, query)
    canonical_rows = sorted(
        rows,
        key=lambda row: json.dumps(
            row,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ),
    )
    return _canonical_sha256(canonical_rows)


def _database_schema_sha256(connection: sqlite3.Connection) -> str:
    rows = _row_dicts(
        connection,
        """
        SELECT type, name, tbl_name, sql
        FROM sqlite_master
        WHERE name NOT LIKE 'sqlite_%' AND sql IS NOT NULL
        ORDER BY type, name
        """,
    )
    return _canonical_sha256(rows)


def _database_counts_sha256(connection: sqlite3.Connection) -> str:
    return _canonical_sha256(_database_counts(connection))


def _database_counts(connection: sqlite3.Connection) -> list[dict[str, object]]:
    return [
        {"table": table, "count": _table_count(connection, table)}
        for table in sorted(_table_names(connection))
    ]


def _source_allowed_rows(connection: sqlite3.Connection) -> dict[str, list[dict[str, object]]]:
    queries = {
        "users": """
            SELECT id, telegram_id, operator_label, username, first_name,
                   last_name, status, locale, is_admin, created_at, updated_at
            FROM users ORDER BY id
        """,
        "plans": """
            SELECT id, name, duration_days, max_devices, price, currency,
                   is_free, is_active, created_at, updated_at
            FROM plans ORDER BY id
        """,
        "devices": """
            SELECT id, user_id, name, created_at, activated_at, expires_at,
                   duration_days, expiry_policy, status, config_version,
                   assignment_mode, last_config_sent_at, first_connected_at,
                   last_connected_at, revoked_at, revoke_reason
            FROM devices ORDER BY id
        """,
        "orders": """
            SELECT id, user_id, device_id, plan_id, requested_config_version,
                   status, payment_mode, created_at, approved_at, fulfilled_at
            FROM orders ORDER BY id
        """,
        "message_templates": """
            SELECT key, text, updated_at FROM message_templates ORDER BY key
        """,
    }
    return {
        table: _row_dicts(connection, query)
        for table, query in sorted(queries.items())
    }


def _source_allowed_rows_sha256(connection: sqlite3.Connection) -> str:
    return _canonical_sha256(_source_allowed_rows(connection))


def _quote_identifier(value: str) -> str:
    if _IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise ValueError("unsafe SQLite identifier")
    return f'"{value}"'


def _row_dicts(
    connection: sqlite3.Connection,
    query: str,
) -> list[dict[str, object]]:
    return [
        {
            key: _canonical_sqlite_value(row[key])
            for key in row.keys()
        }
        for row in connection.execute(query).fetchall()
    ]


def _canonical_sqlite_value(value: object) -> object:
    if isinstance(value, bytes):
        return {"blob_sha256": hashlib.sha256(value).hexdigest()}
    if value is None or isinstance(value, (str, int, float)):
        return value
    raise TypeError("unsupported SQLite value")


def _canonical_sha256(value: object) -> str:
    payload = (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
