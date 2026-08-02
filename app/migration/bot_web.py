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

    stop_reasons = reasons.as_tuple()
    return BotWebMigrationPreview(
        migration_id=migration_id,
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
        "devices": "devices",
        "issuance_receipts": "admin_config_issuance_receipts",
        "issuance_requests": "admin_config_issuance_requests",
        "lifecycle_events": "device_lifecycle_events",
        "passports": "device_passports",
        "servers": "servers",
    }
    values = [
        (name, _table_fingerprint(connection, table))
        for name, table in sorted(tables.items())
    ]
    peer_rows = _row_dicts(
        connection,
        "SELECT peer_public_key FROM devices ORDER BY peer_public_key",
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
    rows = _row_dicts(connection, f"SELECT * FROM {quoted}")
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
