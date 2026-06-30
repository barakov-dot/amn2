import io
import json
import sqlite3
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.backup.manifest import (
    build_manifest,
    checksum_sha256,
    validate_manifest,
)
from app.backup.storage import (
    decrypt_archive_bytes,
    encrypt_archive_bytes,
    secret_box_from_env,
)
from app.security.crypto import SecretBoxError
from app.services.config_export import SUPPORTED_ARTIFACTS, SUPPORTED_TARGET_CLIENTS
from app.vpn.config_versions import SUPPORTED_CONFIG_VERSIONS


DATABASE_ENTRY = "database.sqlite3"
MANIFEST_ENTRY = "manifest.json"
EXPECTED_MEMBERS = {DATABASE_ENTRY, MANIFEST_ENTRY}
REQUIRED_TABLES = {
    "users",
    "servers",
    "plans",
    "devices",
    "orders",
    "admin_actions",
    "device_traffic_snapshots",
    "message_templates",
}
REQUIRED_COLUMNS = {
    "orders": {"requested_config_version"},
    "devices": {"first_connected_at", "last_connected_at"},
}
CONFIG_SHARE_TOKENS_TABLE = "config_share_tokens"
CONFIG_SHARE_RESTORE_DANGEROUS_MODE_GATE = (
    "CONFIG_SHARE_RESTORE_USABLE_TOKEN_HASHES_DANGEROUS_MODE"
)
CONFIG_SHARE_RESTORE_DANGEROUS_MODE_NOT_IMPLEMENTED_ERROR = (
    "Config share restore dangerous mode gate is not implemented"
)
USABLE_CONFIG_SHARE_TOKEN_ERROR = (
    "Backup database contains usable config share token hashes; "
    "restore requires explicit dangerous mode"
)
MALFORMED_CONFIG_SHARE_TOKEN_POLICY_ERROR = (
    "Backup database config share token has invalid policy shape"
)
MALFORMED_CONFIG_SHARE_TOKEN_SCOPE_METADATA_ERROR = (
    "Backup database config share token has invalid scope metadata"
)
MALFORMED_CONFIG_SHARE_TOKEN_IDENTITY_METADATA_ERROR = (
    "Backup database config share token has invalid identity metadata"
)
FOREIGN_KEY_INTEGRITY_ERROR = "Backup database failed foreign key integrity check"
FOREIGN_KEY_SCHEMA_ERROR = "Backup database failed foreign key schema check"
CHECK_CONSTRAINT_SCHEMA_ERROR = (
    "Backup database failed check constraint schema check"
)
UNIQUE_CONSTRAINT_SCHEMA_ERROR = (
    "Backup database failed unique constraint schema check"
)
REQUIRED_OPTIONAL_TABLE_COLUMNS_SCHEMA_ERROR = (
    "Backup database failed required columns schema check"
)
COLUMN_DECLARATION_SCHEMA_ERROR = (
    "Backup database failed column declaration schema check"
)
EXPECTED_FOREIGN_KEYS = {
    CONFIG_SHARE_TOKENS_TABLE: (("owner_user_id", "users", "id"),),
}
EXPECTED_CHECK_CONSTRAINTS = {
    CONFIG_SHARE_TOKENS_TABLE: (
        "purpose TEXT NOT NULL CHECK (purpose IN ('config_share'))",
        "max_downloads INTEGER NOT NULL CHECK (max_downloads > 0)",
        "download_count INTEGER NOT NULL DEFAULT 0 CHECK (download_count >= 0)",
    ),
}
EXPECTED_PRIMARY_KEYS = {
    CONFIG_SHARE_TOKENS_TABLE: ("id",),
}
EXPECTED_UNIQUE_CONSTRAINTS = {
    CONFIG_SHARE_TOKENS_TABLE: (("token_hash",),),
}
EXPECTED_OPTIONAL_TABLE_COLUMNS = {
    CONFIG_SHARE_TOKENS_TABLE: (
        "id",
        "token_hash",
        "token_prefix",
        "purpose",
        "created_by_actor",
        "owner_user_id",
        "bound_device_ids_json",
        "bound_server_ids_json",
        "allowed_artifact_kinds_json",
        "target_client",
        "expires_at",
        "revoked_at",
        "revoked_by_actor",
        "one_time",
        "max_downloads",
        "download_count",
        "last_used_at",
        "last_used_ip_hash",
        "created_at",
    ),
}
EXPECTED_OPTIONAL_TABLE_COLUMN_DECLARATIONS = {
    CONFIG_SHARE_TOKENS_TABLE: {
        "id": ("TEXT", False, None),
        "token_hash": ("TEXT", True, None),
        "token_prefix": ("TEXT", True, None),
        "purpose": ("TEXT", True, None),
        "created_by_actor": ("TEXT", True, None),
        "owner_user_id": ("INTEGER", True, None),
        "bound_device_ids_json": ("TEXT", True, None),
        "bound_server_ids_json": ("TEXT", True, None),
        "allowed_artifact_kinds_json": ("TEXT", True, None),
        "target_client": ("TEXT", True, None),
        "expires_at": ("TEXT", True, None),
        "revoked_at": ("TEXT", False, None),
        "revoked_by_actor": ("TEXT", False, None),
        "one_time": ("INTEGER", True, "1"),
        "max_downloads": ("INTEGER", True, None),
        "download_count": ("INTEGER", True, "0"),
        "last_used_at": ("TEXT", False, None),
        "last_used_ip_hash": ("TEXT", False, None),
        "created_at": ("TEXT", True, "CURRENT_TIMESTAMP"),
    },
}


class BackupService:
    def __init__(self, app_version: str) -> None:
        self.app_version = app_version

    def create(self, db_path: Path, output_dir: Path) -> Path:
        db_path = Path(db_path)
        if not db_path.is_file():
            raise ValueError("database path must be a regular file")
        self._validate_database_foreign_key_schema_from_path(db_path)
        self._validate_database_check_constraint_schema_from_path(db_path)
        self._validate_database_unique_constraint_schema_from_path(db_path)
        self._validate_optional_table_columns_schema_from_path(db_path)
        self._validate_optional_table_column_declarations_schema_from_path(db_path)
        self._validate_database_foreign_keys_from_path(db_path)
        self._validate_no_usable_config_share_tokens_from_path(db_path)

        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        manifest = build_manifest(
            app_version=self.app_version,
            database_checksum_sha256=checksum_sha256(db_path),
        )
        archive_bytes = self._build_archive(db_path, manifest)
        encrypted_bytes = encrypt_archive_bytes(archive_bytes)

        backup_path = output_dir / f"amneziya-backup-{self._timestamp()}.tar.enc"
        backup_path.write_bytes(encrypted_bytes)
        return backup_path

    def verify(self, backup_path: Path) -> dict[str, Any]:
        archive_bytes = decrypt_archive_bytes(Path(backup_path).read_bytes())
        manifest, database_bytes = self._read_archive(archive_bytes)
        validate_manifest(manifest)
        self._verify_database_checksum(manifest, database_bytes)
        return manifest

    def restore(
        self,
        backup_path: Path,
        target_db_path: Path,
        force: bool = False,
        restore_usable_config_share_tokens: bool = False,
    ) -> Path:
        if restore_usable_config_share_tokens:
            raise ValueError(CONFIG_SHARE_RESTORE_DANGEROUS_MODE_NOT_IMPLEMENTED_ERROR)

        target_db_path = Path(target_db_path)
        if target_db_path.exists() and not force:
            raise FileExistsError(target_db_path)

        archive_bytes = decrypt_archive_bytes(Path(backup_path).read_bytes())
        manifest, database_bytes = self._read_archive(archive_bytes)
        validate_manifest(manifest)
        self._verify_database_checksum(manifest, database_bytes)
        self._validate_restorable_database(database_bytes)

        target_db_path.parent.mkdir(parents=True, exist_ok=True)
        target_db_path.write_bytes(database_bytes)
        return target_db_path

    def _build_archive(self, db_path: Path, manifest: dict[str, Any]) -> bytes:
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w") as tar:
            database_bytes = db_path.read_bytes()
            database_info = tarfile.TarInfo(DATABASE_ENTRY)
            database_info.size = len(database_bytes)
            tar.addfile(database_info, io.BytesIO(database_bytes))

            manifest_bytes = json.dumps(
                manifest,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            manifest_info = tarfile.TarInfo(MANIFEST_ENTRY)
            manifest_info.size = len(manifest_bytes)
            tar.addfile(manifest_info, io.BytesIO(manifest_bytes))
        return archive.getvalue()

    def _read_archive(self, archive_bytes: bytes) -> tuple[dict[str, Any], bytes]:
        try:
            with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r") as tar:
                members = tar.getmembers()
                member_names = [member.name for member in members]
                if len(member_names) != len(EXPECTED_MEMBERS):
                    raise ValueError("Backup archive has unexpected members")
                if set(member_names) != EXPECTED_MEMBERS:
                    raise ValueError("Backup archive has unexpected members")

                member_by_name = {member.name: member for member in members}
                if not all(member_by_name[name].isfile() for name in EXPECTED_MEMBERS):
                    raise ValueError("Backup archive entries must be regular files")

                database_file = tar.extractfile(member_by_name[DATABASE_ENTRY])
                manifest_file = tar.extractfile(member_by_name[MANIFEST_ENTRY])
                if database_file is None or manifest_file is None:
                    raise ValueError("Backup archive is missing required files")
                database_bytes = database_file.read()
                manifest = json.loads(manifest_file.read().decode("utf-8"))
        except (tarfile.TarError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError("Invalid backup archive") from exc
        if not isinstance(manifest, dict):
            raise ValueError("Invalid backup manifest")
        return manifest, database_bytes

    def _verify_database_checksum(
        self,
        manifest: dict[str, Any],
        database_bytes: bytes,
    ) -> None:
        import hashlib

        checksum = hashlib.sha256(database_bytes).hexdigest()
        if checksum != manifest["database_checksum_sha256"]:
            raise ValueError("Backup database checksum mismatch")

    def _validate_restorable_database(self, database_bytes: bytes) -> None:
        temp_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False) as temp_file:
                temp_file.write(database_bytes)
                temp_path = Path(temp_file.name)

            conn = sqlite3.connect(temp_path)
            try:
                conn.row_factory = sqlite3.Row
                integrity = conn.execute("PRAGMA integrity_check").fetchone()
                if integrity is None or integrity[0] != "ok":
                    raise ValueError("Backup database failed integrity check")

                tables = {
                    str(row["name"])
                    for row in conn.execute(
                        """
                        SELECT name
                        FROM sqlite_master
                        WHERE type = 'table'
                        """
                    )
                }
                missing_tables = REQUIRED_TABLES - tables
                if missing_tables:
                    missing = ", ".join(sorted(missing_tables))
                    raise ValueError(f"Backup database is missing required tables: {missing}")

                self._validate_required_columns(conn)
                self._validate_database_foreign_key_schema(conn)
                self._validate_database_check_constraint_schema(conn)
                self._validate_database_unique_constraint_schema(conn)
                self._validate_optional_table_columns_schema(conn)
                self._validate_optional_table_column_declarations_schema(conn)
                self._validate_database_foreign_keys(conn)
                self._validate_order_rows(conn)
                self._validate_active_device_rows(conn)
                self._validate_device_secrets(conn)
                self._validate_no_usable_config_share_tokens(conn)
            finally:
                conn.close()
        except sqlite3.DatabaseError as exc:
            raise ValueError("Backup database is not a usable SQLite database") from exc
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)

    def _validate_active_device_rows(self, conn: sqlite3.Connection) -> None:
        rows = conn.execute(
            """
            SELECT id, name, vpn_ip, peer_public_key, config_version, expires_at
            FROM devices
            WHERE status IN ('active', 'pending')
            """
        ).fetchall()
        for row in rows:
            for column in (
                "name",
                "vpn_ip",
                "peer_public_key",
                "config_version",
                "expires_at",
            ):
                if not row[column]:
                    raise ValueError(
                        f"Backup database device {row['id']} is missing {column}"
                    )
            if row["config_version"] not in SUPPORTED_CONFIG_VERSIONS:
                raise ValueError(
                    f"Backup database device {row['id']} has unsupported config_version"
                )

    def _validate_required_columns(self, conn: sqlite3.Connection) -> None:
        for table_name, required_columns in REQUIRED_COLUMNS.items():
            columns = {
                str(row["name"])
                for row in conn.execute(f"PRAGMA table_info({table_name})")
            }
            missing_columns = required_columns - columns
            if missing_columns:
                missing = ", ".join(
                    f"{table_name}.{column}" for column in sorted(missing_columns)
                )
                raise ValueError(
                    f"Backup database is missing required columns: {missing}"
                )

    def _validate_order_rows(self, conn: sqlite3.Connection) -> None:
        rows = conn.execute(
            """
            SELECT id, requested_config_version
            FROM orders
            WHERE status IN ('manual_review', 'approved')
              AND device_id IS NULL
            """
        ).fetchall()
        for row in rows:
            if row["requested_config_version"] not in SUPPORTED_CONFIG_VERSIONS:
                raise ValueError(
                    f"Backup database order {row['id']} has unsupported "
                    "requested_config_version"
                )

    def _validate_device_secrets(self, conn: sqlite3.Connection) -> None:
        secret_box = secret_box_from_env()
        rows = conn.execute(
            """
            SELECT id, peer_private_key_encrypted, preshared_key_encrypted
            FROM devices
            WHERE status IN ('active', 'pending')
            """
        ).fetchall()
        for row in rows:
            for column in ("peer_private_key_encrypted", "preshared_key_encrypted"):
                encrypted_value = row[column]
                try:
                    secret_box.decrypt_text(str(encrypted_value))
                except SecretBoxError as exc:
                    raise ValueError(
                        f"Backup database device {row['id']} {column} could not be "
                        "decrypted with current APP_SECRET_KEY"
                    ) from exc

    def _timestamp(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    def config_share_restore_dangerous_mode_gate(self) -> dict[str, Any]:
        return {
            "gate": CONFIG_SHARE_RESTORE_DANGEROUS_MODE_GATE,
            "status": "not_implemented",
            "enabled": False,
            "requires_explicit_operator_gate": True,
            "restores_usable_config_share_token_hashes": False,
        }

    def config_share_restore_history_policy(self) -> dict[str, str]:
        return {
            "usable": "blocked-without-dangerous-mode",
            "expired": "restore-allowed-history-only",
            "revoked": "restore-allowed-history-only",
            "exhausted": "restore-allowed-history-only",
        }

    def _validate_database_unique_constraint_schema_from_path(
        self,
        db_path: Path,
    ) -> None:
        try:
            conn = sqlite3.connect(db_path)
            try:
                self._validate_database_unique_constraint_schema(conn)
            finally:
                conn.close()
        except sqlite3.DatabaseError as exc:
            raise ValueError("Backup database is not a usable SQLite database") from exc

    def _validate_database_unique_constraint_schema(
        self,
        conn: sqlite3.Connection,
    ) -> None:
        for table_name, expected_columns in EXPECTED_PRIMARY_KEYS.items():
            if not self._table_exists(conn, table_name):
                continue
            primary_key_columns = self._primary_key_columns(conn, table_name)
            if any(column not in primary_key_columns for column in expected_columns):
                raise ValueError(UNIQUE_CONSTRAINT_SCHEMA_ERROR)

        for table_name, expected_constraints in EXPECTED_UNIQUE_CONSTRAINTS.items():
            if not self._table_exists(conn, table_name):
                continue
            unique_constraints = self._unique_constraint_columns(conn, table_name)
            if any(
                expected_constraint not in unique_constraints
                for expected_constraint in expected_constraints
            ):
                raise ValueError(UNIQUE_CONSTRAINT_SCHEMA_ERROR)

    def _primary_key_columns(
        self,
        conn: sqlite3.Connection,
        table_name: str,
    ) -> set[str]:
        return {
            str(self._pragma_row_value(row, "name", 1))
            for row in conn.execute(f"PRAGMA table_info({table_name})")
            if int(self._pragma_row_value(row, "pk", 5) or 0) > 0
        }

    def _unique_constraint_columns(
        self,
        conn: sqlite3.Connection,
        table_name: str,
    ) -> set[tuple[str, ...]]:
        constraints: set[tuple[str, ...]] = set()
        for index_row in conn.execute(f"PRAGMA index_list({table_name})"):
            if int(self._pragma_row_value(index_row, "unique", 2) or 0) != 1:
                continue
            index_name = str(self._pragma_row_value(index_row, "name", 1))
            columns = tuple(
                str(self._pragma_row_value(row, "name", 2))
                for row in conn.execute(f"PRAGMA index_info({index_name})")
            )
            constraints.add(columns)
        return constraints

    def _pragma_row_value(
        self,
        row: sqlite3.Row | tuple[Any, ...],
        key: str,
        index: int,
    ) -> Any:
        if isinstance(row, sqlite3.Row):
            return row[key]
        return row[index]

    def _validate_optional_table_columns_schema_from_path(
        self,
        db_path: Path,
    ) -> None:
        try:
            conn = sqlite3.connect(db_path)
            try:
                self._validate_optional_table_columns_schema(conn)
            finally:
                conn.close()
        except sqlite3.DatabaseError as exc:
            raise ValueError("Backup database is not a usable SQLite database") from exc

    def _validate_optional_table_columns_schema(
        self,
        conn: sqlite3.Connection,
    ) -> None:
        for table_name, expected_columns in EXPECTED_OPTIONAL_TABLE_COLUMNS.items():
            if not self._table_exists(conn, table_name):
                continue
            actual_columns = {
                str(self._pragma_row_value(row, "name", 1))
                for row in conn.execute(f"PRAGMA table_info({table_name})")
            }
            if any(column not in actual_columns for column in expected_columns):
                raise ValueError(REQUIRED_OPTIONAL_TABLE_COLUMNS_SCHEMA_ERROR)

    def _validate_optional_table_column_declarations_schema_from_path(
        self,
        db_path: Path,
    ) -> None:
        try:
            conn = sqlite3.connect(db_path)
            try:
                self._validate_optional_table_column_declarations_schema(conn)
            finally:
                conn.close()
        except sqlite3.DatabaseError as exc:
            raise ValueError("Backup database is not a usable SQLite database") from exc

    def _validate_optional_table_column_declarations_schema(
        self,
        conn: sqlite3.Connection,
    ) -> None:
        expected_tables = EXPECTED_OPTIONAL_TABLE_COLUMN_DECLARATIONS.items()
        for table_name, expected_columns in expected_tables:
            if not self._table_exists(conn, table_name):
                continue
            actual_columns = {
                str(self._pragma_row_value(row, "name", 1)): row
                for row in conn.execute(f"PRAGMA table_info({table_name})")
            }
            for column_name, expected_declaration in expected_columns.items():
                row = actual_columns.get(column_name)
                if row is None:
                    raise ValueError(COLUMN_DECLARATION_SCHEMA_ERROR)
                if self._column_declaration(row) != expected_declaration:
                    raise ValueError(COLUMN_DECLARATION_SCHEMA_ERROR)

    def _column_declaration(
        self,
        row: sqlite3.Row | tuple[Any, ...],
    ) -> tuple[str, bool, str | None]:
        return (
            self._normalize_column_declaration_value(
                self._pragma_row_value(row, "type", 2)
            )
            or "",
            bool(self._pragma_row_value(row, "notnull", 3)),
            self._normalize_column_declaration_value(
                self._pragma_row_value(row, "dflt_value", 4)
            ),
        )

    def _normalize_column_declaration_value(self, value: Any) -> str | None:
        if value is None:
            return None
        return " ".join(str(value).upper().split())

    def _validate_database_check_constraint_schema_from_path(
        self,
        db_path: Path,
    ) -> None:
        try:
            conn = sqlite3.connect(db_path)
            try:
                self._validate_database_check_constraint_schema(conn)
            finally:
                conn.close()
        except sqlite3.DatabaseError as exc:
            raise ValueError("Backup database is not a usable SQLite database") from exc

    def _validate_database_check_constraint_schema(
        self,
        conn: sqlite3.Connection,
    ) -> None:
        for table_name, expected_constraints in EXPECTED_CHECK_CONSTRAINTS.items():
            table_sql = self._table_sql(conn, table_name)
            if table_sql is None:
                continue
            normalized_sql = self._normalize_schema_sql(table_sql)
            expected = {
                self._normalize_schema_sql(constraint)
                for constraint in expected_constraints
            }
            if any(constraint not in normalized_sql for constraint in expected):
                raise ValueError(CHECK_CONSTRAINT_SCHEMA_ERROR)

    def _table_sql(self, conn: sqlite3.Connection, table_name: str) -> str | None:
        row = conn.execute(
            """
            SELECT sql
            FROM sqlite_master
            WHERE type = 'table'
              AND name = ?
            """,
            (table_name,),
        ).fetchone()
        if row is None:
            return None
        return str(row["sql"] if isinstance(row, sqlite3.Row) else row[0])

    def _normalize_schema_sql(self, value: str) -> str:
        return " ".join(value.lower().split())

    def _validate_database_foreign_key_schema_from_path(self, db_path: Path) -> None:
        try:
            conn = sqlite3.connect(db_path)
            try:
                self._validate_database_foreign_key_schema(conn)
            finally:
                conn.close()
        except sqlite3.DatabaseError as exc:
            raise ValueError("Backup database is not a usable SQLite database") from exc

    def _validate_database_foreign_key_schema(self, conn: sqlite3.Connection) -> None:
        for table_name, expected_keys in EXPECTED_FOREIGN_KEYS.items():
            if not self._table_exists(conn, table_name):
                continue
            actual_keys = {
                self._foreign_key_identity(row)
                for row in conn.execute(f"PRAGMA foreign_key_list({table_name})")
            }
            if any(expected_key not in actual_keys for expected_key in expected_keys):
                raise ValueError(FOREIGN_KEY_SCHEMA_ERROR)

    def _foreign_key_identity(
        self,
        row: sqlite3.Row | tuple[Any, ...],
    ) -> tuple[str, str, str]:
        if isinstance(row, sqlite3.Row):
            return (str(row["from"]), str(row["table"]), str(row["to"]))
        return (str(row[3]), str(row[2]), str(row[4]))

    def _validate_database_foreign_keys_from_path(self, db_path: Path) -> None:
        try:
            conn = sqlite3.connect(db_path)
            try:
                self._validate_database_foreign_keys(conn)
            finally:
                conn.close()
        except sqlite3.DatabaseError as exc:
            raise ValueError("Backup database is not a usable SQLite database") from exc

    def _validate_database_foreign_keys(self, conn: sqlite3.Connection) -> None:
        violations = conn.execute("PRAGMA foreign_key_check").fetchall()
        if violations:
            raise ValueError(FOREIGN_KEY_INTEGRITY_ERROR)

    def _validate_no_usable_config_share_tokens_from_path(self, db_path: Path) -> None:
        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            try:
                self._validate_no_usable_config_share_tokens(conn)
            finally:
                conn.close()
        except sqlite3.DatabaseError as exc:
            raise ValueError("Backup database is not a usable SQLite database") from exc

    def _validate_no_usable_config_share_tokens(self, conn: sqlite3.Connection) -> None:
        if not self._table_exists(conn, CONFIG_SHARE_TOKENS_TABLE):
            return
        rows = conn.execute(
            """
            SELECT id, token_hash, token_prefix, created_by_actor, owner_user_id
                 , expires_at, revoked_at, one_time, max_downloads, download_count
                 , bound_device_ids_json, bound_server_ids_json
                 , allowed_artifact_kinds_json, target_client
            FROM config_share_tokens
            WHERE purpose = 'config_share'
            """
        ).fetchall()
        now = datetime.now(timezone.utc)
        for row in rows:
            self._validate_config_share_token_identity_metadata_shape(row)
            self._validate_config_share_token_policy_shape(row)
            self._validate_config_share_token_timestamp_shape(row)
            self._validate_config_share_token_scope_metadata_shape(row)
        if any(self._config_share_token_is_usable(row, now=now) for row in rows):
            raise ValueError(USABLE_CONFIG_SHARE_TOKEN_ERROR)

    def _validate_config_share_token_identity_metadata_shape(
        self,
        row: sqlite3.Row,
    ) -> None:
        token_id = str(row["id"]).strip()
        token_hash = str(row["token_hash"]).strip()
        token_prefix = str(row["token_prefix"]).strip()
        created_by_actor = str(row["created_by_actor"]).strip()
        try:
            owner_user_id = int(row["owner_user_id"])
        except (TypeError, ValueError) as exc:
            raise ValueError(MALFORMED_CONFIG_SHARE_TOKEN_IDENTITY_METADATA_ERROR) from exc
        if not token_id or not token_prefix or not created_by_actor:
            raise ValueError(MALFORMED_CONFIG_SHARE_TOKEN_IDENTITY_METADATA_ERROR)
        if owner_user_id <= 0:
            raise ValueError(MALFORMED_CONFIG_SHARE_TOKEN_IDENTITY_METADATA_ERROR)
        if not self._is_config_share_token_hash_shape(token_hash):
            raise ValueError(MALFORMED_CONFIG_SHARE_TOKEN_IDENTITY_METADATA_ERROR)

    def _is_config_share_token_hash_shape(self, value: str) -> bool:
        prefix = "sha256:"
        if not value.startswith(prefix):
            return False
        digest = value[len(prefix):]
        return len(digest) == 64 and all(
            char in "0123456789abcdef" for char in digest
        )

    def _validate_config_share_token_policy_shape(self, row: sqlite3.Row) -> None:
        try:
            one_time = int(row["one_time"])
            max_downloads = int(row["max_downloads"])
            download_count = int(row["download_count"])
        except (TypeError, ValueError) as exc:
            raise ValueError(MALFORMED_CONFIG_SHARE_TOKEN_POLICY_ERROR) from exc
        if one_time not in (0, 1):
            raise ValueError(MALFORMED_CONFIG_SHARE_TOKEN_POLICY_ERROR)
        if max_downloads <= 0 or download_count < 0:
            raise ValueError(MALFORMED_CONFIG_SHARE_TOKEN_POLICY_ERROR)
        if bool(one_time) and max_downloads != 1:
            raise ValueError(MALFORMED_CONFIG_SHARE_TOKEN_POLICY_ERROR)

    def _validate_config_share_token_timestamp_shape(self, row: sqlite3.Row) -> None:
        self._parse_backup_datetime(row["expires_at"], field_name="expires_at")
        revoked_at = row["revoked_at"]
        if revoked_at is not None and str(revoked_at).strip():
            self._parse_backup_datetime(revoked_at, field_name="revoked_at")

    def _validate_config_share_token_scope_metadata_shape(
        self,
        row: sqlite3.Row,
    ) -> None:
        device_ids = self._parse_positive_int_json_array(
            row["bound_device_ids_json"],
            field_name="bound_device_ids_json",
        )
        server_ids = self._parse_positive_int_json_array(
            row["bound_server_ids_json"],
            field_name="bound_server_ids_json",
        )
        artifact_kinds = self._parse_string_json_array(
            row["allowed_artifact_kinds_json"],
            field_name="allowed_artifact_kinds_json",
        )
        target_client = str(row["target_client"]).strip()
        unsupported_artifacts = set(artifact_kinds) - SUPPORTED_ARTIFACTS
        if not device_ids or not server_ids or not artifact_kinds:
            raise ValueError(MALFORMED_CONFIG_SHARE_TOKEN_SCOPE_METADATA_ERROR)
        if unsupported_artifacts:
            raise ValueError(MALFORMED_CONFIG_SHARE_TOKEN_SCOPE_METADATA_ERROR)
        if target_client not in SUPPORTED_TARGET_CLIENTS:
            raise ValueError(MALFORMED_CONFIG_SHARE_TOKEN_SCOPE_METADATA_ERROR)

    def _parse_positive_int_json_array(
        self,
        value: object,
        *,
        field_name: str,
    ) -> tuple[int, ...]:
        try:
            parsed = json.loads(str(value))
            if not isinstance(parsed, list):
                raise ValueError
            if any(not isinstance(item, int) or isinstance(item, bool) for item in parsed):
                raise ValueError
            result = tuple(parsed)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError(MALFORMED_CONFIG_SHARE_TOKEN_SCOPE_METADATA_ERROR) from exc
        if not result or any(item <= 0 for item in result):
            raise ValueError(MALFORMED_CONFIG_SHARE_TOKEN_SCOPE_METADATA_ERROR)
        return result

    def _parse_string_json_array(
        self,
        value: object,
        *,
        field_name: str,
    ) -> tuple[str, ...]:
        try:
            parsed = json.loads(str(value))
            if not isinstance(parsed, list):
                raise ValueError
            if any(not isinstance(item, str) for item in parsed):
                raise ValueError
            result = tuple(item.strip() for item in parsed)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError(MALFORMED_CONFIG_SHARE_TOKEN_SCOPE_METADATA_ERROR) from exc
        if not result or any(not item for item in result):
            raise ValueError(MALFORMED_CONFIG_SHARE_TOKEN_SCOPE_METADATA_ERROR)
        return result

    def _config_share_token_is_usable(self, row: sqlite3.Row, *, now: datetime) -> bool:
        revoked_at = row["revoked_at"]
        if revoked_at is not None and str(revoked_at).strip():
            return False
        expires_at = self._parse_backup_datetime(row["expires_at"], field_name="expires_at")
        if expires_at <= now:
            return False
        download_count = int(row["download_count"])
        max_downloads = int(row["max_downloads"])
        if download_count >= max_downloads:
            return False
        if bool(row["one_time"]) and download_count > 0:
            return False
        return True

    def _parse_backup_datetime(self, value: object, *, field_name: str) -> datetime:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(
                f"Backup database config share token has invalid {field_name}"
            ) from exc
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    def _table_exists(self, conn: sqlite3.Connection, table_name: str) -> bool:
        row = conn.execute(
            """
            SELECT 1
            FROM sqlite_master
            WHERE type = 'table'
              AND name = ?
            """,
            (table_name,),
        ).fetchone()
        return row is not None
