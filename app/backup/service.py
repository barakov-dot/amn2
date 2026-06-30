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


class BackupService:
    def __init__(self, app_version: str) -> None:
        self.app_version = app_version

    def create(self, db_path: Path, output_dir: Path) -> Path:
        db_path = Path(db_path)
        if not db_path.is_file():
            raise ValueError("database path must be a regular file")
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
            SELECT id, expires_at, revoked_at, one_time, max_downloads, download_count
            FROM config_share_tokens
            WHERE purpose = 'config_share'
            """
        ).fetchall()
        now = datetime.now(timezone.utc)
        for row in rows:
            self._validate_config_share_token_policy_shape(row)
            self._validate_config_share_token_timestamp_shape(row)
        if any(self._config_share_token_is_usable(row, now=now) for row in rows):
            raise ValueError(USABLE_CONFIG_SHARE_TOKEN_ERROR)

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
