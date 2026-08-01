import io
import json
import re
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
    "vpn_runtime_instances",
    "client_compatibility_evidence",
    "device_passports",
    "admin_config_issuance_receipts",
}
REQUIRED_COLUMNS = {
    "orders": {"requested_config_version"},
    "devices": {"first_connected_at", "last_connected_at"},
}
PHASE13_PROTOCOL_VERSIONS = {"awg2", "awg3"}
PHASE13_SAFE_TABLE_FIELDS = {
    "vpn_runtime_instances": {
        "runtime_instance_id",
        "server_id",
        "protocol_version",
        "runtime_version",
        "interface_name",
        "udp_port",
        "vpn_cidr",
        "container_name",
        "service_name",
        "config_path",
        "lifecycle_state",
        "acceptance_receipt",
    },
    "client_compatibility_evidence": {
        "evidence_id",
        "application",
        "platform",
        "client_version",
        "protocol_version",
        "source_kind",
        "status",
        "observed_at",
        "safe_reference",
        "scope",
    },
}
PHASE13_REFERENCE_COLUMNS = {
    "devices": ("runtime_instance_id", "compatibility_evidence_id"),
    "device_passports": ("runtime_instance_id", "compatibility_evidence_id"),
    "admin_config_issuance_receipts": (
        "runtime_instance_id",
        "compatibility_evidence_id",
    ),
}


class BackupService:
    def __init__(self, app_version: str) -> None:
        self.app_version = app_version

    def create(self, db_path: Path, output_dir: Path) -> Path:
        db_path = Path(db_path)
        if not db_path.is_file():
            raise ValueError("database path must be a regular file")

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
        backup_path.chmod(0o600)
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
    ) -> Path:
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
                self._validate_phase13_state(conn)
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
              AND config_material_status = 'available'
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

    def _validate_phase13_state(self, conn: sqlite3.Connection) -> None:
        for table_name, safe_fields in PHASE13_SAFE_TABLE_FIELDS.items():
            columns = {
                str(row["name"])
                for row in conn.execute(f"PRAGMA table_info({table_name})")
            }
            missing_fields = safe_fields - columns
            if missing_fields:
                missing = ", ".join(
                    f"{table_name}.{field}" for field in sorted(missing_fields)
                )
                raise ValueError(
                    f"Backup database is missing Phase 13 fields: {missing}"
                )

        runtime_rows = conn.execute(
            """
            SELECT runtime_instance_id, protocol_version, lifecycle_state,
                   acceptance_receipt
            FROM vpn_runtime_instances
            """
        ).fetchall()
        for row in runtime_rows:
            receipt = row["acceptance_receipt"]
            if row["protocol_version"] not in PHASE13_PROTOCOL_VERSIONS or (
                row["lifecycle_state"] == "accepted"
                and (
                    receipt is None
                    or re.fullmatch(r"sha256:[0-9a-f]{64}", str(receipt)) is None
                )
            ):
                raise ValueError(
                    "Backup database vpn_runtime_instances contains invalid protocol "
                    "or accepted-runtime receipt"
                )

        evidence_rows = conn.execute(
            "SELECT evidence_id, protocol_version FROM client_compatibility_evidence"
        ).fetchall()
        if any(
            row["protocol_version"] not in PHASE13_PROTOCOL_VERSIONS
            for row in evidence_rows
        ):
            raise ValueError(
                "Backup database client_compatibility_evidence contains invalid "
                "protocol_version"
            )

        for table_name, reference_columns in PHASE13_REFERENCE_COLUMNS.items():
            for column_name in reference_columns:
                target_table, target_column = (
                    ("vpn_runtime_instances", "runtime_instance_id")
                    if column_name == "runtime_instance_id"
                    else ("client_compatibility_evidence", "evidence_id")
                )
                dangling = conn.execute(
                    f"""
                    SELECT source.{column_name}
                    FROM {table_name} AS source
                    LEFT JOIN {target_table} AS target
                      ON target.{target_column} = source.{column_name}
                    WHERE source.{column_name} IS NOT NULL
                      AND target.{target_column} IS NULL
                    LIMIT 1
                    """
                ).fetchone()
                if dangling is not None:
                    raise ValueError(
                        f"Backup database {table_name}.{column_name} has a "
                        "dangling Phase 13 identity"
                    )

    def _timestamp(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
