import hashlib
import io
import json
import tarfile
from datetime import datetime, timedelta, timezone

import pytest

from app.backup.manifest import build_manifest
from app.backup.service import BackupService
from app.cli import build_parser
from app.db.connection import connect
from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.security.crypto import SecretBox
from app.services.config_share_tokens import hash_config_share_token


STRONG_SECRET = "test-secret-for-backup-1234567890-ABCDE"
OTHER_STRONG_SECRET = "other-secret-for-backup-1234567890-XYZ"


def _create_database(path):
    conn = connect(path)
    initialize_schema(conn)
    conn.close()


def _create_database_with_encrypted_device(path, app_secret=STRONG_SECRET):
    conn = connect(path)
    initialize_schema(conn)
    repo = Repository(conn)
    user_id = repo.upsert_user(telegram_id=1001, username="alice", first_name="Alice", last_name=None)
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    box = SecretBox.from_app_secret(app_secret)
    repo.create_device(
        user_id=user_id,
        server_id=server_id,
        name="iPhone",
        duration_days=30,
        vpn_ip="10.8.0.2",
        peer_public_key="peer-public-key",
        peer_private_key_encrypted=box.encrypt_text("peer-private-key"),
        preshared_key_encrypted=box.encrypt_text("preshared-key"),
        config_version="amneziawg_v2",
    )
    conn.close()


def _create_database_with_config_share_token(
    path,
    *,
    expires_at=None,
    revoked_at=None,
    download_count=0,
    max_downloads=1,
    one_time=True,
):
    conn = connect(path)
    initialize_schema(conn)
    repo = Repository(conn)
    user_id = repo.upsert_user(
        telegram_id=1001,
        username="alice",
        first_name="Alice",
        last_name=None,
    )
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    now = datetime.now(timezone.utc)
    token_expires_at = expires_at or (now + timedelta(minutes=30)).isoformat()
    repo.create_config_share_token(
        token_id="share-token-1",
        token_hash=hash_config_share_token("backup-redaction-token"),
        token_prefix="backup-",
        purpose="config_share",
        created_by_actor="web-admin:7",
        owner_user_id=user_id,
        bound_device_ids=[10],
        bound_server_ids=[server_id],
        allowed_artifact_kinds=["wireguard_conf"],
        target_client="amnezia_generic",
        expires_at=token_expires_at,
        created_at=now.isoformat(),
        one_time=one_time,
        max_downloads=max_downloads,
    )
    conn.execute(
        """
        UPDATE config_share_tokens
        SET revoked_at = ?, download_count = ?
        WHERE id = ?
        """,
        (revoked_at, download_count, "share-token-1"),
    )
    conn.commit()
    conn.close()


def _create_database_with_usable_config_share_token(path):
    _create_database_with_config_share_token(path)


def _create_database_with_config_share_token_history(path, history_state):
    now = datetime.now(timezone.utc)
    if history_state == "expired":
        _create_database_with_config_share_token(
            path,
            expires_at=(now - timedelta(minutes=1)).isoformat(),
        )
        return
    if history_state == "revoked":
        _create_database_with_config_share_token(
            path,
            revoked_at=now.isoformat(),
        )
        return
    if history_state == "exhausted":
        _create_database_with_config_share_token(
            path,
            download_count=1,
            max_downloads=1,
        )
        return
    raise ValueError(f"unknown config share token history state: {history_state}")


def _drop_table(path, table_name):
    conn = connect(path)
    conn.execute(f"DROP TABLE {table_name}")
    conn.commit()
    conn.close()


def _drop_orders_requested_config_version_column(path):
    conn = connect(path)
    conn.executescript(
        """
        ALTER TABLE orders RENAME TO orders_old;
        CREATE TABLE orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            device_id INTEGER,
            plan_id TEXT,
            status TEXT NOT NULL DEFAULT 'manual_review',
            payment_mode TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            approved_at TEXT,
            fulfilled_at TEXT
        );
        INSERT INTO orders (
            id,
            user_id,
            device_id,
            plan_id,
            status,
            payment_mode,
            created_at,
            approved_at,
            fulfilled_at
        )
        SELECT
            id,
            user_id,
            device_id,
            plan_id,
            status,
            payment_mode,
            created_at,
            approved_at,
            fulfilled_at
        FROM orders_old;
        DROP TABLE orders_old;
        """
    )
    conn.commit()
    conn.close()


def _drop_devices_connection_columns(path):
    conn = connect(path)
    conn.executescript(
        """
        ALTER TABLE devices RENAME TO devices_old;
        CREATE TABLE devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            server_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            activated_at TEXT,
            expires_at TEXT,
            duration_days INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            vpn_ip TEXT NOT NULL,
            peer_public_key TEXT NOT NULL,
            peer_private_key_encrypted TEXT NOT NULL,
            preshared_key_encrypted TEXT NOT NULL,
            config_version TEXT NOT NULL,
            last_config_sent_at TEXT,
            revoked_at TEXT,
            revoke_reason TEXT
        );
        INSERT INTO devices (
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
            revoked_at,
            revoke_reason
        FROM devices_old;
        DROP TABLE devices_old;
        """
    )
    conn.commit()
    conn.close()


def _blank_device_fields(path, *fields):
    conn = connect(path)
    assignments = ", ".join(f"{field} = ''" for field in fields)
    conn.execute(f"UPDATE devices SET {assignments}")
    conn.commit()
    conn.close()


def _regular_member(name, payload):
    info = tarfile.TarInfo(name)
    info.size = len(payload)
    return info, io.BytesIO(payload)


def _write_encrypted_archive(path, members):
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w") as tar:
        for info, fileobj in members:
            tar.addfile(info, fileobj)

    box = SecretBox.from_app_secret(STRONG_SECRET)
    path.write_bytes(box._fernet.encrypt(archive.getvalue()))
    return path


def test_backup_create_verify_and_restore_requires_secret(tmp_path, monkeypatch):
    db_path = tmp_path / "source.sqlite3"
    _create_database(db_path)

    monkeypatch.setenv("APP_SECRET_KEY", STRONG_SECRET)
    service = BackupService(app_version="0.1.0")
    backup_path = service.create(db_path=db_path, output_dir=tmp_path / "backups")

    assert backup_path.exists()
    assert backup_path.suffixes[-2:] == [".tar", ".enc"]
    assert "source" not in backup_path.name

    manifest = service.verify(backup_path)
    assert manifest["format_version"] == 1
    assert manifest["app"] == "amneziya"
    assert manifest["app_version"] == "0.1.0"
    assert manifest["database_kind"] == "sqlite"
    assert manifest["includes"] == ["database", "manifest"]
    assert "app_secret_key" in manifest["excludes"]
    assert "telegram_bot_token" in manifest["excludes"]
    assert "qr_files" in manifest["excludes"]
    assert "plain_configs" in manifest["excludes"]
    assert "usable_config_share_token_hashes" in manifest["excludes"]

    encrypted_bytes = backup_path.read_bytes()
    assert b"APP_SECRET_KEY" not in encrypted_bytes
    assert STRONG_SECRET.encode("utf-8") not in encrypted_bytes
    assert b"database.sqlite3" not in encrypted_bytes
    assert b"manifest.json" not in encrypted_bytes

    monkeypatch.delenv("APP_SECRET_KEY")
    with pytest.raises(RuntimeError, match="APP_SECRET_KEY"):
        service.restore(
            backup_path=backup_path,
            target_db_path=tmp_path / "restored.sqlite3",
        )


def test_create_rejects_directory_db_path(tmp_path, monkeypatch):
    monkeypatch.setenv("APP_SECRET_KEY", STRONG_SECRET)
    service = BackupService(app_version="0.1.0")

    with pytest.raises(ValueError, match="database.*regular file"):
        service.create(db_path=tmp_path, output_dir=tmp_path / "backups")


def test_verify_accepts_legacy_manifest_excludes_without_share_token_hashes(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("APP_SECRET_KEY", STRONG_SECRET)
    db_path = tmp_path / "source.sqlite3"
    _create_database(db_path)
    database_payload = db_path.read_bytes()
    manifest = build_manifest(
        app_version="0.1.0",
        database_checksum_sha256=hashlib.sha256(database_payload).hexdigest(),
    )
    manifest["excludes"] = [
        "app_secret_key",
        "telegram_bot_token",
        "qr_files",
        "plain_configs",
    ]
    backup_path = _write_encrypted_archive(
        tmp_path / "legacy-manifest.tar.enc",
        [
            _regular_member("database.sqlite3", database_payload),
            _regular_member("manifest.json", json.dumps(manifest).encode("utf-8")),
        ],
    )

    service = BackupService(app_version="0.1.0")

    assert service.verify(backup_path)["excludes"] == manifest["excludes"]


def test_backup_create_rejects_usable_config_share_token_hashes(tmp_path, monkeypatch):
    monkeypatch.setenv("APP_SECRET_KEY", STRONG_SECRET)
    db_path = tmp_path / "source.sqlite3"
    _create_database_with_usable_config_share_token(db_path)

    service = BackupService(app_version="0.1.0")

    with pytest.raises(ValueError, match="config share token.*dangerous mode"):
        service.create(db_path=db_path, output_dir=tmp_path / "backups")


def test_backup_create_rejects_malformed_config_share_token_policy_shape(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("APP_SECRET_KEY", STRONG_SECRET)
    db_path = tmp_path / "source.sqlite3"
    _create_database_with_config_share_token(
        db_path,
        one_time=True,
        max_downloads=2,
        download_count=1,
    )

    service = BackupService(app_version="0.1.0")

    with pytest.raises(ValueError, match="config share token.*policy shape"):
        service.create(db_path=db_path, output_dir=tmp_path / "backups")


def test_restore_refuses_overwrite_without_force(tmp_path, monkeypatch):
    monkeypatch.setenv("APP_SECRET_KEY", STRONG_SECRET)
    db_path = tmp_path / "source.sqlite3"
    target_path = tmp_path / "target.sqlite3"
    _create_database(db_path)
    _create_database(target_path)

    service = BackupService(app_version="0.1.0")
    backup_path = service.create(db_path=db_path, output_dir=tmp_path / "backups")

    with pytest.raises(FileExistsError):
        service.restore(backup_path=backup_path, target_db_path=target_path)


def test_restore_writes_database_only_after_successful_checksum(tmp_path, monkeypatch):
    monkeypatch.setenv("APP_SECRET_KEY", STRONG_SECRET)
    db_path = tmp_path / "source.sqlite3"
    target_path = tmp_path / "restored.sqlite3"
    _create_database(db_path)

    service = BackupService(app_version="0.1.0")
    backup_path = service.create(db_path=db_path, output_dir=tmp_path / "backups")

    restored_path = service.restore(
        backup_path=backup_path,
        target_db_path=target_path,
    )

    assert restored_path == target_path
    assert target_path.read_bytes() == db_path.read_bytes()
    assert not (tmp_path / "manifest.json").exists()
    assert not (tmp_path / "database.sqlite3").exists()


def test_restore_rejects_usable_config_share_token_hashes_before_writing_target(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("APP_SECRET_KEY", STRONG_SECRET)
    db_path = tmp_path / "source.sqlite3"
    target_path = tmp_path / "restored.sqlite3"
    _create_database_with_usable_config_share_token(db_path)
    database_payload = db_path.read_bytes()
    manifest = build_manifest(
        app_version="0.1.0",
        database_checksum_sha256=hashlib.sha256(database_payload).hexdigest(),
    )
    backup_path = _write_encrypted_archive(
        tmp_path / "share-token-backup.tar.enc",
        [
            _regular_member("database.sqlite3", database_payload),
            _regular_member("manifest.json", json.dumps(manifest).encode("utf-8")),
        ],
    )

    service = BackupService(app_version="0.1.0")

    with pytest.raises(ValueError, match="config share token.*dangerous mode"):
        service.restore(backup_path=backup_path, target_db_path=target_path)

    assert not target_path.exists()


def test_restore_rejects_malformed_config_share_token_policy_shape_before_writing_target(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("APP_SECRET_KEY", STRONG_SECRET)
    db_path = tmp_path / "source.sqlite3"
    target_path = tmp_path / "restored.sqlite3"
    _create_database_with_config_share_token(
        db_path,
        one_time=True,
        max_downloads=2,
        download_count=1,
    )
    database_payload = db_path.read_bytes()
    manifest = build_manifest(
        app_version="0.1.0",
        database_checksum_sha256=hashlib.sha256(database_payload).hexdigest(),
    )
    backup_path = _write_encrypted_archive(
        tmp_path / "malformed-share-token-backup.tar.enc",
        [
            _regular_member("database.sqlite3", database_payload),
            _regular_member("manifest.json", json.dumps(manifest).encode("utf-8")),
        ],
    )

    service = BackupService(app_version="0.1.0")

    with pytest.raises(ValueError, match="config share token.*policy shape"):
        service.restore(backup_path=backup_path, target_db_path=target_path)

    assert not target_path.exists()


def test_restore_usable_config_share_tokens_dangerous_mode_gate_is_closed():
    service = BackupService(app_version="0.1.0")

    gate = service.config_share_restore_dangerous_mode_gate()

    assert gate == {
        "gate": "CONFIG_SHARE_RESTORE_USABLE_TOKEN_HASHES_DANGEROUS_MODE",
        "status": "not_implemented",
        "enabled": False,
        "requires_explicit_operator_gate": True,
        "restores_usable_config_share_token_hashes": False,
    }


def test_config_share_restore_history_policy_documents_allowed_non_usable_states():
    service = BackupService(app_version="0.1.0")

    policy = service.config_share_restore_history_policy()

    assert policy == {
        "usable": "blocked-without-dangerous-mode",
        "expired": "restore-allowed-history-only",
        "revoked": "restore-allowed-history-only",
        "exhausted": "restore-allowed-history-only",
    }


@pytest.mark.parametrize("history_state", ["expired", "revoked", "exhausted"])
def test_restore_accepts_config_share_token_history_without_dangerous_mode(
    tmp_path,
    monkeypatch,
    history_state,
):
    monkeypatch.setenv("APP_SECRET_KEY", STRONG_SECRET)
    db_path = tmp_path / "source.sqlite3"
    target_path = tmp_path / "restored.sqlite3"
    _create_database_with_config_share_token_history(db_path, history_state)

    service = BackupService(app_version="0.1.0")
    backup_path = service.create(db_path=db_path, output_dir=tmp_path / "backups")

    restored_path = service.restore(
        backup_path=backup_path,
        target_db_path=target_path,
    )

    assert restored_path == target_path
    conn = connect(target_path)
    restored = conn.execute(
        """
        SELECT revoked_at, download_count, max_downloads, expires_at
        FROM config_share_tokens
        WHERE id = ?
        """,
        ("share-token-1",),
    ).fetchone()
    conn.close()
    assert restored is not None
    if history_state == "revoked":
        assert restored["revoked_at"] is not None
    if history_state == "exhausted":
        assert restored["download_count"] == restored["max_downloads"]
    if history_state == "expired":
        expires_at = datetime.fromisoformat(restored["expires_at"])
        assert expires_at <= datetime.now(timezone.utc)


def test_restore_rejects_explicit_share_token_dangerous_mode_before_writing_target(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("APP_SECRET_KEY", STRONG_SECRET)
    db_path = tmp_path / "source.sqlite3"
    target_path = tmp_path / "restored.sqlite3"
    _create_database(db_path)

    service = BackupService(app_version="0.1.0")
    backup_path = service.create(db_path=db_path, output_dir=tmp_path / "backups")

    with pytest.raises(ValueError, match="dangerous mode gate.*not implemented"):
        service.restore(
            backup_path=backup_path,
            target_db_path=target_path,
            restore_usable_config_share_tokens=True,
        )

    assert not target_path.exists()


def test_restore_cli_does_not_expose_share_token_dangerous_mode():
    parser = build_parser()

    args = parser.parse_args(
        [
            "backup",
            "restore",
            "--file",
            "backup.tar.enc",
            "--target-db",
            "restored.sqlite3",
            "--force",
        ]
    )

    assert args.force is True
    assert not hasattr(args, "restore_usable_config_share_tokens")
    with pytest.raises(SystemExit):
        parser.parse_args(
            [
                "backup",
                "restore",
                "--file",
                "backup.tar.enc",
                "--target-db",
                "restored.sqlite3",
                "--restore-usable-config-share-tokens",
            ]
        )


def test_restore_accepts_database_with_encrypted_peer_secrets_for_current_secret(tmp_path, monkeypatch):
    monkeypatch.setenv("APP_SECRET_KEY", STRONG_SECRET)
    db_path = tmp_path / "source.sqlite3"
    target_path = tmp_path / "restored.sqlite3"
    _create_database_with_encrypted_device(db_path, app_secret=STRONG_SECRET)

    service = BackupService(app_version="0.1.0")
    backup_path = service.create(db_path=db_path, output_dir=tmp_path / "backups")

    restored_path = service.restore(backup_path=backup_path, target_db_path=target_path)

    assert restored_path == target_path
    conn = connect(target_path)
    device = conn.execute("SELECT * FROM devices").fetchone()
    assert SecretBox.from_app_secret(STRONG_SECRET).decrypt_text(device["peer_private_key_encrypted"]) == "peer-private-key"
    conn.close()


def test_restore_preserves_device_traffic_snapshots(tmp_path, monkeypatch):
    monkeypatch.setenv("APP_SECRET_KEY", STRONG_SECRET)
    db_path = tmp_path / "source.sqlite3"
    target_path = tmp_path / "restored.sqlite3"
    _create_database_with_encrypted_device(db_path, app_secret=STRONG_SECRET)
    conn = connect(db_path)
    device = conn.execute("SELECT id, server_id, peer_public_key FROM devices").fetchone()
    conn.execute(
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
            device["id"],
            device["server_id"],
            device["peer_public_key"],
            1024,
            2048,
            "test",
            "2026-05-27T12:00:00Z",
        ),
    )
    conn.commit()
    conn.close()

    service = BackupService(app_version="0.1.0")
    backup_path = service.create(db_path=db_path, output_dir=tmp_path / "backups")
    service.restore(backup_path=backup_path, target_db_path=target_path)

    restored = connect(target_path)
    snapshot = restored.execute("SELECT * FROM device_traffic_snapshots").fetchone()
    assert snapshot["rx_bytes"] == 1024
    assert snapshot["tx_bytes"] == 2048
    restored.close()


def test_restore_rejects_database_without_traffic_snapshot_table_before_writing_target(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("APP_SECRET_KEY", STRONG_SECRET)
    db_path = tmp_path / "source.sqlite3"
    target_path = tmp_path / "restored.sqlite3"
    _create_database_with_encrypted_device(db_path, app_secret=STRONG_SECRET)
    _drop_table(db_path, "device_traffic_snapshots")

    service = BackupService(app_version="0.1.0")
    backup_path = service.create(db_path=db_path, output_dir=tmp_path / "backups")

    with pytest.raises(ValueError, match="device_traffic_snapshots"):
        service.restore(backup_path=backup_path, target_db_path=target_path)

    assert not target_path.exists()


def test_restore_rejects_database_without_requested_config_version_before_writing_target(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("APP_SECRET_KEY", STRONG_SECRET)
    db_path = tmp_path / "source.sqlite3"
    target_path = tmp_path / "restored.sqlite3"
    _create_database_with_encrypted_device(db_path, app_secret=STRONG_SECRET)
    _drop_orders_requested_config_version_column(db_path)

    service = BackupService(app_version="0.1.0")
    backup_path = service.create(db_path=db_path, output_dir=tmp_path / "backups")

    with pytest.raises(ValueError, match="orders.requested_config_version"):
        service.restore(backup_path=backup_path, target_db_path=target_path)

    assert not target_path.exists()


def test_restore_rejects_database_without_message_templates_table_before_writing_target(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("APP_SECRET_KEY", STRONG_SECRET)
    db_path = tmp_path / "source.sqlite3"
    target_path = tmp_path / "restored.sqlite3"
    _create_database_with_encrypted_device(db_path, app_secret=STRONG_SECRET)
    _drop_table(db_path, "message_templates")

    service = BackupService(app_version="0.1.0")
    backup_path = service.create(db_path=db_path, output_dir=tmp_path / "backups")

    with pytest.raises(ValueError, match="message_templates"):
        service.restore(backup_path=backup_path, target_db_path=target_path)

    assert not target_path.exists()


def test_restore_rejects_database_without_plans_table_before_writing_target(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("APP_SECRET_KEY", STRONG_SECRET)
    db_path = tmp_path / "source.sqlite3"
    target_path = tmp_path / "restored.sqlite3"
    _create_database_with_encrypted_device(db_path, app_secret=STRONG_SECRET)
    _drop_table(db_path, "plans")

    service = BackupService(app_version="0.1.0")
    backup_path = service.create(db_path=db_path, output_dir=tmp_path / "backups")

    with pytest.raises(ValueError, match="plans"):
        service.restore(backup_path=backup_path, target_db_path=target_path)

    assert not target_path.exists()


def test_restore_rejects_database_without_device_connection_columns_before_writing_target(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("APP_SECRET_KEY", STRONG_SECRET)
    db_path = tmp_path / "source.sqlite3"
    target_path = tmp_path / "restored.sqlite3"
    _create_database_with_encrypted_device(db_path, app_secret=STRONG_SECRET)
    _drop_devices_connection_columns(db_path)

    service = BackupService(app_version="0.1.0")
    backup_path = service.create(db_path=db_path, output_dir=tmp_path / "backups")

    with pytest.raises(ValueError, match="devices.first_connected_at"):
        service.restore(backup_path=backup_path, target_db_path=target_path)

    assert not target_path.exists()


def test_restore_rejects_database_with_peer_secrets_encrypted_for_different_secret_without_overwriting_target(
    tmp_path,
    monkeypatch,
):
    db_path = tmp_path / "source.sqlite3"
    target_path = tmp_path / "restored.sqlite3"
    _create_database_with_encrypted_device(db_path, app_secret=STRONG_SECRET)
    _create_database(target_path)
    original_target_bytes = target_path.read_bytes()

    monkeypatch.setenv("APP_SECRET_KEY", OTHER_STRONG_SECRET)
    service = BackupService(app_version="0.1.0")
    backup_path = service.create(db_path=db_path, output_dir=tmp_path / "backups")

    with pytest.raises(ValueError, match="decrypt"):
        service.restore(backup_path=backup_path, target_db_path=target_path, force=True)

    assert target_path.read_bytes() == original_target_bytes


def test_restore_rejects_active_device_with_empty_encrypted_secrets_before_writing_target(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("APP_SECRET_KEY", STRONG_SECRET)
    db_path = tmp_path / "source.sqlite3"
    target_path = tmp_path / "restored.sqlite3"
    _create_database_with_encrypted_device(db_path, app_secret=STRONG_SECRET)
    _blank_device_fields(db_path, "peer_private_key_encrypted", "preshared_key_encrypted")

    service = BackupService(app_version="0.1.0")
    backup_path = service.create(db_path=db_path, output_dir=tmp_path / "backups")

    with pytest.raises(ValueError, match="peer_private_key_encrypted"):
        service.restore(backup_path=backup_path, target_db_path=target_path)

    assert not target_path.exists()


def test_restore_rejects_active_device_with_empty_required_fields_before_writing_target(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("APP_SECRET_KEY", STRONG_SECRET)
    db_path = tmp_path / "source.sqlite3"
    target_path = tmp_path / "restored.sqlite3"
    _create_database_with_encrypted_device(db_path, app_secret=STRONG_SECRET)
    _blank_device_fields(db_path, "name", "peer_public_key", "config_version")

    service = BackupService(app_version="0.1.0")
    backup_path = service.create(db_path=db_path, output_dir=tmp_path / "backups")

    with pytest.raises(ValueError, match="name"):
        service.restore(backup_path=backup_path, target_db_path=target_path)

    assert not target_path.exists()


def test_restore_rejects_active_device_with_unsupported_config_version_before_writing_target(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("APP_SECRET_KEY", STRONG_SECRET)
    db_path = tmp_path / "source.sqlite3"
    target_path = tmp_path / "restored.sqlite3"
    _create_database_with_encrypted_device(db_path, app_secret=STRONG_SECRET)
    conn = connect(db_path)
    conn.execute("UPDATE devices SET config_version = 'wireguard'")
    conn.commit()
    conn.close()

    service = BackupService(app_version="0.1.0")
    backup_path = service.create(db_path=db_path, output_dir=tmp_path / "backups")

    with pytest.raises(ValueError, match="unsupported config_version"):
        service.restore(backup_path=backup_path, target_db_path=target_path)

    assert not target_path.exists()


def test_restore_rejects_invalid_sqlite_database_with_valid_checksum_before_writing_target(tmp_path, monkeypatch):
    monkeypatch.setenv("APP_SECRET_KEY", STRONG_SECRET)
    target_path = tmp_path / "restored.sqlite3"
    database_payload = b"not sqlite bytes"
    manifest = build_manifest(
        app_version="0.1.0",
        database_checksum_sha256=hashlib.sha256(database_payload).hexdigest(),
    )
    backup_path = _write_encrypted_archive(
        tmp_path / "invalid-sqlite.tar.enc",
        [
            _regular_member("database.sqlite3", database_payload),
            _regular_member("manifest.json", json.dumps(manifest).encode("utf-8")),
        ],
    )

    service = BackupService(app_version="0.1.0")
    with pytest.raises(ValueError, match="database"):
        service.restore(backup_path=backup_path, target_db_path=target_path)

    assert not target_path.exists()


def test_restore_rejects_checksum_mismatch_before_writing_target(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("APP_SECRET_KEY", STRONG_SECRET)
    db_path = tmp_path / "source.sqlite3"
    target_path = tmp_path / "restored.sqlite3"
    _create_database(db_path)

    service = BackupService(app_version="0.1.0")
    backup_path = service.create(db_path=db_path, output_dir=tmp_path / "backups")

    manifest = service.verify(backup_path)
    manifest["database_checksum_sha256"] = hashlib.sha256(b"other").hexdigest()
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w") as tar:
        db_payload = db_path.read_bytes()
        db_info = tarfile.TarInfo("database.sqlite3")
        db_info.size = len(db_payload)
        tar.addfile(db_info, io.BytesIO(db_payload))
        manifest_payload = json.dumps(manifest).encode("utf-8")
        manifest_info = tarfile.TarInfo("manifest.json")
        manifest_info.size = len(manifest_payload)
        tar.addfile(manifest_info, io.BytesIO(manifest_payload))

    box = SecretBox.from_app_secret(STRONG_SECRET)
    tampered_backup = tmp_path / "tampered.tar.enc"
    tampered_backup.write_bytes(box._fernet.encrypt(archive.getvalue()))

    with pytest.raises(ValueError, match="checksum"):
        service.restore(backup_path=tampered_backup, target_db_path=target_path)

    assert not target_path.exists()


def test_verify_rejects_archive_with_extra_member(tmp_path, monkeypatch):
    monkeypatch.setenv("APP_SECRET_KEY", STRONG_SECRET)
    db_path = tmp_path / "source.sqlite3"
    _create_database(db_path)

    service = BackupService(app_version="0.1.0")
    backup_path = service.create(db_path=db_path, output_dir=tmp_path / "backups")
    manifest_payload = json.dumps(service.verify(backup_path)).encode("utf-8")
    tampered_backup = _write_encrypted_archive(
        tmp_path / "extra-member.tar.enc",
        [
            _regular_member("database.sqlite3", db_path.read_bytes()),
            _regular_member("manifest.json", manifest_payload),
            _regular_member("leaked.conf", b"private config"),
        ],
    )

    with pytest.raises(ValueError, match="unexpected.*members"):
        service.verify(tampered_backup)


def test_verify_rejects_non_regular_database_member(tmp_path, monkeypatch):
    monkeypatch.setenv("APP_SECRET_KEY", STRONG_SECRET)
    db_path = tmp_path / "source.sqlite3"
    _create_database(db_path)

    service = BackupService(app_version="0.1.0")
    backup_path = service.create(db_path=db_path, output_dir=tmp_path / "backups")
    manifest_payload = json.dumps(service.verify(backup_path)).encode("utf-8")
    symlink_info = tarfile.TarInfo("database.sqlite3")
    symlink_info.type = tarfile.SYMTYPE
    symlink_info.linkname = "outside.sqlite3"
    tampered_backup = _write_encrypted_archive(
        tmp_path / "symlink-member.tar.enc",
        [
            (symlink_info, None),
            _regular_member("manifest.json", manifest_payload),
        ],
    )

    with pytest.raises(ValueError, match="regular file"):
        service.verify(tampered_backup)
