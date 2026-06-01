import json

import pytest

from app.backup.policy import (
    BackupPolicyError,
    build_backup_policy_manifest,
    create_import_preview,
    create_restore_preview,
    secret_field_sources,
    validate_backup_mode_request,
)


SECRET_FIELD_SOURCES = {
    "api_tokens.token_hash",
    "config_share_tokens.token_hash",
    "email_recovery_tokens.token_hash",
    "devices.peer_private_key_encrypted",
    "devices.preshared_key_encrypted",
    "web_admin_password_hash",
    "generated_config_artifacts.wireguard_conf",
    "generated_config_artifacts.qr_payload",
    "generated_config_artifacts.qr_png",
    "generated_config_artifacts.vpn_import_link",
}


def _json_text(value):
    return json.dumps(value, sort_keys=True)


def test_metadata_export_policy_is_default_safe_and_excludes_secret_bearing_state():
    policy = validate_backup_mode_request("metadata-export")
    manifest = build_backup_policy_manifest("metadata-export")

    assert policy.mode == "metadata-export"
    assert policy.default_for_web is True
    assert policy.default_for_api is True
    assert policy.requires_explicit_dangerous_confirmation is False
    assert set(secret_field_sources()) == SECRET_FIELD_SOURCES
    assert SECRET_FIELD_SOURCES <= set(manifest["secret_field_sources"])
    assert "schema_metadata" in manifest["includes"]
    assert "database_rows" not in manifest["includes"]
    assert manifest["restore"]["status"] == "preview-only"
    assert manifest["restore"]["apply_allowed"] is False
    assert manifest["restore"]["revives_tokens"] is False
    assert manifest["restore"]["revives_config_secrets"] is False


def test_redacted_backup_policy_does_not_restore_tokens_or_generated_configs():
    policy = validate_backup_mode_request("redacted-backup")
    manifest = build_backup_policy_manifest("redacted-backup")

    assert policy.mode == "redacted-backup"
    assert policy.requires_explicit_dangerous_confirmation is False
    assert policy.revives_tokens is False
    assert policy.revives_config_secrets is False
    assert "redacted_database_rows" in manifest["includes"]
    assert SECRET_FIELD_SOURCES <= set(manifest["excludes"])
    assert manifest["restore"]["apply_allowed"] is False
    assert manifest["restore"]["revives_tokens"] is False
    assert manifest["restore"]["revives_config_secrets"] is False


def test_encrypted_full_backup_requires_explicit_dangerous_confirmation():
    with pytest.raises(BackupPolicyError, match="explicit dangerous confirmation"):
        validate_backup_mode_request("encrypted-full-backup")

    policy = validate_backup_mode_request(
        "encrypted-full-backup",
        explicit_dangerous=True,
    )
    manifest = build_backup_policy_manifest(
        "encrypted-full-backup",
        explicit_dangerous=True,
    )

    assert policy.requires_encryption is True
    assert policy.requires_explicit_dangerous_confirmation is True
    assert policy.default_for_web is False
    assert policy.default_for_api is False
    assert manifest["restore"]["status"] == "preview-only"
    assert manifest["restore"]["apply_allowed"] is False
    assert manifest["restore"]["requires_explicit_apply_confirmation"] is True


def test_restore_preview_is_side_effect_free_and_drops_raw_secret_like_values():
    source_manifest = {
        "mode": "redacted-backup",
        "counts": {"users": 3, "devices": 5},
        "token_hash": "RAW-TOKEN-HASH-SHOULD-NOT-LEAK",
        "peer_private_key_encrypted": "RAW-PRIVATE-KEY-SHOULD-NOT-LEAK",
        "preshared_key_encrypted": "RAW-PSK-SHOULD-NOT-LEAK",
        "wireguard_conf": "[Interface]\nPrivateKey = RAW-CONFIG-SHOULD-NOT-LEAK",
        "qr_payload": "RAW-QR-PAYLOAD-SHOULD-NOT-LEAK",
        "vpn_import_link": "vpn://RAW-VPN-LINK-SHOULD-NOT-LEAK",
    }
    target_summary = {"counts": {"users": 1, "devices": 2}}

    preview = create_restore_preview(
        source_manifest=source_manifest,
        target_summary=target_summary,
        requested_mode="redacted-backup",
    )
    metadata = preview.safe_metadata()

    assert metadata["operation"] == "restore-preview"
    assert metadata["status"] == "preview-only"
    assert metadata["apply_allowed"] is False
    assert metadata["side_effects"] == []
    assert metadata["source_counts"] == {"users": 3, "devices": 5}
    assert metadata["target_counts"] == {"users": 1, "devices": 2}
    assert "target_state_exists" in metadata["warnings"]
    assert "restore_apply_blocked" in metadata["warnings"]

    rendered = _json_text(metadata)
    assert "RAW-TOKEN-HASH-SHOULD-NOT-LEAK" not in rendered
    assert "RAW-PRIVATE-KEY-SHOULD-NOT-LEAK" not in rendered
    assert "RAW-PSK-SHOULD-NOT-LEAK" not in rendered
    assert "RAW-CONFIG-SHOULD-NOT-LEAK" not in rendered
    assert "RAW-QR-PAYLOAD-SHOULD-NOT-LEAK" not in rendered
    assert "RAW-VPN-LINK-SHOULD-NOT-LEAK" not in rendered


def test_import_preview_reports_conflicts_without_apply_or_secret_echo():
    preview = create_import_preview(
        source_summary={
            "counts": {"users": 2, "devices": 4},
            "raw_config": "vpn://RAW-IMPORT-LINK-SHOULD-NOT-LEAK",
        },
        target_summary={"counts": {"users": 1, "servers": 1}},
        import_kind="existing-state",
    )
    metadata = preview.safe_metadata()

    assert metadata["operation"] == "import-preview"
    assert metadata["status"] == "preview-only"
    assert metadata["requested_mode"] == "existing-state"
    assert metadata["apply_allowed"] is False
    assert metadata["side_effects"] == []
    assert "target_state_exists" in metadata["warnings"]
    assert "import_apply_blocked" in metadata["warnings"]
    assert "vpn://RAW-IMPORT-LINK-SHOULD-NOT-LEAK" not in _json_text(metadata)


def test_import_preview_rejects_unsupported_import_kind_without_echoing_source():
    with pytest.raises(BackupPolicyError, match="Unsupported import kind"):
        create_import_preview(
            source_summary={
                "counts": {"users": 2},
                "raw_config": "vpn://RAW-UNSUPPORTED-IMPORT-SHOULD-NOT-LEAK",
            },
            target_summary=None,
            import_kind="raw-config-dump",
        )
