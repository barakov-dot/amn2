import json

from app.backup.policy import secret_field_sources
from app.security.secret_inventory import (
    SECRET_INVENTORY,
    SecretInventoryError,
    build_secret_inventory_manifest,
    entries_by_secret_class,
    entries_by_storage_surface,
    get_secret_inventory_entry,
)


REQUIRED_INVENTORY_IDS = {
    "env.app_secret_key",
    "env.telegram_bot_token",
    "env.vps_ssh_password",
    "env.smtp_password",
    "setting.web_admin_password_hash",
    "setting.web_admin_session_secret",
    "setting.local_agent_token_hash",
    "db.api_tokens.token_hash",
    "db.config_share_tokens.token_hash",
    "db.email_recovery_tokens.token_hash",
    "db.devices.peer_private_key_encrypted",
    "db.devices.preshared_key_encrypted",
    "generated_config_artifacts.wireguard_conf",
    "generated_config_artifacts.qr_payload",
    "generated_config_artifacts.qr_png",
    "generated_config_artifacts.vpn_import_link",
    "remote_operation.output",
    "audit.admin_actions.metadata_json",
}

BLOCKED_SECRET_CLASSES = {
    "credential-secret",
    "session-secret",
    "token-hash",
    "client-config-secret",
}


def _json_text(value):
    return json.dumps(value, sort_keys=True)


def test_required_secret_inventory_entries_exist_and_are_unique():
    actual_ids = {entry.inventory_id for entry in SECRET_INVENTORY}

    assert REQUIRED_INVENTORY_IDS <= actual_ids
    assert len(actual_ids) == len(SECRET_INVENTORY)


def test_secret_inventory_metadata_is_safe_and_policy_oriented():
    manifest = build_secret_inventory_manifest()
    rendered = _json_text(manifest)

    assert manifest["policy_version"] == 1
    assert len(manifest["entries"]) == len(SECRET_INVENTORY)
    assert "sample_value" not in rendered
    assert "example_secret" not in rendered
    assert "vpn://REAL" not in rendered
    assert "[Interface]" not in rendered

    for entry in SECRET_INVENTORY:
        metadata = entry.safe_metadata()

        assert metadata["inventory_id"] == entry.inventory_id
        assert metadata["source_ref"] == entry.source_ref
        assert metadata["raw_value_allowed_in_safe_metadata"] is False
        assert metadata["redaction_required"] is True
        assert "raw_value" not in metadata
        assert "sample_value" not in metadata


def test_secret_inventory_covers_backup_policy_secret_sources():
    inventory_sources = {entry.source_ref: entry for entry in SECRET_INVENTORY}

    for source in secret_field_sources():
        entry = inventory_sources[source]

        assert entry.backup_default in {"exclude", "encrypted-only"}
        assert entry.restore_default in {
            "restore-disabled",
            "rotate",
            "reconfigure",
            "regenerate",
            "explicit-confirmation-only",
        }
        assert entry.route_exposure == "blocked"


def test_config_artifacts_are_blocked_client_config_secrets():
    for inventory_id in (
        "generated_config_artifacts.wireguard_conf",
        "generated_config_artifacts.qr_payload",
        "generated_config_artifacts.qr_png",
        "generated_config_artifacts.vpn_import_link",
    ):
        entry = get_secret_inventory_entry(inventory_id)

        assert entry.secret_class == "client-config-secret"
        assert entry.storage_surface == "generated-artifact"
        assert entry.backup_default == "exclude"
        assert entry.restore_default == "regenerate"
        assert entry.route_exposure == "blocked"


def test_token_hashes_are_never_active_after_redacted_restore():
    for entry in entries_by_secret_class("token-hash"):
        assert entry.backup_default == "exclude"
        assert entry.restore_default in {"restore-disabled", "rotate"}
        assert entry.route_exposure == "blocked"
        assert "token" in entry.source_ref.lower()


def test_inventory_filters_and_lookup_fail_closed():
    sqlite_entries = entries_by_storage_surface("sqlite")
    client_config_entries = entries_by_secret_class("client-config-secret")

    assert {entry.inventory_id for entry in sqlite_entries} >= {
        "db.api_tokens.token_hash",
        "db.devices.peer_private_key_encrypted",
    }
    assert {entry.inventory_id for entry in client_config_entries} >= {
        "db.devices.peer_private_key_encrypted",
        "generated_config_artifacts.vpn_import_link",
    }

    try:
        get_secret_inventory_entry("missing.secret")
    except SecretInventoryError as exc:
        assert "missing.secret" in str(exc)
    else:
        raise AssertionError("missing secret inventory lookup must fail closed")


def test_blocked_secret_classes_are_not_route_exposed():
    for entry in SECRET_INVENTORY:
        if entry.secret_class in BLOCKED_SECRET_CLASSES:
            assert entry.route_exposure == "blocked"
            assert entry.raw_value_allowed_in_safe_metadata is False
