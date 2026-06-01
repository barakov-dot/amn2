from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


SecretClass = Literal[
    "credential-secret",
    "credential-hash",
    "session-secret",
    "token-hash",
    "client-config-secret",
    "operation-output",
    "topology-sensitive",
]
StorageSurface = Literal[
    "env",
    "settings",
    "sqlite",
    "generated-artifact",
    "audit-log",
    "remote-output",
]
BackupDefault = Literal[
    "exclude",
    "encrypted-only",
    "redact",
    "metadata-only",
]
RestoreDefault = Literal[
    "never-restore",
    "restore-disabled",
    "rotate",
    "reconfigure",
    "regenerate",
    "revalidate",
    "explicit-confirmation-only",
]
RouteExposure = Literal["blocked", "internal-only"]


class SecretInventoryError(ValueError):
    pass


@dataclass(frozen=True)
class SecretInventoryEntry:
    inventory_id: str
    source_ref: str
    secret_class: SecretClass
    storage_surface: StorageSurface
    backup_default: BackupDefault
    restore_default: RestoreDefault
    route_exposure: RouteExposure = "blocked"
    redaction_required: bool = True
    raw_value_allowed_in_safe_metadata: bool = False
    notes: str = ""

    def safe_metadata(self) -> dict[str, object]:
        return {
            "inventory_id": self.inventory_id,
            "source_ref": self.source_ref,
            "secret_class": self.secret_class,
            "storage_surface": self.storage_surface,
            "backup_default": self.backup_default,
            "restore_default": self.restore_default,
            "route_exposure": self.route_exposure,
            "redaction_required": self.redaction_required,
            "raw_value_allowed_in_safe_metadata": self.raw_value_allowed_in_safe_metadata,
            "notes": self.notes,
        }


SECRET_INVENTORY: tuple[SecretInventoryEntry, ...] = (
    SecretInventoryEntry(
        inventory_id="env.app_secret_key",
        source_ref="APP_SECRET_KEY",
        secret_class="credential-secret",
        storage_surface="env",
        backup_default="exclude",
        restore_default="reconfigure",
        notes="Application encryption root; never copied into support metadata.",
    ),
    SecretInventoryEntry(
        inventory_id="env.telegram_bot_token",
        source_ref="TELEGRAM_BOT_TOKEN",
        secret_class="credential-secret",
        storage_surface="env",
        backup_default="exclude",
        restore_default="reconfigure",
        notes="Telegram credential; operator-managed environment secret.",
    ),
    SecretInventoryEntry(
        inventory_id="env.telegram_proxy_url",
        source_ref="TELEGRAM_PROXY_URL",
        secret_class="credential-secret",
        storage_surface="env",
        backup_default="exclude",
        restore_default="reconfigure",
        notes="Proxy URL may include embedded credentials.",
    ),
    SecretInventoryEntry(
        inventory_id="env.vps_ssh_password",
        source_ref="VPS_SSH_PASSWORD",
        secret_class="credential-secret",
        storage_surface="env",
        backup_default="exclude",
        restore_default="reconfigure",
        notes="Legacy/operator SSH credential; not suitable for route metadata.",
    ),
    SecretInventoryEntry(
        inventory_id="env.smtp_password",
        source_ref="SMTP_PASSWORD",
        secret_class="credential-secret",
        storage_surface="env",
        backup_default="exclude",
        restore_default="reconfigure",
        notes="SMTP credential; redacted in diagnostics and settings views.",
    ),
    SecretInventoryEntry(
        inventory_id="env.smtp_username",
        source_ref="SMTP_USERNAME",
        secret_class="credential-secret",
        storage_surface="env",
        backup_default="exclude",
        restore_default="reconfigure",
        notes="May be a credential-bearing SMTP login value.",
    ),
    SecretInventoryEntry(
        inventory_id="setting.web_admin_password_hash",
        source_ref="web_admin_password_hash",
        secret_class="credential-hash",
        storage_surface="settings",
        backup_default="exclude",
        restore_default="rotate",
        notes="Password hash must not become an admin-equivalent API artifact.",
    ),
    SecretInventoryEntry(
        inventory_id="setting.web_admin_session_secret",
        source_ref="WEB_ADMIN_SESSION_SECRET",
        secret_class="session-secret",
        storage_surface="settings",
        backup_default="exclude",
        restore_default="reconfigure",
        notes="Session signing secret; recreate rather than restore from support export.",
    ),
    SecretInventoryEntry(
        inventory_id="setting.local_agent_token_hash",
        source_ref="LOCAL_AGENT_TOKEN_HASH",
        secret_class="token-hash",
        storage_surface="settings",
        backup_default="exclude",
        restore_default="rotate",
        notes="Local Agent token hash is scoped to agent routes only.",
    ),
    SecretInventoryEntry(
        inventory_id="db.api_tokens.token_hash",
        source_ref="api_tokens.token_hash",
        secret_class="token-hash",
        storage_surface="sqlite",
        backup_default="exclude",
        restore_default="rotate",
        notes="External API token hashes must not revive active access after redacted restore.",
    ),
    SecretInventoryEntry(
        inventory_id="db.config_share_tokens.token_hash",
        source_ref="config_share_tokens.token_hash",
        secret_class="token-hash",
        storage_surface="sqlite",
        backup_default="exclude",
        restore_default="restore-disabled",
        notes="Public share token hashes are one-time/purpose-bound state.",
    ),
    SecretInventoryEntry(
        inventory_id="db.email_recovery_tokens.token_hash",
        source_ref="email_recovery_tokens.token_hash",
        secret_class="token-hash",
        storage_surface="sqlite",
        backup_default="exclude",
        restore_default="restore-disabled",
        notes="Email verification/recovery token hashes are short-lived public-token state.",
    ),
    SecretInventoryEntry(
        inventory_id="db.devices.peer_private_key_encrypted",
        source_ref="devices.peer_private_key_encrypted",
        secret_class="client-config-secret",
        storage_surface="sqlite",
        backup_default="encrypted-only",
        restore_default="explicit-confirmation-only",
        notes="Peer private key may be present only in explicit encrypted recovery artifacts.",
    ),
    SecretInventoryEntry(
        inventory_id="db.devices.preshared_key_encrypted",
        source_ref="devices.preshared_key_encrypted",
        secret_class="client-config-secret",
        storage_surface="sqlite",
        backup_default="encrypted-only",
        restore_default="explicit-confirmation-only",
        notes="Preshared key may be present only in explicit encrypted recovery artifacts.",
    ),
    SecretInventoryEntry(
        inventory_id="generated_config_artifacts.wireguard_conf",
        source_ref="generated_config_artifacts.wireguard_conf",
        secret_class="client-config-secret",
        storage_surface="generated-artifact",
        backup_default="exclude",
        restore_default="regenerate",
        notes="Generated config text is a delivery artifact, not backup metadata.",
    ),
    SecretInventoryEntry(
        inventory_id="generated_config_artifacts.qr_payload",
        source_ref="generated_config_artifacts.qr_payload",
        secret_class="client-config-secret",
        storage_surface="generated-artifact",
        backup_default="exclude",
        restore_default="regenerate",
        notes="QR payload can embed the same access material as generated config text.",
    ),
    SecretInventoryEntry(
        inventory_id="generated_config_artifacts.qr_png",
        source_ref="generated_config_artifacts.qr_png",
        secret_class="client-config-secret",
        storage_surface="generated-artifact",
        backup_default="exclude",
        restore_default="regenerate",
        notes="QR image can encode client config material.",
    ),
    SecretInventoryEntry(
        inventory_id="generated_config_artifacts.vpn_import_link",
        source_ref="generated_config_artifacts.vpn_import_link",
        secret_class="client-config-secret",
        storage_surface="generated-artifact",
        backup_default="exclude",
        restore_default="regenerate",
        notes="Import link is treated like a client config secret.",
    ),
    SecretInventoryEntry(
        inventory_id="remote_operation.output",
        source_ref="remote_operation.output",
        secret_class="operation-output",
        storage_surface="remote-output",
        backup_default="redact",
        restore_default="never-restore",
        route_exposure="internal-only",
        notes="Remote stdout/stderr may contain credentials or runtime-sensitive values.",
    ),
    SecretInventoryEntry(
        inventory_id="audit.admin_actions.metadata_json",
        source_ref="admin_actions.metadata_json",
        secret_class="operation-output",
        storage_surface="audit-log",
        backup_default="redact",
        restore_default="revalidate",
        route_exposure="internal-only",
        notes="Audit metadata is allowed only after redaction and safe serialization.",
    ),
    SecretInventoryEntry(
        inventory_id="runtime.server_topology",
        source_ref="runtime.server_topology",
        secret_class="topology-sensitive",
        storage_surface="remote-output",
        backup_default="metadata-only",
        restore_default="revalidate",
        route_exposure="internal-only",
        notes="Hostnames, interfaces and container names may expose deployment topology.",
    ),
)

_ENTRY_BY_ID = {entry.inventory_id: entry for entry in SECRET_INVENTORY}


def get_secret_inventory_entry(inventory_id: str) -> SecretInventoryEntry:
    try:
        return _ENTRY_BY_ID[inventory_id]
    except KeyError as exc:
        raise SecretInventoryError(
            f"No secret inventory entry for {inventory_id}"
        ) from exc


def entries_by_secret_class(secret_class: str) -> tuple[SecretInventoryEntry, ...]:
    return tuple(
        entry for entry in SECRET_INVENTORY if entry.secret_class == secret_class
    )


def entries_by_storage_surface(
    storage_surface: str,
) -> tuple[SecretInventoryEntry, ...]:
    return tuple(
        entry
        for entry in SECRET_INVENTORY
        if entry.storage_surface == storage_surface
    )


def build_secret_inventory_manifest() -> dict[str, object]:
    return {
        "policy_version": 1,
        "entries": [entry.safe_metadata() for entry in SECRET_INVENTORY],
    }
