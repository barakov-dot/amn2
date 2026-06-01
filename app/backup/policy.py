from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Literal


BackupMode = Literal["metadata-export", "redacted-backup", "encrypted-full-backup"]
SecretFieldAction = Literal["exclude", "encrypted-only"]
PreviewOperation = Literal["restore-preview", "import-preview"]
ImportKind = Literal["existing-state"]


class BackupPolicyError(ValueError):
    pass


@dataclass(frozen=True)
class SecretFieldPolicy:
    source: str
    secret_class: str
    action: SecretFieldAction
    reason: str

    def safe_metadata(self) -> dict[str, str]:
        return {
            "source": self.source,
            "secret_class": self.secret_class,
            "action": self.action,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class BackupModePolicy:
    mode: BackupMode
    includes: tuple[str, ...]
    excludes: tuple[str, ...]
    requires_encryption: bool
    requires_explicit_dangerous_confirmation: bool
    default_for_web: bool
    default_for_api: bool
    revives_tokens: bool
    revives_config_secrets: bool
    requires_explicit_apply_confirmation: bool
    notes: str

    def safe_metadata(self) -> dict[str, object]:
        return {
            "mode": self.mode,
            "includes": list(self.includes),
            "excludes": list(self.excludes),
            "requires_encryption": self.requires_encryption,
            "requires_explicit_dangerous_confirmation": (
                self.requires_explicit_dangerous_confirmation
            ),
            "default_for_web": self.default_for_web,
            "default_for_api": self.default_for_api,
            "revives_tokens": self.revives_tokens,
            "revives_config_secrets": self.revives_config_secrets,
            "restore": _restore_contract(self),
            "notes": self.notes,
        }


@dataclass(frozen=True)
class BackupPreview:
    operation: PreviewOperation
    requested_mode: str
    source_counts: Mapping[str, int] = field(default_factory=dict)
    target_counts: Mapping[str, int] = field(default_factory=dict)
    warnings: tuple[str, ...] = ()
    status: str = "preview-only"
    apply_allowed: bool = False
    side_effects: tuple[str, ...] = ()

    def safe_metadata(self) -> dict[str, object]:
        return {
            "operation": self.operation,
            "requested_mode": self.requested_mode,
            "status": self.status,
            "apply_allowed": self.apply_allowed,
            "side_effects": list(self.side_effects),
            "source_counts": dict(self.source_counts),
            "target_counts": dict(self.target_counts),
            "warnings": list(self.warnings),
        }


EXTERNAL_SECRET_EXCLUDES: tuple[str, ...] = (
    "app_secret_key",
    "telegram_bot_token",
)

GENERATED_CONFIG_ARTIFACTS: tuple[str, ...] = (
    "generated_config_artifacts.wireguard_conf",
    "generated_config_artifacts.qr_payload",
    "generated_config_artifacts.qr_png",
    "generated_config_artifacts.vpn_import_link",
)

SECRET_FIELD_POLICIES: tuple[SecretFieldPolicy, ...] = (
    SecretFieldPolicy(
        source="api_tokens.token_hash",
        secret_class="token-hash",
        action="exclude",
        reason="hashes cannot be revived into a broader API surface by default",
    ),
    SecretFieldPolicy(
        source="config_share_tokens.token_hash",
        secret_class="public-token-hash",
        action="exclude",
        reason="share-token state is one-time/purpose-bound and must not revive silently",
    ),
    SecretFieldPolicy(
        source="email_recovery_tokens.token_hash",
        secret_class="public-token-hash",
        action="exclude",
        reason="recovery-token state is short-lived and must not revive silently",
    ),
    SecretFieldPolicy(
        source="devices.peer_private_key_encrypted",
        secret_class="client-config-secret",
        action="exclude",
        reason="private keys are only allowed in explicit encrypted-full-backup mode",
    ),
    SecretFieldPolicy(
        source="devices.preshared_key_encrypted",
        secret_class="client-config-secret",
        action="exclude",
        reason="preshared keys are only allowed in explicit encrypted-full-backup mode",
    ),
    SecretFieldPolicy(
        source="web_admin_password_hash",
        secret_class="credential-hash",
        action="exclude",
        reason="admin credential state must be recreated or rotated after import",
    ),
    SecretFieldPolicy(
        source="generated_config_artifacts.wireguard_conf",
        secret_class="client-config-secret",
        action="exclude",
        reason="generated configs are delivery artifacts, not backup metadata",
    ),
    SecretFieldPolicy(
        source="generated_config_artifacts.qr_payload",
        secret_class="client-config-secret",
        action="exclude",
        reason="QR payloads can embed the same secret material as .conf files",
    ),
    SecretFieldPolicy(
        source="generated_config_artifacts.qr_png",
        secret_class="client-config-secret",
        action="exclude",
        reason="QR images can embed the same secret material as .conf files",
    ),
    SecretFieldPolicy(
        source="generated_config_artifacts.vpn_import_link",
        secret_class="client-config-secret",
        action="exclude",
        reason="vpn:// import links are client config secrets",
    ),
)

_SECRET_FIELD_SOURCES = tuple(policy.source for policy in SECRET_FIELD_POLICIES)
_REDACTED_EXCLUDES = EXTERNAL_SECRET_EXCLUDES + _SECRET_FIELD_SOURCES
_FULL_BACKUP_EXCLUDES = EXTERNAL_SECRET_EXCLUDES + GENERATED_CONFIG_ARTIFACTS

BACKUP_MODE_POLICIES: tuple[BackupModePolicy, ...] = (
    BackupModePolicy(
        mode="metadata-export",
        includes=("schema_metadata", "table_counts", "policy_manifest"),
        excludes=("database_rows",) + _REDACTED_EXCLUDES,
        requires_encryption=False,
        requires_explicit_dangerous_confirmation=False,
        default_for_web=True,
        default_for_api=True,
        revives_tokens=False,
        revives_config_secrets=False,
        requires_explicit_apply_confirmation=False,
        notes="Default safe export: counts and schema metadata only.",
    ),
    BackupModePolicy(
        mode="redacted-backup",
        includes=("redacted_database_rows", "schema_metadata", "table_counts", "policy_manifest"),
        excludes=_REDACTED_EXCLUDES,
        requires_encryption=True,
        requires_explicit_dangerous_confirmation=False,
        default_for_web=False,
        default_for_api=False,
        revives_tokens=False,
        revives_config_secrets=False,
        requires_explicit_apply_confirmation=True,
        notes="Redacted state export: no token hashes, keys, generated configs, or admin credential hash.",
    ),
    BackupModePolicy(
        mode="encrypted-full-backup",
        includes=("encrypted_database", "manifest", "policy_manifest"),
        excludes=_FULL_BACKUP_EXCLUDES,
        requires_encryption=True,
        requires_explicit_dangerous_confirmation=True,
        default_for_web=False,
        default_for_api=False,
        revives_tokens=True,
        revives_config_secrets=True,
        requires_explicit_apply_confirmation=True,
        notes="Dangerous full state export; never a default web/API mode.",
    ),
)

_POLICY_BY_MODE = {policy.mode: policy for policy in BACKUP_MODE_POLICIES}


def secret_field_sources() -> tuple[str, ...]:
    return _SECRET_FIELD_SOURCES


def get_backup_mode_policy(mode: str) -> BackupModePolicy:
    try:
        return _POLICY_BY_MODE[mode]
    except KeyError as exc:
        raise BackupPolicyError(f"Unsupported backup mode: {mode}") from exc


def validate_backup_mode_request(
    mode: str,
    *,
    explicit_dangerous: bool = False,
) -> BackupModePolicy:
    policy = get_backup_mode_policy(mode)
    if policy.requires_explicit_dangerous_confirmation and not explicit_dangerous:
        raise BackupPolicyError(
            f"{mode} requires explicit dangerous confirmation"
        )
    return policy


def build_backup_policy_manifest(
    mode: str,
    *,
    explicit_dangerous: bool = False,
) -> dict[str, object]:
    policy = validate_backup_mode_request(
        mode,
        explicit_dangerous=explicit_dangerous,
    )
    metadata = policy.safe_metadata()
    metadata.update(
        {
            "policy_version": 1,
            "secret_field_sources": list(_SECRET_FIELD_SOURCES),
            "secret_field_actions": [
                field_policy.safe_metadata()
                for field_policy in SECRET_FIELD_POLICIES
            ],
        }
    )
    return metadata


def create_restore_preview(
    *,
    source_manifest: Mapping[str, object],
    target_summary: Mapping[str, object] | None,
    requested_mode: str,
    explicit_dangerous: bool = False,
) -> BackupPreview:
    policy = validate_backup_mode_request(
        requested_mode,
        explicit_dangerous=explicit_dangerous,
    )
    warnings = _preview_warnings(
        operation="restore-preview",
        target_counts=_safe_counts(target_summary),
        policy=policy,
    )
    return BackupPreview(
        operation="restore-preview",
        requested_mode=policy.mode,
        source_counts=_safe_counts(source_manifest),
        target_counts=_safe_counts(target_summary),
        warnings=warnings,
    )


def create_import_preview(
    *,
    source_summary: Mapping[str, object],
    target_summary: Mapping[str, object] | None,
    import_kind: ImportKind | str,
) -> BackupPreview:
    if import_kind != "existing-state":
        raise BackupPolicyError(f"Unsupported import kind: {import_kind}")
    warnings = _preview_warnings(
        operation="import-preview",
        target_counts=_safe_counts(target_summary),
        policy=None,
    )
    return BackupPreview(
        operation="import-preview",
        requested_mode=import_kind,
        source_counts=_safe_counts(source_summary),
        target_counts=_safe_counts(target_summary),
        warnings=warnings,
    )


def _restore_contract(policy: BackupModePolicy) -> dict[str, object]:
    return {
        "status": "preview-only",
        "apply_allowed": False,
        "revives_tokens": policy.revives_tokens,
        "revives_config_secrets": policy.revives_config_secrets,
        "requires_explicit_apply_confirmation": (
            policy.requires_explicit_apply_confirmation
        ),
    }


def _preview_warnings(
    *,
    operation: PreviewOperation,
    target_counts: Mapping[str, int],
    policy: BackupModePolicy | None,
) -> tuple[str, ...]:
    warnings: list[str] = []
    if any(count > 0 for count in target_counts.values()):
        warnings.append("target_state_exists")
    if policy is not None and not policy.revives_tokens:
        warnings.append("token_state_not_revived")
    if policy is not None and not policy.revives_config_secrets:
        warnings.append("config_secrets_not_revived")
    if operation == "restore-preview":
        warnings.append("restore_apply_blocked")
    else:
        warnings.append("import_apply_blocked")
    return tuple(warnings)


def _safe_counts(summary: Mapping[str, object] | None) -> dict[str, int]:
    if not isinstance(summary, Mapping):
        return {}
    counts = summary.get("counts")
    if not isinstance(counts, Mapping):
        return {}

    safe: dict[str, int] = {}
    for key, value in counts.items():
        if not isinstance(key, str):
            continue
        if isinstance(value, bool) or not isinstance(value, int):
            continue
        if value < 0:
            continue
        safe[key] = value
    return safe
