import hashlib
from pathlib import Path
from typing import Any


FORMAT_VERSION = 1
APP_NAME = "amneziya"
DATABASE_KIND = "sqlite"
INCLUDES = ["database", "manifest"]
EXCLUDES = [
    "app_secret_key",
    "telegram_bot_token",
    "qr_files",
    "plain_configs",
    "usable_config_share_token_hashes",
]
LEGACY_EXCLUDES = [
    "app_secret_key",
    "telegram_bot_token",
    "qr_files",
    "plain_configs",
]


def checksum_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(app_version: str, database_checksum_sha256: str) -> dict[str, Any]:
    return {
        "format_version": FORMAT_VERSION,
        "app": APP_NAME,
        "app_version": app_version,
        "database_kind": DATABASE_KIND,
        "database_checksum_sha256": database_checksum_sha256,
        "includes": INCLUDES,
        "excludes": EXCLUDES,
    }


def validate_manifest(manifest: dict[str, Any]) -> None:
    if manifest.get("format_version") != FORMAT_VERSION:
        raise ValueError("Unsupported backup manifest format_version")
    if manifest.get("app") != APP_NAME:
        raise ValueError("Unsupported backup app")
    if manifest.get("database_kind") != DATABASE_KIND:
        raise ValueError("Unsupported backup database_kind")
    if manifest.get("includes") != INCLUDES:
        raise ValueError("Unexpected backup includes")
    if manifest.get("excludes") not in (EXCLUDES, LEGACY_EXCLUDES):
        raise ValueError("Unexpected backup excludes")
    checksum = manifest.get("database_checksum_sha256")
    if not isinstance(checksum, str) or len(checksum) != 64:
        raise ValueError("Invalid database checksum")
