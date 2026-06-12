from __future__ import annotations

import hashlib
import json
import re
import shutil
import struct
from pathlib import Path
from typing import Any


BOT_KINDS = {"access", "support", "news"}
SURFACES = {"start_header", "profile_icon"}
ACCEPTED_MIME_TYPES = {"image/png", "image/jpeg", "image/webp"}
MAX_IMAGE_BYTES = 10 * 1024 * 1024
BLOCKED_FILENAME_MARKERS = ("conf", "config", "qr", "vpn", "private", "preshared")


class BotMediaValidationError(ValueError):
    pass


class BotMediaRegistry:
    def __init__(self, *, registry_path: Path, media_root: Path) -> None:
        self.registry_path = registry_path
        self.media_root = media_root

    def validate(self, *, bot_kind: str, surface: str, path: Path) -> dict[str, Any]:
        bot_kind = _validate_choice("bot_kind", bot_kind, BOT_KINDS)
        surface = _validate_choice("surface", surface, SURFACES)
        path = Path(path)
        _reject_remote_path(path)
        if not path.is_file():
            raise BotMediaValidationError(f"image file does not exist: {path}")
        source_filename = _safe_filename(path.name)
        _reject_private_filename(source_filename)
        data = path.read_bytes()
        if len(data) > MAX_IMAGE_BYTES:
            raise BotMediaValidationError("image file is larger than 10 MB")
        mime_type, width_px, height_px = _inspect_image(data)
        if mime_type not in ACCEPTED_MIME_TYPES:
            raise BotMediaValidationError(f"unsupported image type: {mime_type}")
        _validate_dimensions(surface, width_px, height_px)
        content_sha256 = hashlib.sha256(data).hexdigest().upper()
        asset_id = f"{bot_kind}-{surface}-{content_sha256[:12].lower()}"
        return {
            "asset_id": asset_id,
            "bot_kind": bot_kind,
            "surface": surface,
            "source_filename": source_filename,
            "content_sha256": content_sha256,
            "mime_type": mime_type,
            "byte_size": len(data),
            "width_px": width_px,
            "height_px": height_px,
            "validation_status": "valid",
            "selected_for_runtime": False,
            "apply_status": (
                "staged-for-operator" if surface == "profile_icon" else "local-only"
            ),
            "local_only": True,
            "telegram_api_called": False,
        }

    def stage(self, *, bot_kind: str, surface: str, path: Path) -> dict[str, Any]:
        asset = self.validate(bot_kind=bot_kind, surface=surface, path=path)
        staged_dir = self.media_root / asset["asset_id"]
        staged_dir.mkdir(parents=True, exist_ok=True)
        staged_path = staged_dir / asset["source_filename"]
        shutil.copyfile(path, staged_path)
        asset["staged_relative_path"] = (
            f"data/bot-media/{asset['asset_id']}/{asset['source_filename']}"
        )
        manifest = self._load_manifest()
        manifest["assets"][asset["asset_id"]] = asset
        self._save_manifest(manifest)
        return asset

    def select(self, *, bot_kind: str, surface: str, asset_id: str) -> dict[str, Any]:
        bot_kind = _validate_choice("bot_kind", bot_kind, BOT_KINDS)
        surface = _validate_choice("surface", surface, SURFACES)
        manifest = self._load_manifest()
        asset = manifest["assets"].get(asset_id)
        if asset is None:
            raise BotMediaValidationError(f"unknown asset_id: {asset_id}")
        if asset["bot_kind"] != bot_kind or asset["surface"] != surface:
            raise BotMediaValidationError("asset does not match requested bot/surface")
        manifest["selections"][f"{bot_kind}:{surface}"] = asset_id
        for item in manifest["assets"].values():
            if item["bot_kind"] == bot_kind and item["surface"] == surface:
                item["selected_for_runtime"] = item["asset_id"] == asset_id
        self._save_manifest(manifest)
        return manifest["assets"][asset_id]

    def manifest(self) -> dict[str, Any]:
        manifest = self._load_manifest()
        manifest["safety"] = _safety()
        return manifest

    def _load_manifest(self) -> dict[str, Any]:
        if not self.registry_path.exists():
            return {"version": 1, "assets": {}, "selections": {}, "safety": _safety()}
        data = json.loads(self.registry_path.read_text(encoding="utf-8"))
        data.setdefault("version", 1)
        data.setdefault("assets", {})
        data.setdefault("selections", {})
        data["safety"] = _safety()
        return data

    def _save_manifest(self, manifest: dict[str, Any]) -> None:
        self.registry_path.parent.mkdir(parents=True, exist_ok=True)
        manifest["safety"] = _safety()
        self.registry_path.write_text(
            json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )


def _safety() -> dict[str, bool]:
    return {
        "local_only": True,
        "telegram_api_called": False,
        "telegram_secret_stored": False,
        "public_upload_route": False,
        "live_vps_commands": False,
    }


def _validate_choice(name: str, value: str, allowed: set[str]) -> str:
    if value not in allowed:
        raise BotMediaValidationError(
            f"{name} must be one of: {', '.join(sorted(allowed))}"
        )
    return value


def _reject_remote_path(path: Path) -> None:
    value = path.as_posix().lower()
    if value.startswith(("http://", "https://")):
        raise BotMediaValidationError("remote URL upload is disabled")


def _safe_filename(name: str) -> str:
    original = Path(name)
    safe_stem = re.sub(r"[^A-Za-z0-9._-]+", "-", original.stem).strip(".-_")
    if not safe_stem:
        safe_stem = "asset"
    return f"{safe_stem}{original.suffix.lower()}"


def _reject_private_filename(name: str) -> None:
    lowered = name.lower()
    if any(marker in lowered for marker in BLOCKED_FILENAME_MARKERS):
        raise BotMediaValidationError(
            "image filename suggests config, QR, vpn or secret-bearing material"
        )


def _validate_dimensions(surface: str, width: int, height: int) -> None:
    if surface == "profile_icon":
        if width < 512 or height < 512 or width != height:
            raise BotMediaValidationError(
                "profile_icon must be square and at least 512x512"
            )
        return
    if width < 512 and height < 512:
        raise BotMediaValidationError("start_header must be at least 512px wide or tall")


def _inspect_image(data: bytes) -> tuple[str, int, int]:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        if len(data) < 24:
            raise BotMediaValidationError("invalid PNG image")
        width, height = struct.unpack(">II", data[16:24])
        return "image/png", width, height
    if data.startswith(b"\xff\xd8"):
        return _inspect_jpeg(data)
    if data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        return _inspect_webp(data)
    raise BotMediaValidationError("unsupported or unreadable image")


def _inspect_jpeg(data: bytes) -> tuple[str, int, int]:
    index = 2
    while index + 9 < len(data):
        if data[index] != 0xFF:
            index += 1
            continue
        marker = data[index + 1]
        index += 2
        if marker in {0xD8, 0xD9}:
            continue
        if index + 2 > len(data):
            break
        segment_length = struct.unpack(">H", data[index : index + 2])[0]
        if segment_length < 2 or index + segment_length > len(data):
            break
        if marker in {
            0xC0,
            0xC1,
            0xC2,
            0xC3,
            0xC5,
            0xC6,
            0xC7,
            0xC9,
            0xCA,
            0xCB,
            0xCD,
            0xCE,
            0xCF,
        }:
            height, width = struct.unpack(">HH", data[index + 3 : index + 7])
            return "image/jpeg", width, height
        index += segment_length
    raise BotMediaValidationError("invalid JPEG image")


def _inspect_webp(data: bytes) -> tuple[str, int, int]:
    chunk = data[12:16]
    if chunk == b"VP8X" and len(data) >= 30:
        width = int.from_bytes(data[24:27], "little") + 1
        height = int.from_bytes(data[27:30], "little") + 1
        return "image/webp", width, height
    if chunk == b"VP8 " and len(data) >= 30:
        width, height = struct.unpack("<HH", data[26:30])
        return "image/webp", width & 0x3FFF, height & 0x3FFF
    if chunk == b"VP8L" and len(data) >= 25:
        bits = int.from_bytes(data[21:25], "little")
        width = (bits & 0x3FFF) + 1
        height = ((bits >> 14) & 0x3FFF) + 1
        return "image/webp", width, height
    raise BotMediaValidationError("invalid WebP image")
