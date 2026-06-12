import json
from pathlib import Path

import pytest

from app.services.bot_media import BotMediaRegistry
from app.services.bot_media import BotMediaValidationError


def test_validate_bot_media_accepts_safe_png_without_writing_registry(tmp_path: Path):
    image_path = tmp_path / "NEOBYATNAYA-AMNZ-SUPPORT-BOT.png"
    image_path.write_bytes(_png_bytes(width=640, height=360))
    registry_path = tmp_path / "registry.json"

    registry = BotMediaRegistry(
        registry_path=registry_path,
        media_root=tmp_path / "media",
    )

    asset = registry.validate(
        bot_kind="support",
        surface="start_header",
        path=image_path,
    )

    assert asset["bot_kind"] == "support"
    assert asset["surface"] == "start_header"
    assert asset["source_filename"] == "NEOBYATNAYA-AMNZ-SUPPORT-BOT.png"
    assert asset["mime_type"] == "image/png"
    assert asset["width_px"] == 640
    assert asset["height_px"] == 360
    assert asset["byte_size"] == len(image_path.read_bytes())
    assert asset["validation_status"] == "valid"
    assert asset["apply_status"] == "local-only"
    assert asset["selected_for_runtime"] is False
    assert asset["local_only"] is True
    assert asset["telegram_api_called"] is False
    assert not registry_path.exists()


def test_stage_and_select_bot_media_records_safe_manifest(tmp_path: Path):
    image_path = tmp_path / "access header.png"
    image_path.write_bytes(_png_bytes(width=768, height=512))
    registry = BotMediaRegistry(
        registry_path=tmp_path / "registry.json",
        media_root=tmp_path / "media",
    )

    staged = registry.stage(
        bot_kind="access",
        surface="start_header",
        path=image_path,
    )
    selected = registry.select(
        bot_kind="access",
        surface="start_header",
        asset_id=staged["asset_id"],
    )
    manifest = registry.manifest()

    assert selected["selected_for_runtime"] is True
    assert selected["asset_id"] == staged["asset_id"]
    assert selected["staged_relative_path"].startswith(
        f"data/bot-media/{staged['asset_id']}/"
    )
    assert " " not in Path(selected["staged_relative_path"]).name
    assert manifest["selections"]["access:start_header"] == staged["asset_id"]
    assert manifest["assets"][staged["asset_id"]]["selected_for_runtime"] is True
    assert "token" not in json.dumps(manifest, ensure_ascii=False).lower()


def test_profile_icon_can_be_staged_but_not_marked_as_applied(tmp_path: Path):
    image_path = tmp_path / "support-icon.png"
    image_path.write_bytes(_png_bytes(width=512, height=512))
    registry = BotMediaRegistry(
        registry_path=tmp_path / "registry.json",
        media_root=tmp_path / "media",
    )

    staged = registry.stage(
        bot_kind="support",
        surface="profile_icon",
        path=image_path,
    )

    assert staged["surface"] == "profile_icon"
    assert staged["apply_status"] == "staged-for-operator"
    assert staged["telegram_api_called"] is False
    assert staged["selected_for_runtime"] is False


def test_rejects_remote_urls_and_config_like_images(tmp_path: Path):
    registry = BotMediaRegistry(
        registry_path=tmp_path / "registry.json",
        media_root=tmp_path / "media",
    )
    config_like_image = tmp_path / "qr-vpn-config.png"
    config_like_image.write_bytes(_png_bytes(width=512, height=512))

    with pytest.raises(BotMediaValidationError):
        registry.validate(
            bot_kind="access",
            surface="start_header",
            path=Path("https://example.com/image.png"),
        )
    with pytest.raises(BotMediaValidationError):
        registry.validate(
            bot_kind="access",
            surface="start_header",
            path=config_like_image,
        )


def _png_bytes(*, width: int, height: int) -> bytes:
    import struct
    import zlib

    signature = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)

    def chunk(kind: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(kind + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", crc)

    row = b"\x00" + (b"\xff\xff\xff" * width)
    raw = row * height
    return signature + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")
