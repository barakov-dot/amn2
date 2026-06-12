import json
from pathlib import Path

from app.cli import build_parser
from app.cli import run_bot_media_manifest
from app.cli import run_bot_media_select
from app.cli import run_bot_media_stage
from app.cli import run_bot_media_validate


def test_cli_accepts_bot_media_commands():
    parser = build_parser()

    args = parser.parse_args(
        [
            "bot-media",
            "stage",
            "--bot-kind",
            "news",
            "--surface",
            "start_header",
            "--path",
            "news.png",
            "--registry",
            "data/bot-media-registry.json",
            "--media-root",
            "data/bot-media",
            "--pretty",
        ]
    )

    assert args.command == "bot-media"
    assert args.bot_media_command == "stage"
    assert args.bot_kind == "news"
    assert args.surface == "start_header"
    assert args.path == "news.png"
    assert args.pretty is True


def test_run_bot_media_cli_flow_is_local_only(tmp_path: Path):
    image_path = tmp_path / "news.png"
    image_path.write_bytes(_png_bytes(width=640, height=360))
    registry_path = tmp_path / "registry.json"
    media_root = tmp_path / "media"

    validated = json.loads(
        run_bot_media_validate(
            bot_kind="news",
            surface="start_header",
            path=image_path,
            registry_path=registry_path,
            media_root=media_root,
            pretty=True,
        )
    )
    staged = json.loads(
        run_bot_media_stage(
            bot_kind="news",
            surface="start_header",
            path=image_path,
            registry_path=registry_path,
            media_root=media_root,
            pretty=True,
        )
    )
    selected = json.loads(
        run_bot_media_select(
            bot_kind="news",
            surface="start_header",
            asset_id=staged["asset_id"],
            registry_path=registry_path,
            media_root=media_root,
            pretty=True,
        )
    )
    manifest = json.loads(
        run_bot_media_manifest(
            registry_path=registry_path,
            media_root=media_root,
            pretty=True,
        )
    )

    assert validated["validation_status"] == "valid"
    assert staged["asset_id"] == selected["asset_id"]
    assert manifest["selections"]["news:start_header"] == staged["asset_id"]
    assert manifest["safety"]["local_only"] is True
    assert manifest["safety"]["telegram_api_called"] is False
    assert "token" not in json.dumps(manifest, ensure_ascii=False).lower()


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
