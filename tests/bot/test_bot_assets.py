import hashlib
import struct
import tomllib
from pathlib import Path

from app.bot import assets


def test_language_selection_header_has_approved_identity_and_dimensions():
    assert getattr(assets, "BOT_LANGUAGE_SELECTION_HEADER_IMAGE_NAME", None) == (
        "NEOBYATNAYA-AMNZ-LANGUAGE-HEADER.png"
    )
    image_path = assets.BOT_LANGUAGE_SELECTION_HEADER_IMAGE_PATH
    image_bytes = image_path.read_bytes()
    assert image_bytes[:8] == b"\x89PNG\r\n\x1a\n"
    assert struct.unpack(">II", image_bytes[16:24]) == (1672, 941)
    assert hashlib.sha256(image_bytes).hexdigest() == (
        "bbddfa72d1d1fc37e412d2f4a9b4124001ff91fbd641635e31a47e008fc4611f"
    )


def test_bot_png_assets_are_included_in_setuptools_package_data():
    repository_root = Path(__file__).resolve().parents[2]
    config = tomllib.loads((repository_root / "pyproject.toml").read_text("utf-8"))

    assert "assets/*.png" in config["tool"]["setuptools"]["package-data"][
        "app.bot"
    ]
