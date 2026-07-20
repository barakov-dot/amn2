from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass


BRAND = "NEOBYATNAYA.NET"
MAX_FILENAME_LENGTH = 96

_CYRILLIC_TRANSLITERATION = str.maketrans(
    {
        "А": "A",
        "Б": "B",
        "В": "V",
        "Г": "G",
        "Д": "D",
        "Е": "E",
        "Ё": "Yo",
        "Ж": "Zh",
        "З": "Z",
        "И": "I",
        "Й": "Y",
        "К": "K",
        "Л": "L",
        "М": "M",
        "Н": "N",
        "О": "O",
        "П": "P",
        "Р": "R",
        "С": "S",
        "Т": "T",
        "У": "U",
        "Ф": "F",
        "Х": "Kh",
        "Ц": "Ts",
        "Ч": "Ch",
        "Ш": "Sh",
        "Щ": "Shch",
        "Ъ": "",
        "Ы": "Y",
        "Ь": "",
        "Э": "E",
        "Ю": "Yu",
        "Я": "Ya",
        "а": "a",
        "б": "b",
        "в": "v",
        "г": "g",
        "д": "d",
        "е": "e",
        "ё": "yo",
        "ж": "zh",
        "з": "z",
        "и": "i",
        "й": "y",
        "к": "k",
        "л": "l",
        "м": "m",
        "н": "n",
        "о": "o",
        "п": "p",
        "р": "r",
        "с": "s",
        "т": "t",
        "у": "u",
        "ф": "f",
        "х": "kh",
        "ц": "ts",
        "ч": "ch",
        "ш": "sh",
        "щ": "shch",
        "ъ": "",
        "ы": "y",
        "ь": "",
        "э": "e",
        "ю": "yu",
        "я": "ya",
    }
)
_WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}


@dataclass(frozen=True)
class ConfigIdentity:
    display_name: str
    filename: str


def build_config_identity(
    user_label: str,
    device_label: str,
    *,
    collision_device_id: int | None = None,
) -> ConfigIdentity:
    normalized_user_label = _display_label(user_label, name="user_label")
    normalized_device_label = _display_label(device_label, name="device_label")
    if collision_device_id is not None:
        if (
            isinstance(collision_device_id, bool)
            or not isinstance(collision_device_id, int)
            or collision_device_id <= 0
        ):
            raise ValueError("collision_device_id must be positive")

    user_component = _filename_component(normalized_user_label, fallback="user")
    device_component = _filename_component(
        normalized_device_label,
        fallback="device",
    )
    collision_suffix = (
        f"-d{collision_device_id}" if collision_device_id is not None else ""
    )
    extension = ".conf"
    minimum_stem = f"{BRAND}-u-d"
    if len(minimum_stem) + len(collision_suffix) + len(extension) > MAX_FILENAME_LENGTH:
        raise ValueError("collision_device_id is too large for canonical filename")
    filename_stem = f"{BRAND}-{user_component}-{device_component}"
    maximum_stem_length = (
        MAX_FILENAME_LENGTH - len(collision_suffix) - len(extension)
    )
    filename_stem = filename_stem[:maximum_stem_length].rstrip("-._")

    return ConfigIdentity(
        display_name=(
            f"{BRAND} — {normalized_user_label} — {normalized_device_label}"
        ),
        filename=f"{filename_stem}{collision_suffix}{extension}",
    )


def build_unassigned_slot_identity(
    recipient_label: str,
    slot_sequence: int,
) -> ConfigIdentity:
    if (
        isinstance(slot_sequence, bool)
        or not isinstance(slot_sequence, int)
        or not 1 <= slot_sequence <= 100
    ):
        raise ValueError("slot_sequence must be between 1 and 100")
    return build_config_identity(recipient_label, f"{slot_sequence:02d}")


def _display_label(value: str, *, name: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{name} must not be blank")
    return normalized


def _filename_component(value: str, *, fallback: str) -> str:
    transliterated = value.translate(_CYRILLIC_TRANSLITERATION)
    decomposed = unicodedata.normalize("NFKD", transliterated)
    ascii_value = decomposed.encode("ascii", errors="ignore").decode("ascii")
    component = re.sub(r"[^A-Za-z0-9]+", "-", ascii_value).strip("-")
    if not component:
        component = fallback
    if component.upper() in _WINDOWS_RESERVED_NAMES:
        component = f"_{component}"
    return component
