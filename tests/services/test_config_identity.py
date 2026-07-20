import re

import pytest

from app.services.config_identity import build_config_identity, build_unassigned_slot_identity


def test_build_config_identity_uses_exact_display_and_transliterated_filename():
    identity = build_config_identity(user_label="Иван", device_label="Pixel 8")

    assert identity.display_name == "NEOBYATNAYA.NET — Иван — Pixel 8"
    assert identity.filename == "NEOBYATNAYA.NET-Ivan-Pixel-8.conf"


def test_build_config_identity_strips_outer_display_label_whitespace():
    identity = build_config_identity(
        user_label="  Иван  ",
        device_label="  Pixel 8  ",
    )

    assert identity.display_name == "NEOBYATNAYA.NET — Иван — Pixel 8"


@pytest.mark.parametrize(
    ("user_label", "device_label", "expected_filename"),
    [
        ("Ёж", "Телефон", "NEOBYATNAYA.NET-Yozh-Telefon.conf"),
        ("用户", "📱", "NEOBYATNAYA.NET-user-device.conf"),
        ("Alice/..\\Bob", "Pixel\x00\n8", "NEOBYATNAYA.NET-Alice-Bob-Pixel-8.conf"),
        ("  Alice   Smith  ", " Pixel\t\t8 ", "NEOBYATNAYA.NET-Alice-Smith-Pixel-8.conf"),
    ],
)
def test_build_config_identity_sanitizes_filename_components(
    user_label, device_label, expected_filename
):
    identity = build_config_identity(
        user_label=user_label,
        device_label=device_label,
    )

    assert identity.filename == expected_filename


def test_build_config_identity_escapes_reserved_windows_components():
    identity = build_config_identity(user_label="CON", device_label="LPT1")

    assert identity.filename == "NEOBYATNAYA.NET-_CON-_LPT1.conf"


def test_build_config_identity_bounds_filename_and_keeps_extension_and_suffix():
    identity = build_config_identity(
        user_label="A" * 100,
        device_label="B" * 100,
        collision_device_id=4821,
    )

    assert len(identity.filename) == 96
    assert identity.filename.endswith("-d4821.conf")
    assert re.fullmatch(r"[A-Za-z0-9._-]+", identity.filename)


def test_collision_suffix_uses_only_immutable_local_device_id():
    first = build_config_identity(
        user_label="Alice",
        device_label="Phone",
        collision_device_id=41,
    )
    second = build_config_identity(
        user_label="Alice",
        device_label="Phone",
        collision_device_id=42,
    )

    assert first.filename == "NEOBYATNAYA.NET-Alice-Phone-d41.conf"
    assert second.filename == "NEOBYATNAYA.NET-Alice-Phone-d42.conf"
    assert "secret" not in first.filename.lower()
    assert "key" not in first.filename.lower()


@pytest.mark.parametrize("collision_device_id", [0, -1, True])
def test_collision_device_id_must_be_a_positive_integer(collision_device_id):
    with pytest.raises(ValueError, match="collision_device_id must be positive"):
        build_config_identity(
            user_label="Alice",
            device_label="Phone",
            collision_device_id=collision_device_id,
        )


def test_collision_device_id_rejects_suffix_that_cannot_fit_canonical_filename():
    with pytest.raises(ValueError, match="collision_device_id is too large"):
        build_config_identity(
            user_label="Alice",
            device_label="Phone",
            collision_device_id=10**80,
        )


def test_unassigned_slot_identity_uses_stable_two_digit_sequence():
    identity = build_unassigned_slot_identity("Иван", 4)

    assert identity.display_name == "NEOBYATNAYA.NET — Иван — 04"
    assert identity.filename == "NEOBYATNAYA.NET-Ivan-04.conf"
