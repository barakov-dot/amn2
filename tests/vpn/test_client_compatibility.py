from app.vpn.client_compatibility import (
    AMN2_DELIVERY_ARTIFACTS,
    CLIENT_COMPATIBILITY_MATRIX,
    CLIENT_COMPATIBILITY_WATCH,
    CLIENT_ROLE_ANDROID_SUPPORTED,
    CLIENT_ROLE_INSTALLED_LEGACY,
    CLIENT_ROLE_PRIMARY_RF_IOS,
    DISPLAY_NAME_CLIENT_GENERATED_SERVER_N,
    DISPLAY_NAME_FILENAME_STEM,
    DISPLAY_NAME_MANUAL_PROMPT,
    DISPLAY_NAME_MANUAL_RENAME_FALLBACK,
    DISPLAY_NAME_UNPROVEN,
    SUPPORT_RECOMMENDED,
    SUPPORT_SUPPORTED,
    SUPPORT_UNRELIABLE,
    clients_for_artifact,
    display_name_guidance_for,
    display_name_policy_for,
    recommended_delivery_order,
    render_ru_install_guidance,
)


def test_delivery_artifacts_cover_current_bot_outputs():
    assert set(AMN2_DELIVERY_ARTIFACTS) == {
        "conf_file",
        "vpn_import_link",
        "qr_vpn_import_link",
    }


def test_defaultvpn_is_primary_rf_ios_after_real_device_conf_pass():
    defaultvpn = CLIENT_COMPATIBILITY_MATRIX["defaultvpn_ios_ru"]

    assert defaultvpn.client_role == CLIENT_ROLE_PRIMARY_RF_IOS
    assert "2026-07-11 real-device .conf first-connect and traffic passed" in (
        defaultvpn.platform_constraints
    )
    assert defaultvpn.artifact_support["conf_file"].level == SUPPORT_RECOMMENDED
    assert defaultvpn.artifact_support["vpn_import_link"].level == SUPPORT_UNRELIABLE
    assert defaultvpn.artifact_support["qr_vpn_import_link"].level == SUPPORT_UNRELIABLE
    assert recommended_delivery_order("defaultvpn_ios_ru") == [
        "conf_file",
        "vpn_import_link",
        "qr_vpn_import_link",
    ]


def test_amneziawg_ios_is_installed_legacy_not_primary_rf_path():
    apple = CLIENT_COMPATIBILITY_MATRIX["amneziawg_apple"]

    assert apple.client_role == CLIENT_ROLE_INSTALLED_LEGACY
    assert "not available in RF App Store by default" in apple.platform_constraints
    assert "use only when already installed" in apple.platform_constraints
    assert recommended_delivery_order("amneziawg_apple") == [
        "conf_file",
        "vpn_import_link",
        "qr_vpn_import_link",
    ]


def test_amneziawg_android_is_separate_supported_path():
    android = CLIENT_COMPATIBILITY_MATRIX["amneziawg_android"]

    assert android.client_role == CLIENT_ROLE_ANDROID_SUPPORTED
    assert "Android standalone AWG path" in android.platform_constraints


def test_phase_10_watch_records_real_device_cross_client_conf_pass():
    assert CLIENT_COMPATIBILITY_WATCH["status"] == "real_device_cross_client_conf_pass"
    assert CLIENT_COMPATIBILITY_WATCH["date"] == "2026-07-11"
    assert CLIENT_COMPATIBILITY_WATCH["config_delivery_allowed"] is True
    assert CLIENT_COMPATIBILITY_WATCH["live_client_import_verified"] is True
    assert CLIENT_COMPATIBILITY_WATCH["source_evidence"] == (
        "research/upstreams/amnezia-vpn-client-defaultvpn-refresh-2026-06-14.md"
    )
    assert CLIENT_COMPATIBILITY_WATCH["signals"] == {
        "amnezia_client_release": "4.8.18.0",
        "defaultvpn_commit": "d139fb5",
        "amneziawg_android_release": "2.0.1",
        "amneziawg_apple_commit": "0c4d98d",
        "android_tv_amneziavpn_conf": "passed",
        "ios_defaultvpn_conf": "passed",
        "windows_11_amneziavpn_conf": "passed",
        "native_vpn_json": "failed_connecting_without_error",
    }


def test_release_platform_constraints_are_machine_checkable():
    amnezia = CLIENT_COMPATIBILITY_MATRIX["amnezia_vpn"]

    assert "Android 9+" in amnezia.platform_constraints
    assert "Android 7/8 temporarily unavailable" in amnezia.platform_constraints
    assert "macOS 13+" in amnezia.platform_constraints
    assert "macOS 10.15-12 temporarily unavailable" in amnezia.platform_constraints
    assert "Linux GUI dependencies required" in amnezia.platform_constraints
    assert "Linux x64 tar available; distro-specific packages not promised" in (
        amnezia.platform_constraints
    )


def test_no_qr_claim_is_universal_across_clients():
    qr_clients = clients_for_artifact("qr_vpn_import_link")

    assert qr_clients["defaultvpn_ios_ru"].level == SUPPORT_UNRELIABLE
    assert qr_clients["amneziawg_android"].level == SUPPORT_SUPPORTED
    assert qr_clients["amneziawg_apple"].level == SUPPORT_SUPPORTED


def test_ru_install_guidance_mentions_constraints_without_secret_material():
    guidance = render_ru_install_guidance()

    assert "Файл .conf" in guidance
    assert "iOS DefaultVPN" in guidance
    assert "подтвержден на реальном устройстве" in guidance
    assert "first-connect и трафик прошли" in guidance
    assert "iOS AmneziaWG" in guidance
    assert "если приложение уже установлено" in guidance
    assert "Android AmneziaWG" in guidance
    assert "отдельный поддерживаемый путь" in guidance
    assert "QR не является универсальным" in guidance
    assert "Android 9+" in guidance
    assert "macOS 13+" in guidance
    assert "Linux x64 tar" in guidance
    assert "Debian 12 / Ubuntu 22.04.x builds temporarily unavailable" not in guidance
    assert "PrivateKey" not in guidance
    assert "vpn://" not in guidance


def test_display_name_policy_records_amnezia_vpn_filename_stem_real_device_pass():
    assert display_name_policy_for(
        "amnezia_vpn",
        "conf_file",
    ) == DISPLAY_NAME_FILENAME_STEM
    assert display_name_policy_for(
        "amnezia_vpn",
        "vpn_import_link",
    ) == DISPLAY_NAME_CLIENT_GENERATED_SERVER_N

    guidance = display_name_guidance_for("amnezia_vpn")

    assert "Android TV" in guidance
    assert "Windows 11" in guidance
    assert "filename stem" in guidance
    assert "Native .vpn JSON" in guidance


def test_display_name_policy_records_standalone_awg_filename_import_paths():
    assert display_name_policy_for(
        "amneziawg_android",
        "conf_file",
    ) == DISPLAY_NAME_FILENAME_STEM
    assert display_name_policy_for(
        "amneziawg_windows",
        "conf_file",
    ) == DISPLAY_NAME_FILENAME_STEM
    assert display_name_policy_for(
        "amneziawg_android",
        "qr_vpn_import_link",
    ) == DISPLAY_NAME_MANUAL_PROMPT


def test_display_name_policy_keeps_unproven_clients_on_fallbacks():
    assert display_name_policy_for(
        "defaultvpn_ios_ru",
        "conf_file",
    ) == DISPLAY_NAME_MANUAL_RENAME_FALLBACK
    assert display_name_policy_for(
        "defaultvpn_ios_ru",
        "qr_vpn_import_link",
    ) == DISPLAY_NAME_UNPROVEN
    assert display_name_policy_for(
        "amneziawg_apple",
        "vpn_import_link",
    ) == DISPLAY_NAME_UNPROVEN
