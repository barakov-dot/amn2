from app.vpn.client_compatibility import (
    AMN2_DELIVERY_ARTIFACTS,
    CLIENT_COMPATIBILITY_MATRIX,
    CLIENT_ROLE_ANDROID_SUPPORTED,
    CLIENT_ROLE_EXPERIMENTAL_IOS,
    CLIENT_ROLE_INSTALLED_LEGACY,
    SUPPORT_RECOMMENDED,
    SUPPORT_UNRELIABLE,
    clients_for_artifact,
    recommended_delivery_order,
    render_ru_install_guidance,
)


def test_delivery_artifacts_cover_current_bot_outputs():
    assert set(AMN2_DELIVERY_ARTIFACTS) == {
        "conf_file",
        "vpn_import_link",
        "qr_vpn_import_link",
    }


def test_defaultvpn_is_experimental_after_mobile_retest_failure():
    defaultvpn = CLIENT_COMPATIBILITY_MATRIX["defaultvpn_ios_ru"]

    assert defaultvpn.client_role == CLIENT_ROLE_EXPERIMENTAL_IOS
    assert "not accepted as primary path after P7-C010c real-device retest" in (
        defaultvpn.platform_constraints
    )
    assert defaultvpn.artifact_support["conf_file"].level == SUPPORT_UNRELIABLE
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


def test_android_amneziawg_requires_real_device_acceptance_before_phase8():
    android = CLIENT_COMPATIBILITY_MATRIX["amneziawg_android"]

    assert android.acceptance_status == "pending_real_device_acceptance"
    assert android.release_primary_allowed is False
    assert "Android AmneziaWG 2.0.1 real-device acceptance pending" in (
        android.platform_constraints
    )
    assert android.artifact_support["conf_file"].level == SUPPORT_RECOMMENDED
    assert android.artifact_support["vpn_import_link"].level == SUPPORT_UNRELIABLE
    assert android.artifact_support["qr_vpn_import_link"].level == SUPPORT_UNRELIABLE


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
    assert qr_clients["amneziawg_android"].level == SUPPORT_UNRELIABLE
    assert qr_clients["amneziawg_apple"].level == SUPPORT_UNRELIABLE


def test_ru_install_guidance_mentions_constraints_without_secret_material():
    guidance = render_ru_install_guidance()

    assert "Файл .conf" in guidance
    assert "iOS DefaultVPN" in guidance
    assert "экспериментальный путь" in guidance
    assert "не считать основным iOS-клиентом" in guidance
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
