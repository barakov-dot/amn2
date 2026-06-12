from app.vpn.client_compatibility import (
    AMN2_DELIVERY_ARTIFACTS,
    CLIENT_COMPATIBILITY_MATRIX,
    SUPPORT_RECOMMENDED,
    SUPPORT_SUPPORTED,
    SUPPORT_UNRELIABLE,
    SUPPORT_UNAVAILABLE,
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


def test_defaultvpn_keeps_conf_ahead_of_qr_import():
    defaultvpn = CLIENT_COMPATIBILITY_MATRIX["defaultvpn_ios_ru"]

    assert defaultvpn.artifact_support["conf_file"].level == SUPPORT_RECOMMENDED
    assert defaultvpn.artifact_support["vpn_import_link"].level == SUPPORT_SUPPORTED
    assert defaultvpn.artifact_support["qr_vpn_import_link"].level == SUPPORT_UNRELIABLE
    assert recommended_delivery_order("defaultvpn_ios_ru") == [
        "conf_file",
        "vpn_import_link",
        "qr_vpn_import_link",
    ]


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
    assert "DefaultVPN" in guidance
    assert "QR" in guidance
    assert "Android 9+" in guidance
    assert "macOS 13+" in guidance
    assert "Linux x64 tar" in guidance
    assert "Debian 12 / Ubuntu 22.04.x builds temporarily unavailable" not in guidance
    assert "PrivateKey" not in guidance
    assert "vpn://" not in guidance
