from __future__ import annotations

from dataclasses import dataclass


SUPPORT_RECOMMENDED = "recommended"
SUPPORT_SUPPORTED = "supported"
SUPPORT_UNRELIABLE = "unreliable"
SUPPORT_UNAVAILABLE = "unavailable"
SUPPORT_FUTURE_GATE = "future_gate"

CLIENT_ROLE_PRIMARY_RF_IOS = "primary_rf_ios"
CLIENT_ROLE_EXPERIMENTAL_IOS = "experimental_ios"
CLIENT_ROLE_INSTALLED_LEGACY = "installed_legacy"
CLIENT_ROLE_ANDROID_SUPPORTED = "android_supported"
CLIENT_ROLE_GENERAL = "general"
DISPLAY_NAME_FILENAME_STEM = "filename_stem"
DISPLAY_NAME_MANUAL_PROMPT = "manual_prompt"
DISPLAY_NAME_CLIENT_GENERATED_SERVER_N = "client_generated_server_n"
DISPLAY_NAME_MANUAL_RENAME_FALLBACK = "manual_rename_fallback"
DISPLAY_NAME_UNPROVEN = "unproven"

AMN2_DELIVERY_ARTIFACTS = (
    "conf_file",
    "vpn_import_link",
    "qr_vpn_import_link",
)

CLIENT_COMPATIBILITY_WATCH = {
    "status": "real_device_cross_client_conf_pass",
    "date": "2026-07-11",
    "source_evidence": (
        "research/upstreams/amnezia-vpn-client-defaultvpn-refresh-2026-06-14.md"
    ),
    "config_delivery_allowed": True,
    "live_client_import_verified": True,
    "signals": {
        "amnezia_client_release": "4.8.18.0",
        "defaultvpn_commit": "d139fb5",
        "amneziawg_android_release": "2.0.1",
        "amneziawg_apple_commit": "0c4d98d",
        "android_tv_amneziavpn_conf": "passed",
        "ios_defaultvpn_conf": "passed",
        "windows_11_amneziavpn_conf": "passed",
        "native_vpn_json": "failed_connecting_without_error",
    },
}

_SUPPORT_ORDER = {
    SUPPORT_RECOMMENDED: 0,
    SUPPORT_SUPPORTED: 1,
    SUPPORT_UNRELIABLE: 2,
    SUPPORT_FUTURE_GATE: 3,
    SUPPORT_UNAVAILABLE: 4,
}


@dataclass(frozen=True)
class ArtifactSupport:
    level: str
    note_ru: str


@dataclass(frozen=True)
class ClientCompatibility:
    label: str
    platform: str
    app_url: str
    client_role: str
    platform_constraints: tuple[str, ...]
    artifact_support: dict[str, ArtifactSupport]
    notes_ru: tuple[str, ...] = ()
    display_name_policy: dict[str, str] | None = None
    display_name_notes_ru: tuple[str, ...] = ()


CLIENT_COMPATIBILITY_MATRIX: dict[str, ClientCompatibility] = {
    "amnezia_vpn": ClientCompatibility(
        label="AmneziaVPN",
        platform="Android / iOS / macOS / Windows / Linux",
        app_url="https://github.com/amnezia-vpn/amnezia-client",
        client_role=CLIENT_ROLE_GENERAL,
        platform_constraints=(
            "Android 9+",
            "Android 7/8 temporarily unavailable",
            "macOS 13+",
            "macOS 10.15-12 temporarily unavailable",
            "Linux GUI dependencies required",
            "Linux x64 tar available; distro-specific packages not promised",
        ),
        artifact_support={
            "conf_file": ArtifactSupport(
                SUPPORT_RECOMMENDED,
                "Надежный fallback для ручного импорта.",
            ),
            "vpn_import_link": ArtifactSupport(
                SUPPORT_SUPPORTED,
                "Отдельная import-ссылка удобнее длинного общего сообщения.",
            ),
            "qr_vpn_import_link": ArtifactSupport(
                SUPPORT_UNRELIABLE,
                "QR содержит vpn:// payload; не считать универсальным для всех сборок.",
            ),
            "native_vpn_json": ArtifactSupport(
                SUPPORT_UNRELIABLE,
                "Real-device Android TV import прошел, но подключение зависло без ошибки.",
            ),
        },
        notes_ru=(
            "Не обещать один универсальный путь установки для всех OS/version.",
        ),
        display_name_policy={
            "conf_file": DISPLAY_NAME_FILENAME_STEM,
            "vpn_import_link": DISPLAY_NAME_CLIENT_GENERATED_SERVER_N,
            "qr_vpn_import_link": DISPLAY_NAME_CLIENT_GENERATED_SERVER_N,
        },
        display_name_notes_ru=(
            "Real-device Android TV и Windows 11 AmneziaVPN imports подтвердили, "
            "что обычный .conf использует filename stem как display name.",
            "Native .vpn JSON импортировался, но не подключился; основной путь - "
            "стандартный .conf с каноническим filename.",
        ),
    ),
    "defaultvpn_ios_ru": ClientCompatibility(
        label="DefaultVPN",
        platform="iOS",
        app_url="https://apps.apple.com/app/defaultvpn/id6473452691",
        client_role=CLIENT_ROLE_PRIMARY_RF_IOS,
        platform_constraints=(
            "iOS App Store availability is region-specific",
            "RF-available iOS candidate",
            "2026-07-11 real-device .conf first-connect and traffic passed",
            "reconnect and long-session soak remain separate checks",
        ),
        artifact_support={
            "conf_file": ArtifactSupport(
                SUPPORT_RECOMMENDED,
                "Real-device iOS DefaultVPN import, handshake and traffic passed.",
            ),
            "vpn_import_link": ArtifactSupport(
                SUPPORT_UNRELIABLE,
                "Не считать рабочим путем до отдельной DefaultVPN compatibility диагностики.",
            ),
            "qr_vpn_import_link": ArtifactSupport(
                SUPPORT_UNRELIABLE,
                "P7-C010c: QR не прошел; не обещать QR/import flow для DefaultVPN.",
            ),
            "native_vpn_json": ArtifactSupport(
                SUPPORT_FUTURE_GATE,
                "Изучать только после compatibility matrix и config-delivery design gate.",
            ),
        },
        display_name_policy={
            "conf_file": DISPLAY_NAME_MANUAL_RENAME_FALLBACK,
            "vpn_import_link": DISPLAY_NAME_MANUAL_RENAME_FALLBACK,
            "qr_vpn_import_link": DISPLAY_NAME_UNPROVEN,
        },
        display_name_notes_ru=(
            "DefaultVPN display-name source не доказан в текущем AMN2 evidence. "
            "Не обещать автоматическое имя без отдельного real-device result.",
        ),
    ),
    "amneziawg_android": ClientCompatibility(
        label="AmneziaWG Android",
        platform="Android",
        app_url="https://play.google.com/store/apps/details?id=org.amnezia.awg",
        client_role=CLIENT_ROLE_ANDROID_SUPPORTED,
        platform_constraints=(
            "Standalone AWG client",
            "Android standalone AWG path",
        ),
        artifact_support={
            "conf_file": ArtifactSupport(
                SUPPORT_RECOMMENDED,
                "Надежный import path для WireGuard-style profile.",
            ),
            "vpn_import_link": ArtifactSupport(
                SUPPORT_SUPPORTED,
                "Поддерживать как отдельный convenience channel.",
            ),
            "qr_vpn_import_link": ArtifactSupport(
                SUPPORT_SUPPORTED,
                "Допустимый QR path для AWG importer tests, но не universal promise.",
            ),
        },
        display_name_policy={
            "conf_file": DISPLAY_NAME_FILENAME_STEM,
            "vpn_import_link": DISPLAY_NAME_MANUAL_PROMPT,
            "qr_vpn_import_link": DISPLAY_NAME_MANUAL_PROMPT,
        },
        display_name_notes_ru=(
            "Standalone AmneziaWG Android file import derives tunnel name from "
            "OpenableColumns.DISPLAY_NAME / filename and strips .conf.",
            "QR/text import validates config then opens a naming dialog; there is "
            "no automatic display-name field in AMN2 vpn:// payload.",
        ),
    ),
    "amneziawg_apple": ClientCompatibility(
        label="AmneziaWG Apple",
        platform="iOS / macOS",
        app_url="https://github.com/amnezia-vpn/amneziawg-apple",
        client_role=CLIENT_ROLE_INSTALLED_LEGACY,
        platform_constraints=(
            "Standalone AWG client",
            "not available in RF App Store by default",
            "use only when already installed",
        ),
        artifact_support={
            "conf_file": ArtifactSupport(
                SUPPORT_RECOMMENDED,
                "Надежный import path для WireGuard-style profile.",
            ),
            "vpn_import_link": ArtifactSupport(
                SUPPORT_SUPPORTED,
                "Поддерживать как отдельный convenience channel.",
            ),
            "qr_vpn_import_link": ArtifactSupport(
                SUPPORT_SUPPORTED,
                "Допустимый QR path для AWG importer tests, но не universal promise.",
            ),
        },
        display_name_policy={
            "conf_file": DISPLAY_NAME_FILENAME_STEM,
            "vpn_import_link": DISPLAY_NAME_UNPROVEN,
            "qr_vpn_import_link": DISPLAY_NAME_UNPROVEN,
        },
        display_name_notes_ru=(
            "Standalone AmneziaWG Apple filename/display-name behavior remains "
            "unproven until source or real-device evidence is added.",
        ),
    ),
    "amneziawg_windows": ClientCompatibility(
        label="AmneziaWG Windows",
        platform="Windows",
        app_url="https://github.com/amnezia-vpn/amneziawg-windows-client/releases",
        client_role=CLIENT_ROLE_GENERAL,
        platform_constraints=(
            "Standalone AWG client",
        ),
        artifact_support={
            "conf_file": ArtifactSupport(
                SUPPORT_RECOMMENDED,
                "Надежный import path для desktop client.",
            ),
            "vpn_import_link": ArtifactSupport(
                SUPPORT_SUPPORTED,
                "Оставить как отдельный text artifact, если client/OS его принимает.",
            ),
            "qr_vpn_import_link": ArtifactSupport(
                SUPPORT_UNRELIABLE,
                "Desktop QR flow не считать основным путем установки.",
            ),
        },
        display_name_policy={
            "conf_file": DISPLAY_NAME_FILENAME_STEM,
            "vpn_import_link": DISPLAY_NAME_UNPROVEN,
            "qr_vpn_import_link": DISPLAY_NAME_UNPROVEN,
        },
        display_name_notes_ru=(
            "Standalone AmneziaWG Windows file import derives tunnel name from "
            "the .conf filename stem before creating the tunnel.",
        ),
    ),
}


def clients_for_artifact(artifact: str) -> dict[str, ArtifactSupport]:
    return {
        client_id: client.artifact_support[artifact]
        for client_id, client in CLIENT_COMPATIBILITY_MATRIX.items()
        if artifact in client.artifact_support
    }


def recommended_delivery_order(client_id: str) -> list[str]:
    client = CLIENT_COMPATIBILITY_MATRIX[client_id]
    supported = [
        artifact
        for artifact in AMN2_DELIVERY_ARTIFACTS
        if artifact in client.artifact_support
    ]
    return sorted(
        supported,
        key=lambda artifact: _SUPPORT_ORDER[client.artifact_support[artifact].level],
    )


def display_name_policy_for(client_id: str, artifact: str) -> str:
    client = CLIENT_COMPATIBILITY_MATRIX[client_id]
    policy = client.display_name_policy or {}
    return policy.get(artifact, DISPLAY_NAME_UNPROVEN)


def display_name_guidance_for(client_id: str) -> str:
    client = CLIENT_COMPATIBILITY_MATRIX[client_id]
    notes = "\n".join(client.display_name_notes_ru)
    if not notes:
        notes = "Display-name behavior не доказан для этого клиента."
    return notes


def render_ru_install_guidance() -> str:
    return "\n\n".join(
        [
            "Файл .conf остается основным надежным способом импорта.",
            (
                "iOS DefaultVPN: .conf подтвержден на реальном устройстве: "
                "first-connect и трафик прошли; "
                "reconnect/long-session проверять отдельно."
            ),
            (
                "iOS AmneziaWG: используйте, если приложение уже установлено. "
                ".conf остается первым fallback; QR/vpn link проверять на конкретной версии."
            ),
            (
                "Android AmneziaWG: отдельный поддерживаемый путь. .conf и QR допустимы "
                "для проверки совместимости, но QR не является универсальным обещанием."
            ),
            (
                "AmneziaVPN: перед рекомендацией приложения учитывайте ограничения "
                "Android 9+, macOS 13+, Linux x64 tar с GUI dependencies required "
                "и временно недоступные Android 7/8, macOS 10.15-12; "
                "distro-specific Linux packages не обещать."
            ),
            (
                "Display name: для проверенных AmneziaVPN Android TV/Windows и "
                "standalone AmneziaWG использовать имя .conf файла без расширения."
            ),
        ]
    )
