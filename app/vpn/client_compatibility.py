from __future__ import annotations

from dataclasses import dataclass


SUPPORT_RECOMMENDED = "recommended"
SUPPORT_SUPPORTED = "supported"
SUPPORT_UNRELIABLE = "unreliable"
SUPPORT_UNAVAILABLE = "unavailable"
SUPPORT_FUTURE_GATE = "future_gate"

AMN2_DELIVERY_ARTIFACTS = (
    "conf_file",
    "vpn_import_link",
    "qr_vpn_import_link",
)

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
    platform_constraints: tuple[str, ...]
    artifact_support: dict[str, ArtifactSupport]
    notes_ru: tuple[str, ...] = ()


CLIENT_COMPATIBILITY_MATRIX: dict[str, ClientCompatibility] = {
    "amnezia_vpn": ClientCompatibility(
        label="AmneziaVPN",
        platform="Android / iOS / macOS / Windows / Linux",
        app_url="https://github.com/amnezia-vpn/amnezia-client",
        platform_constraints=(
            "Android 9+",
            "Android 7/8 temporarily unavailable",
            "macOS 13+",
            "macOS 10.15-12 temporarily unavailable",
            "Linux GUI dependencies required",
            "Debian 12 / Ubuntu 22.04.x builds temporarily unavailable",
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
                SUPPORT_FUTURE_GATE,
                "Требует отдельного design gate перед генерацией secret-bearing artifacts.",
            ),
        },
        notes_ru=(
            "Не обещать один универсальный путь установки для всех OS/version.",
        ),
    ),
    "defaultvpn_ios_ru": ClientCompatibility(
        label="DefaultVPN",
        platform="iOS",
        app_url="https://apps.apple.com/app/defaultvpn/id6473452691",
        platform_constraints=(
            "iOS App Store availability is region-specific",
        ),
        artifact_support={
            "conf_file": ArtifactSupport(
                SUPPORT_RECOMMENDED,
                "Основной безопасный путь, если встроенный QR/import flow не принимает профиль.",
            ),
            "vpn_import_link": ArtifactSupport(
                SUPPORT_SUPPORTED,
                "Отправлять отдельным сообщением, чтобы пользователь мог открыть или скопировать.",
            ),
            "qr_vpn_import_link": ArtifactSupport(
                SUPPORT_UNRELIABLE,
                "Не обещать, что встроенный QR-сканер DefaultVPN примет AMN2 vpn:// QR.",
            ),
            "native_vpn_json": ArtifactSupport(
                SUPPORT_FUTURE_GATE,
                "Изучать только после compatibility matrix и config-delivery design gate.",
            ),
        },
    ),
    "amneziawg_android": ClientCompatibility(
        label="AmneziaWG Android",
        platform="Android",
        app_url="https://play.google.com/store/apps/details?id=org.amnezia.awg",
        platform_constraints=(
            "Standalone AWG client",
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
    ),
    "amneziawg_apple": ClientCompatibility(
        label="AmneziaWG Apple",
        platform="iOS / macOS",
        app_url="https://github.com/amnezia-vpn/amneziawg-apple",
        platform_constraints=(
            "Standalone AWG client",
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
    ),
    "amneziawg_windows": ClientCompatibility(
        label="AmneziaWG Windows",
        platform="Windows",
        app_url="https://github.com/amnezia-vpn/amneziawg-windows-client/releases",
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


def render_ru_install_guidance() -> str:
    return "\n\n".join(
        [
            "Файл .conf остается основным надежным способом импорта.",
            (
                "DefaultVPN: сначала используйте .conf файл или отдельную ссылку импорта. "
                "QR содержит import-ссылку и может не приниматься встроенным сканером."
            ),
            (
                "AmneziaWG Android/Apple: .conf и QR допустимы для проверки совместимости, "
                "но QR не считается универсальным обещанием для всех клиентов."
            ),
            (
                "AmneziaVPN: перед рекомендацией приложения учитывайте ограничения "
                "Android 9+, macOS 13+, Linux GUI dependencies required и временно "
                "недоступные Android 7/8, macOS 10.15-12, Debian 12 / Ubuntu 22.04.x builds."
            ),
        ]
    )
