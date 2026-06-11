from __future__ import annotations

import io
import re
from dataclasses import dataclass
from string import Formatter

import qrcode

from app.bot.ux import VERSION_LABELS
from app.vpn.client_compatibility import render_ru_install_guidance
from app.vpn.config_templates import build_vpn_import_link


CONFIG_READY_TEMPLATE_KEY = "config_ready"

APP_LINKS = {
    "android_amnezia": "https://play.google.com/store/apps/details?id=org.amnezia.vpn",
    "android_amneziawg": "https://play.google.com/store/apps/details?id=org.amnezia.awg",
    "ios_russia_defaultvpn": "https://apps.apple.com/app/defaultvpn/id6473452691",
    "windows_amneziawg": "https://github.com/amnezia-vpn/amneziawg-windows-client/releases",
    "defaultvpn_github": "https://github.com/amnezia-vpn/DefaultVPN",
}

CONFIG_FILE_CAPTION = "Файл VPN-конфига (.conf)"
QR_CODE_CAPTION = "QR-код ссылки vpn:// для импорта"
IMPORT_LINK_COPY_BUTTON_TEXT = "Скопировать ссылку"
TELEGRAM_COPY_TEXT_MAX_LENGTH = 256

DEFAULT_CONFIG_READY_TEMPLATE = """Ваш VPN-конфиг готов.

Устройство: {device_name}
Формат конфига: {config_version_label}

Варианты установки:
1. Для DefaultVPN импортируйте прикрепленный .conf файл.
2. Откройте отдельную ссылку vpn://, которую бот пришлет следующим сообщением.
3. QR-код тоже содержит ссылку vpn://. Если встроенный QR-сканер приложения ее не принимает, используйте файл или отдельную ссылку.

Ссылки на приложения бот пришлет отдельным сообщением.
"""


@dataclass(frozen=True)
class ConfigDeliveryPackage:
    template_key: str
    message_text: str
    config_filename: str
    config_bytes: bytes
    qr_filename: str
    qr_png_bytes: bytes
    vpn_import_link: str
    vpn_import_link_text: str = ""
    vpn_import_link_copy_button_text: str = ""
    vpn_import_link_copy_text: str | None = None
    app_links_text: str = ""
    config_caption: str = CONFIG_FILE_CAPTION
    qr_caption: str = QR_CODE_CAPTION
    qr_payload_text: str = ""
    config_secret_class: str = "client-config-secret"
    config_content_encoding: str = "utf-8"
    vpn_import_link_encoding: str = "base64-url-no-padding"


def build_config_delivery(
    *,
    device_id: int,
    device_name: str | None = None,
    config_version: str,
    config_text: str,
    template_text: str,
) -> ConfigDeliveryPackage:
    vpn_import_link = build_vpn_import_link(config_text)
    vpn_import_link_copy_text = _copyable_vpn_import_link(vpn_import_link)
    basename = _artifact_basename(device_name=device_name, device_id=device_id)
    context = {
        "device_id": str(device_id),
        "device_name": device_name or f"device-{device_id}",
        "config_version": config_version,
        "config_version_label": VERSION_LABELS.get(config_version, config_version),
        "vpn_link": vpn_import_link,
        **APP_LINKS,
    }
    return ConfigDeliveryPackage(
        template_key=CONFIG_READY_TEMPLATE_KEY,
        message_text=render_template(template_text, context),
        config_filename=f"{basename}.conf",
        config_bytes=config_text.encode("utf-8"),
        qr_filename=f"{basename}.qr.png",
        qr_png_bytes=_build_qr_png(vpn_import_link),
        vpn_import_link=vpn_import_link,
        vpn_import_link_text=f"Ссылка vpn:// для импорта:\n{vpn_import_link}",
        vpn_import_link_copy_button_text=(
            IMPORT_LINK_COPY_BUTTON_TEXT if vpn_import_link_copy_text else ""
        ),
        vpn_import_link_copy_text=vpn_import_link_copy_text,
        app_links_text=_render_app_links(),
        qr_payload_text=vpn_import_link,
    )


def render_template(template_text: str, values: dict[str, str]) -> str:
    formatter = Formatter()
    chunks: list[str] = []
    for literal_text, field_name, format_spec, conversion in formatter.parse(template_text):
        chunks.append(literal_text)
        if field_name is None:
            continue
        if field_name not in values:
            chunks.append("{" + field_name + "}")
            continue
        value = values[field_name]
        if conversion:
            value = formatter.convert_field(value, conversion)
        chunks.append(formatter.format_field(value, format_spec))
    return "".join(chunks)


def _build_qr_png(config_text: str) -> bytes:
    image = qrcode.make(config_text)
    output = io.BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def _copyable_vpn_import_link(vpn_import_link: str) -> str | None:
    if 0 < len(vpn_import_link) <= TELEGRAM_COPY_TEXT_MAX_LENGTH:
        return vpn_import_link
    return None


def _artifact_basename(*, device_name: str | None, device_id: int) -> str:
    source = (device_name or "").strip() or f"device-{device_id}"
    basename = re.sub(r"[^A-Za-z0-9._-]+", "-", source).strip(".-_")
    return basename or f"device-{device_id}"


def _render_app_links() -> str:
    return "\n\n".join(
        [
            f"Android AmneziaVPN:\n{APP_LINKS['android_amnezia']}",
            f"Android AmneziaWG:\n{APP_LINKS['android_amneziawg']}",
            f"iOS DefaultVPN:\n{APP_LINKS['ios_russia_defaultvpn']}",
            f"Windows AmneziaWG:\n{APP_LINKS['windows_amneziawg']}",
            f"DefaultVPN GitHub:\n{APP_LINKS['defaultvpn_github']}",
            render_ru_install_guidance(),
        ]
    )
