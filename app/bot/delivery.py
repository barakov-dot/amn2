from __future__ import annotations

import io
from dataclasses import dataclass
from string import Formatter

import qrcode

from app.bot.ux import VERSION_LABELS
from app.vpn.config_templates import build_vpn_import_link


CONFIG_READY_TEMPLATE_KEY = "config_ready"

APP_LINKS = {
    "android_amnezia": "https://play.google.com/store/apps/details?id=org.amnezia.vpn",
    "android_amneziawg": "https://play.google.com/store/apps/details?id=org.amnezia.awg",
    "ios_russia_defaultvpn": "https://apps.apple.com/app/defaultvpn/id6473452691",
    "windows_amneziawg": "https://github.com/amnezia-vpn/amneziawg-windows-client/releases",
    "defaultvpn_github": "https://github.com/amnezia-vpn/DefaultVPN",
}

DEFAULT_CONFIG_READY_TEMPLATE = """Your VPN config is ready.

Device: #{device_id}
Config format: {config_version_label}

Delivery options:
1. Import the attached .conf file.
2. Scan the attached QR code from the VPN app.
3. Open this vpn:// import link from a VPN app:
{vpn_link}

Apps:
Android AmneziaVPN: {android_amnezia}
Android AmneziaWG: {android_amneziawg}
iOS in Russia DefaultVPN: {ios_russia_defaultvpn}
Windows AmneziaWG: {windows_amneziawg}
DefaultVPN GitHub: {defaultvpn_github}
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
    qr_payload_text: str = ""
    config_secret_class: str = "client-config-secret"
    config_content_encoding: str = "utf-8"
    vpn_import_link_encoding: str = "base64-url-no-padding"


def build_config_delivery(
    *,
    device_id: int,
    config_version: str,
    config_text: str,
    template_text: str,
) -> ConfigDeliveryPackage:
    vpn_import_link = build_vpn_import_link(config_text)
    context = {
        "device_id": str(device_id),
        "config_version": config_version,
        "config_version_label": VERSION_LABELS.get(config_version, config_version),
        "vpn_link": vpn_import_link,
        **APP_LINKS,
    }
    return ConfigDeliveryPackage(
        template_key=CONFIG_READY_TEMPLATE_KEY,
        message_text=render_template(template_text, context),
        config_filename=f"amneziya-device-{device_id}.conf",
        config_bytes=config_text.encode("utf-8"),
        qr_filename=f"amneziya-device-{device_id}.qr.png",
        qr_png_bytes=_build_qr_png(config_text),
        vpn_import_link=vpn_import_link,
        qr_payload_text=config_text,
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
