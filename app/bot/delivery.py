from __future__ import annotations

import io
import re
from dataclasses import dataclass
from string import Formatter

import qrcode
from qrcode.constants import ERROR_CORRECT_M

from app.bot.ux import VERSION_LABELS
from app.config_assignment import (
    DEDICATED_DEVICE,
    OWNER_SHARED,
    config_assignment_policy,
)
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

CONFIG_FILE_CAPTION = "Файл VPN-конфига (.conf) - основной способ установки"
QR_CODE_CAPTION = (
    "QR-код для сканера внутри VPN-клиента. Камера телефона может не открыть "
    "приложение; если QR не сработал, используйте .conf файл."
)
IMPORT_LINK_COPY_BUTTON_TEXT = "Скопировать ссылку"
TELEGRAM_COPY_TEXT_MAX_LENGTH = 256
CANONICAL_STANDALONE_AWG_IMPORT_BASENAME = "Neobyatnaya.NET"
_WINDOWS_RESERVED_FILENAME_STEMS = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}

DEFAULT_CONFIG_READY_TEMPLATE = """Ваш VPN-конфиг готов.

Устройство: {device_name}
Формат: {config_version_label}

Как установить:
1. Самый надежный способ: скачайте прикрепленный .conf файл и импортируйте его в VPN-клиент.
2. iPhone в РФ: начните с DefaultVPN и выберите импорт .conf файла.
3. Android: начните с AmneziaWG и выберите импорт .conf файла.
4. QR-код - дополнительный способ для сканера внутри VPN-клиента. Обычная камера телефона может не открыть приложение.
5. Ссылка vpn:// отправляется отдельно как запасной вариант; для длинных конфигов Telegram не всегда дает кнопку копирования.

Ниже бот отправит ссылку vpn://, приложения, .conf файл и QR-код.
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
    assignment_mode: str = DEDICATED_DEVICE
    physical_device_limit: int | None = 1
    physical_device_count_enforceable: bool = True


def build_config_delivery(
    *,
    device_id: int,
    device_name: str | None = None,
    config_version: str,
    config_text: str,
    template_text: str,
    assignment_mode: str = DEDICATED_DEVICE,
    attachment_filename: str | None = None,
) -> ConfigDeliveryPackage:
    assignment_policy = config_assignment_policy(assignment_mode)
    vpn_import_link = build_vpn_import_link(config_text)
    vpn_import_link_copy_text = _copyable_vpn_import_link(vpn_import_link)
    basename = _config_basename(
        device_id=device_id,
        assignment_mode=assignment_policy.mode,
    )
    config_filename = (
        _validate_attachment_filename(attachment_filename)
        if attachment_filename is not None
        else f"{basename}.conf"
    )
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
        config_filename=config_filename,
        config_bytes=config_text.encode("utf-8"),
        qr_filename=f"{basename}.qr.png",
        qr_png_bytes=_build_qr_png(config_text),
        vpn_import_link=vpn_import_link,
        vpn_import_link_text=_render_vpn_import_link_text(
            vpn_import_link=vpn_import_link,
            is_copyable=vpn_import_link_copy_text is not None,
        ),
        vpn_import_link_copy_button_text=(
            IMPORT_LINK_COPY_BUTTON_TEXT if vpn_import_link_copy_text else ""
        ),
        vpn_import_link_copy_text=vpn_import_link_copy_text,
        app_links_text=_render_app_links(),
        qr_payload_text=config_text,
        assignment_mode=assignment_policy.mode,
        physical_device_limit=assignment_policy.physical_device_limit,
        physical_device_count_enforceable=(
            assignment_policy.physical_device_count_enforceable
        ),
    )


def _config_basename(*, device_id: int, assignment_mode: str) -> str:
    if assignment_mode == OWNER_SHARED:
        return CANONICAL_STANDALONE_AWG_IMPORT_BASENAME
    return f"{CANONICAL_STANDALONE_AWG_IMPORT_BASENAME}-{device_id}"


def _validate_attachment_filename(filename: str) -> str:
    filename_stem = filename.removesuffix(".conf")
    windows_device_stem = filename_stem.split(".", maxsplit=1)[0]
    if (
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,90}\.conf", filename) is None
        or windows_device_stem.upper() in _WINDOWS_RESERVED_FILENAME_STEMS
    ):
        raise ValueError("attachment_filename must be a safe .conf basename")
    return filename


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
    qr = qrcode.QRCode(
        error_correction=ERROR_CORRECT_M,
        box_size=12,
        border=6,
    )
    qr.add_data(config_text)
    qr.make(fit=True)
    image = qr.make_image(fill_color="black", back_color="white")
    output = io.BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def _copyable_vpn_import_link(vpn_import_link: str) -> str | None:
    if 0 < len(vpn_import_link) <= TELEGRAM_COPY_TEXT_MAX_LENGTH:
        return vpn_import_link
    return None


def _render_vpn_import_link_text(*, vpn_import_link: str, is_copyable: bool) -> str:
    if is_copyable:
        return (
            "Ссылка vpn:// для импорта.\n"
            "Если ваш Telegram показывает кнопку ниже, нажмите ее, чтобы скопировать ссылку:\n"
            f"{vpn_import_link}"
        )
    return (
        "Ссылка vpn:// для импорта слишком длинная для кнопки копирования Telegram.\n"
        "Основной способ установки - прикрепленный .conf файл. QR-код ниже "
        "предназначен для сканера внутри VPN-клиента, а не для обычной камеры телефона.\n\n"
        f"{vpn_import_link}"
    )


def _render_app_links() -> str:
    return "\n\n".join(
        [
            "Приложения для импорта VPN-профиля",
            f"iPhone / iPad: DefaultVPN\n{APP_LINKS['ios_russia_defaultvpn']}",
            f"Android: AmneziaWG\n{APP_LINKS['android_amneziawg']}",
            f"Android / Desktop: AmneziaVPN\n{APP_LINKS['android_amnezia']}",
            f"Windows: AmneziaWG\n{APP_LINKS['windows_amneziawg']}",
            f"DefaultVPN GitHub\n{APP_LINKS['defaultvpn_github']}",
            render_ru_install_guidance(),
        ]
    )
