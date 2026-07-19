from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.bot.delivery import (
    CONFIG_READY_TEMPLATE_KEY,
    DEFAULT_CONFIG_READY_TEMPLATE,
    ConfigDeliveryPackage,
    build_config_delivery,
)
from app.db.repositories import Repository
from app.security.crypto import SecretBox
from app.config_assignment import (
    DEDICATED_DEVICE,
    config_assignment_policy,
)
from app.services.config_material import ConfigMaterialUnavailable
from app.vpn.amneziawg_v2.config import ClientConfigDefaults, ClientConfigInput
from app.vpn.config_versions import render_client_config_for_version


@dataclass(frozen=True)
class DeviceConfigDelivery:
    device_id: int
    user_telegram_id: int | None
    config_text: str
    delivery: ConfigDeliveryPackage
    assignment_mode: str
    physical_device_limit: int | None
    physical_device_count_enforceable: bool


def build_device_config_delivery(
    *,
    repo: Repository,
    secret_box: SecretBox,
    device: Any,
    client_config_template_dir: str | None = None,
    client_dns: str = "8.8.8.8, 8.8.4.4",
    client_allowed_ips: str = "0.0.0.0/0, ::/0",
    client_config_defaults: ClientConfigDefaults | None = None,
) -> DeviceConfigDelivery:
    if str(device["status"]) not in {"pending", "active"}:
        raise ConfigMaterialUnavailable(
            f"Config delivery is unavailable for inactive device #{device['id']}"
        )
    if _config_material_status(device) != "available":
        raise ConfigMaterialUnavailable(
            f"Config material is unavailable for device #{device['id']}"
        )
    user = repo.get_user(int(device["user_id"]))
    server = repo.get_server(int(device["server_id"]))
    private_key = secret_box.decrypt_text(device["peer_private_key_encrypted"])
    preshared_key = secret_box.decrypt_text(device["preshared_key_encrypted"])
    config_version = str(device["config_version"])
    defaults = client_config_defaults or ClientConfigDefaults(
        dns=client_dns,
        allowed_ips=client_allowed_ips,
    )
    config_text = render_client_config_for_version(
        ClientConfigInput(
            private_key=private_key,
            address=f"{device['vpn_ip']}/32",
            dns=defaults.dns,
            server_public_key=str(server["server_public_key"]),
            preshared_key=preshared_key,
            endpoint=f"{server['endpoint_host']}:{server['vpn_port']}",
            allowed_ips=defaults.allowed_ips,
            persistent_keepalive=defaults.persistent_keepalive,
            jc=defaults.jc,
            jmin=defaults.jmin,
            jmax=defaults.jmax,
            s1=defaults.s1,
            s2=defaults.s2,
            s3=defaults.s3,
            s4=defaults.s4,
            h1=defaults.h1,
            h2=defaults.h2,
            h3=defaults.h3,
            h4=defaults.h4,
            i1=defaults.i1,
            i2=defaults.i2,
            i3=defaults.i3,
            i4=defaults.i4,
            i5=defaults.i5,
        ),
        config_version,
        template_dir=client_config_template_dir,
    )
    template_text = repo.get_message_template(
        CONFIG_READY_TEMPLATE_KEY,
        default_text=DEFAULT_CONFIG_READY_TEMPLATE,
    )
    assignment_policy = config_assignment_policy(_assignment_mode(device))
    delivery = build_config_delivery(
        device_id=int(device["id"]),
        device_name=str(device["name"]),
        config_version=config_version,
        config_text=config_text,
        template_text=template_text,
        assignment_mode=assignment_policy.mode,
    )
    return DeviceConfigDelivery(
        device_id=int(device["id"]),
        user_telegram_id=(
            int(user["telegram_id"])
            if user["telegram_id"] is not None
            else None
        ),
        config_text=config_text,
        delivery=delivery,
        assignment_mode=assignment_policy.mode,
        physical_device_limit=assignment_policy.physical_device_limit,
        physical_device_count_enforceable=(
            assignment_policy.physical_device_count_enforceable
        ),
    )


def _config_material_status(device: Any) -> str:
    try:
        return str(device["config_material_status"])
    except (IndexError, KeyError):
        return "available"


def _assignment_mode(device: Any) -> str:
    try:
        return str(device["assignment_mode"])
    except (IndexError, KeyError):
        return DEDICATED_DEVICE
