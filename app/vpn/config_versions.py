from pathlib import Path

from app.vpn.amneziawg_v2.config import ClientConfigInput
from app.vpn.config_templates import (
    SUPPORTED_CLIENT_CONFIG_VERSIONS,
    render_client_config_from_template,
)


SUPPORTED_CONFIG_VERSIONS = SUPPORTED_CLIENT_CONFIG_VERSIONS + ("amneziawg_v3",)
NEW_ISSUANCE_CONFIG_VERSIONS = ("amneziawg_v2", "amneziawg_v3")


class ConfigVersionError(ValueError):
    pass


def validate_config_version(version: str) -> str:
    if version not in SUPPORTED_CONFIG_VERSIONS:
        supported = ", ".join(SUPPORTED_CONFIG_VERSIONS)
        raise ConfigVersionError(f"Unsupported config version: {version}. Supported: {supported}")
    return version


def render_client_config_for_version(
    config: ClientConfigInput,
    version: str,
    template_dir: str | Path | None = None,
) -> str:
    validated = validate_config_version(version)
    return render_client_config_from_template(config, validated, template_dir)
