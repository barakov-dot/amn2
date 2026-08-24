from pathlib import Path

from app.vpn.amneziawg_v2.config import ClientConfigInput
from app.vpn.amneziawg_v3.config import (
    Awg3ClientConfigInput,
    SecretResolver,
    render_awg3_client_config,
)
from app.vpn.config_templates import (
    SUPPORTED_CLIENT_CONFIG_VERSIONS,
    render_client_config_from_template,
)


SUPPORTED_CONFIG_VERSIONS = SUPPORTED_CLIENT_CONFIG_VERSIONS + (
    "amneziawg_v3",
    "amneziawg_v3_1",
)
NEW_ISSUANCE_CONFIG_VERSIONS = ("amneziawg_v2", "amneziawg_v3_1")


class ConfigVersionError(ValueError):
    pass


def validate_config_version(version: str) -> str:
    if version not in SUPPORTED_CONFIG_VERSIONS:
        supported = ", ".join(SUPPORTED_CONFIG_VERSIONS)
        raise ConfigVersionError(f"Unsupported config version: {version}. Supported: {supported}")
    return version


def render_client_config_for_version(
    config: ClientConfigInput | Awg3ClientConfigInput,
    version: str,
    template_dir: str | Path | None = None,
    *,
    resolver: SecretResolver | None = None,
) -> str:
    validated = validate_config_version(version)
    if validated in {"amneziawg_v3", "amneziawg_v3_1"}:
        if not isinstance(config, Awg3ClientConfigInput):
            raise ConfigVersionError(f"{validated} requires Awg3ClientConfigInput")
        if resolver is None:
            raise ConfigVersionError(f"{validated} requires an explicit secret resolver")
        if template_dir is not None:
            raise ConfigVersionError(f"{validated} does not use AWG2 template overrides")
        return render_awg3_client_config(
            config,
            resolver=resolver,
            include_awg31=validated == "amneziawg_v3_1",
        )
    if not isinstance(config, ClientConfigInput):
        raise ConfigVersionError(f"{validated} requires ClientConfigInput")
    return render_client_config_from_template(config, validated, template_dir)
