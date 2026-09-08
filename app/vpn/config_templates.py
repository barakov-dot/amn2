from __future__ import annotations

import base64
from dataclasses import asdict, fields
from pathlib import Path
from string import Formatter

from app.vpn.amneziawg_v2.config import ClientConfigInput
from app.vpn.client_import_artifacts import build_client_import_artifact


SUPPORTED_CLIENT_CONFIG_VERSIONS = ("amneziawg_v1_5", "amneziawg_v2")
AVAILABLE_CLIENT_CONFIG_PLACEHOLDERS = tuple(
    field.name for field in fields(ClientConfigInput)
)

_PACKAGE_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


class ConfigTemplateError(ValueError):
    pass


def load_client_config_template(
    config_version: str,
    template_dir: str | Path | None = None,
) -> str:
    _validate_config_template_version(config_version)
    override_path = _override_template_path(config_version, template_dir)
    if override_path is not None and override_path.is_file():
        return _read_template(override_path)

    package_path = _package_template_path(config_version)
    if not package_path.is_file():
        raise ConfigTemplateError(
            f"Default client config template is missing: {package_path.name}"
        )
    return _read_template(package_path)


def client_config_template_source(
    config_version: str,
    template_dir: str | Path | None = None,
) -> str:
    _validate_config_template_version(config_version)
    override_path = _override_template_path(config_version, template_dir)
    if override_path is not None and override_path.is_file():
        return "override"
    return "default"


def save_client_config_template_override(
    config_version: str,
    template_text: str,
    template_dir: str | Path | None,
) -> Path:
    _validate_config_template_version(config_version)
    _validate_template_placeholders(template_text)
    override_path = _require_override_template_path(config_version, template_dir)
    override_path.parent.mkdir(parents=True, exist_ok=True)
    override_path.write_text(_ensure_trailing_newline(template_text), encoding="utf-8")
    return override_path


def reset_client_config_template_override(
    config_version: str,
    template_dir: str | Path | None,
) -> bool:
    _validate_config_template_version(config_version)
    override_path = _require_override_template_path(config_version, template_dir)
    if not override_path.exists():
        return False
    override_path.unlink()
    return True


def render_client_config_template(
    template_text: str,
    config: ClientConfigInput,
) -> str:
    _validate_template_placeholders(template_text)
    try:
        return template_text.format_map(asdict(config))
    except (IndexError, KeyError, ValueError) as exc:
        raise ConfigTemplateError(f"Invalid client config template: {exc}") from exc


def render_client_config_from_template(
    config: ClientConfigInput,
    config_version: str,
    template_dir: str | Path | None = None,
) -> str:
    template_text = load_client_config_template(config_version, template_dir)
    return render_client_config_template(template_text, config)


def build_vpn_import_link(config_text: str, *, target_client: str | None = None) -> str:
    if target_client is not None:
        artifact = build_client_import_artifact(config_text, target_client=target_client)
        if artifact.vpn_import_link is None:
            raise ConfigTemplateError("selected_client_requires_conf_file")
        return artifact.vpn_import_link
    payload = base64.urlsafe_b64encode(config_text.encode("utf-8")).decode("ascii")
    return "vpn://" + payload.rstrip("=")


def _validate_config_template_version(config_version: str) -> None:
    if config_version not in SUPPORTED_CLIENT_CONFIG_VERSIONS:
        supported = ", ".join(SUPPORTED_CLIENT_CONFIG_VERSIONS)
        raise ConfigTemplateError(
            f"Unsupported client config template version: {config_version}. "
            f"Supported: {supported}"
        )


def _validate_template_placeholders(template_text: str) -> None:
    formatter = Formatter()
    unknown: set[str] = set()
    try:
        parsed = formatter.parse(template_text)
        for _, field_name, format_spec, conversion in parsed:
            if field_name is None:
                continue
            if conversion is not None:
                raise ConfigTemplateError(
                    f"Unsupported conversion for client config placeholder {{{field_name}}}"
                )
            if format_spec:
                raise ConfigTemplateError(
                    f"Unsupported format spec for client config placeholder {{{field_name}}}"
                )
            if field_name not in AVAILABLE_CLIENT_CONFIG_PLACEHOLDERS:
                unknown.add(field_name)
    except ValueError as exc:
        raise ConfigTemplateError(f"Invalid client config template: {exc}") from exc
    if unknown:
        supported = ", ".join(f"{{{name}}}" for name in AVAILABLE_CLIENT_CONFIG_PLACEHOLDERS)
        raise ConfigTemplateError(
            "Unknown client config placeholder(s): "
            + ", ".join(f"{{{name}}}" for name in sorted(unknown))
            + f". Supported placeholders: {supported}"
        )


def _override_template_path(
    config_version: str,
    template_dir: str | Path | None,
) -> Path | None:
    if template_dir is None or not str(template_dir).strip():
        return None
    return Path(template_dir) / _template_filename(config_version)


def _require_override_template_path(
    config_version: str,
    template_dir: str | Path | None,
) -> Path:
    override_path = _override_template_path(config_version, template_dir)
    if override_path is None:
        raise ConfigTemplateError("CLIENT_CONFIG_TEMPLATE_DIR must be configured")
    return override_path


def _package_template_path(config_version: str) -> Path:
    return _PACKAGE_TEMPLATE_DIR / _template_filename(config_version)


def _template_filename(config_version: str) -> str:
    return f"{config_version}.conf.tpl"


def _read_template(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigTemplateError(f"Could not read client config template {path}") from exc


def _ensure_trailing_newline(value: str) -> str:
    return value if value.endswith("\n") else value + "\n"
