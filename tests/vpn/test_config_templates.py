import base64

import pytest

from app.vpn.amneziawg_v1_5.config import render_client_config as render_v1_5_config
from app.vpn.amneziawg_v2.config import ClientConfigInput
from app.vpn.amneziawg_v2.config import render_client_config as render_v2_config
from app.vpn.config_templates import (
    AVAILABLE_CLIENT_CONFIG_PLACEHOLDERS,
    ConfigTemplateError,
    build_vpn_import_link,
    load_client_config_template,
    render_client_config_from_template,
    render_client_config_template,
)
from app.vpn.config_versions import render_client_config_for_version


def test_default_templates_preserve_current_config_shapes():
    config = _input()

    assert render_client_config_from_template(config, "amneziawg_v2") == render_v2_config(config)
    assert render_client_config_from_template(config, "amneziawg_v1_5") == render_v1_5_config(config)


def test_available_placeholders_match_client_config_input_fields():
    assert set(AVAILABLE_CLIENT_CONFIG_PLACEHOLDERS) == set(ClientConfigInput.__dataclass_fields__)
    assert "private_key" in AVAILABLE_CLIENT_CONFIG_PLACEHOLDERS
    assert "preshared_key" in AVAILABLE_CLIENT_CONFIG_PLACEHOLDERS


def test_template_renderer_rejects_unknown_placeholders():
    with pytest.raises(ConfigTemplateError, match="unknown.*Supported placeholders"):
        render_client_config_template("PrivateKey = {unknown}", _input())


def test_template_renderer_rejects_empty_rendered_config():
    with pytest.raises(ConfigTemplateError, match="empty"):
        render_client_config_template("   \n\t", _input())


@pytest.mark.parametrize(
    "template_text",
    [
        "PrivateKey = {private_key!r}",
        "PrivateKey = {private_key:>20}",
        "PrivateKey = {private_key:{address}}",
        "PrivateKey = {private_key",
    ],
)
def test_template_renderer_rejects_format_features_and_malformed_templates(
    template_text: str,
):
    with pytest.raises(ConfigTemplateError):
        render_client_config_template(template_text, _input())


def test_external_template_override_takes_precedence(tmp_path):
    template_dir = tmp_path / "templates"
    template_dir.mkdir()
    override = "OVERRIDE private={private_key} endpoint={endpoint}\n"
    (template_dir / "amneziawg_v2.conf.tpl").write_text(override, encoding="utf-8")

    assert load_client_config_template("amneziawg_v2", template_dir) == override
    assert render_client_config_for_version(
        _input(),
        "amneziawg_v2",
        template_dir=template_dir,
    ) == "OVERRIDE private=client-private endpoint=vpn.example.com:30001\n"


def test_vpn_import_link_encodes_config_without_raw_secret_text():
    config_text = "[Interface]\nPrivateKey = client-private\n[Peer]\nEndpoint = vpn.example.com:30001\n"

    link = build_vpn_import_link(config_text)

    assert link.startswith("vpn://")
    assert "PrivateKey" not in link
    assert "client-private" not in link
    payload = link.removeprefix("vpn://")
    padding = "=" * (-len(payload) % 4)
    assert base64.urlsafe_b64decode(payload + padding).decode("utf-8") == config_text


def _input() -> ClientConfigInput:
    return ClientConfigInput(
        private_key="client-private",
        address="10.8.0.2/32",
        dns="1.1.1.1",
        server_public_key="server-public",
        preshared_key="psk",
        endpoint="vpn.example.com:30001",
        allowed_ips="0.0.0.0/0",
        persistent_keepalive=25,
        jc=4,
        jmin=40,
        jmax=70,
        s1=0,
        s2=0,
        h1=1,
        h2=2,
        h3=3,
        h4=4,
    )
