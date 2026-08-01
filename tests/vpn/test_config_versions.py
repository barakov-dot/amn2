import pytest

from app.vpn.amneziawg_v2.config import ClientConfigInput
from app.vpn.amneziawg_v3.config import (
    Awg3ClientConfigInput,
    HeaderProtectionSecretRef,
)
from app.vpn.config_versions import (
    NEW_ISSUANCE_CONFIG_VERSIONS,
    SUPPORTED_CONFIG_VERSIONS,
    ConfigVersionError,
    render_client_config_for_version,
    validate_config_version,
)


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


def test_supported_config_versions_are_explicit():
    assert SUPPORTED_CONFIG_VERSIONS == (
        "amneziawg_v1_5",
        "amneziawg_v2",
        "amneziawg_v3",
    )


def test_new_issuance_excludes_legacy_config_versions():
    assert NEW_ISSUANCE_CONFIG_VERSIONS == ("amneziawg_v2", "amneziawg_v3")


def test_validate_config_version_rejects_unknown_value():
    with pytest.raises(ConfigVersionError, match="Unsupported config version"):
        validate_config_version("wireguard")


def test_v2_renderer_keeps_existing_amneziawg_v2_fields():
    config = render_client_config_for_version(_input(), "amneziawg_v2")

    assert "Jc = 4" in config
    assert "S1 = 0" in config
    assert "H4 = 4" in config


def test_v1_5_renderer_omits_v2_only_s3_s4_and_keeps_basic_shape():
    config = render_client_config_for_version(_input(), "amneziawg_v1_5")

    assert "[Interface]" in config
    assert "PrivateKey = client-private" in config
    assert "[Peer]" in config
    assert "PresharedKey = psk" in config
    assert "S3 =" not in config
    assert "S4 =" not in config


class _Resolver:
    def resolve(self, reference: str) -> str:
        assert reference == "secret:awg3:hpk"
        return "raw-hpk"


def _awg3_input() -> Awg3ClientConfigInput:
    return Awg3ClientConfigInput(
        awg2=_input(),
        header_protection_key=HeaderProtectionSecretRef(
            "secret:awg3:hpk", "sha256:" + "b" * 64
        ),
        content_padding_addition="0-64",
        rekey_after_time="120",
        rekey_timeout="5",
        reject_after_time="180",
        keepalive_timeout="10",
        max_handshake_attempts="20",
    )


def test_v3_renderer_requires_typed_input_and_explicit_resolver():
    with pytest.raises(ConfigVersionError, match="resolver"):
        render_client_config_for_version(_awg3_input(), "amneziawg_v3")
    with pytest.raises(ConfigVersionError, match="Awg3ClientConfigInput"):
        render_client_config_for_version(
            _input(), "amneziawg_v3", resolver=_Resolver()
        )


def test_v3_renderer_routes_only_explicit_typed_input():
    config = render_client_config_for_version(
        _awg3_input(), "amneziawg_v3", resolver=_Resolver()
    )
    assert "HeaderProtectionKey = raw-hpk" in config
    assert "[Peer]" in config
