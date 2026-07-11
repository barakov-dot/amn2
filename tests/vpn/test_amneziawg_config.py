import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from app.vpn.amneziawg_v2.config import (
    ClientConfigDefaults,
    ClientConfigInput,
    render_client_config,
    validate_magic_headers,
)
from app.vpn.amneziawg_v2.keys import generate_key, generate_keypair


def test_render_client_config_contains_expected_fields():
    config = render_client_config(
        ClientConfigInput(
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
    )

    assert "[Interface]" in config
    assert "PrivateKey = client-private" in config
    assert "Address = 10.8.0.2/32" in config
    assert "DNS = 1.1.1.1" in config
    assert "[Peer]" in config
    assert "PublicKey = server-public" in config
    assert "PresharedKey = psk" in config
    assert "Endpoint = vpn.example.com:30001" in config
    assert "AllowedIPs = 0.0.0.0/0" in config
    assert "PersistentKeepalive = 25" in config
    assert "Jc = 4" in config
    assert "H4 = 4" in config


def test_render_client_config_contains_full_amneziawg_v2_fields():
    config = render_client_config(
        ClientConfigInput(
            private_key="client-private",
            address="10.8.1.2/32",
            dns="8.8.8.8, 8.8.4.4",
            server_public_key="server-public",
            preshared_key="psk",
            endpoint="backup.smart-finance.ru:37661",
            allowed_ips="0.0.0.0/0, ::/0",
            persistent_keepalive=25,
            jc=4,
            jmin=10,
            jmax=50,
            s1=19,
            s2=90,
            s3=45,
            s4=17,
            h1="1622123045-2053868572",
            h2="2065609453-2121973747",
            h3="2144678566-2147363193",
            h4="2147478675-2147482564",
            i1="<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>",
            i2="",
            i3="",
            i4="",
            i5="",
        )
    )

    assert "Address = 10.8.1.2/32" in config
    assert "DNS = 8.8.8.8, 8.8.4.4" in config
    assert "S3 = 45" in config
    assert "S4 = 17" in config
    assert "I1 = <r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>" in config
    assert "I2 = " in config
    assert "I5 = " in config
    assert "AllowedIPs = 0.0.0.0/0, ::/0" in config


def test_validate_magic_headers_accepts_single_and_ranged_uint32_values():
    validate_magic_headers(
        {
            "H1": 0,
            "H2": "1-100",
            "H3": "101",
            "H4": "4294967294-4294967295",
        }
    )


@pytest.mark.parametrize(
    "value",
    ["", "1-", "-1", "2-1", "1-2-3", " 1-2", 4294967296],
)
def test_validate_magic_headers_rejects_invalid_values(value):
    with pytest.raises(ValueError, match="H1"):
        validate_magic_headers({"H1": value, "H2": 10, "H3": 20, "H4": 30})


def test_validate_magic_headers_rejects_overlapping_ranges():
    with pytest.raises(ValueError, match="must not overlap"):
        validate_magic_headers(
            {"H1": "100-200", "H2": "200-300", "H3": 400, "H4": 500}
        )


def test_client_config_defaults_rejects_ambiguous_magic_headers():
    with pytest.raises(ValueError, match="must not overlap"):
        ClientConfigDefaults(h1=100, h2="90-110", h3=200, h4=300)


def test_generate_key_returns_base64_encoded_32_byte_secret():
    key = generate_key()

    assert len(base64.b64decode(key)) == 32


def test_generate_keypair_returns_matching_base64_x25519_keys():
    keypair = generate_keypair()

    private_bytes = base64.b64decode(keypair.private_key)
    public_bytes = base64.b64decode(keypair.public_key)
    derived_public_bytes = (
        x25519.X25519PrivateKey.from_private_bytes(private_bytes)
        .public_key()
        .public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )

    assert len(private_bytes) == 32
    assert len(public_bytes) == 32
    assert public_bytes == derived_public_bytes
