import hashlib
import json
from dataclasses import replace

import pytest

from app.vpn.amneziawg_v2.config import (
    ClientConfigInput,
    render_client_config as render_awg2_client_config,
)
from app.vpn.amneziawg_v3.config import (
    Awg3ClientConfigInput,
    HeaderProtectionSecretRef,
    render_awg3_client_config,
)


def existing_awg2_input() -> ClientConfigInput:
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


class StaticResolver:
    def __init__(self, value: str) -> None:
        self._value = value

    def resolve(self, reference: str) -> str:
        assert reference == "secret:awg3:hpk"
        return self._value


def awg3_input(
    *, s1: int = 12, s2: int = 12, s3: int = 12, s4: int = 12
) -> Awg3ClientConfigInput:
    return Awg3ClientConfigInput(
        awg2=replace(existing_awg2_input(), s1=s1, s2=s2, s3=s3, s4=s4),
        header_protection_key=HeaderProtectionSecretRef(
            reference="secret:awg3:hpk",
            fingerprint="sha256:" + "b" * 64,
        ),
        content_padding_addition="0-64",
        rekey_after_time="120",
        rekey_timeout="5",
        reject_after_time="180",
        keepalive_timeout="10",
        max_handshake_attempts="20",
        random_trailers=True,
        disable_cookies=True,
    )


def test_awg2_renderer_golden_output_is_byte_unchanged():
    source = existing_awg2_input()
    assert (source.s1, source.s2, source.s3, source.s4) == (0, 0, 0, 0)
    rendered = render_awg2_client_config(source).encode()
    assert len(rendered) == 323
    assert hashlib.sha256(rendered).hexdigest() == (
        "8425d1666135621c398e1df29ee82c849a28641a152ddf1f69b5330f6b95e5eb"
    )


@pytest.mark.parametrize("field", ["s1", "s2", "s3", "s4"])
def test_awg3_header_protection_rejects_each_nonce_below_12(field):
    values = {"s1": 12, "s2": 12, "s3": 12, "s4": 12}
    values[field] = 11
    with pytest.raises(ValueError, match="S1-S4.*12"):
        render_awg3_client_config(
            awg3_input(**values), resolver=StaticResolver("raw-hpk")
        )


def test_awg3_header_protection_accepts_all_nonces_at_12():
    rendered = render_awg3_client_config(
        awg3_input(s1=12, s2=12, s3=12, s4=12),
        resolver=StaticResolver("raw-hpk"),
    )
    assert "HeaderProtectionKey" in rendered


def test_awg2_input_rejects_awg3_only_fields():
    with pytest.raises(TypeError):
        ClientConfigInput(
            **vars(existing_awg2_input()),
            header_protection_key_ref="secret:awg3",
        )


def test_awg3_requires_secret_reference_and_renders_official_field_names():
    config = render_awg3_client_config(
        awg3_input(), resolver=StaticResolver("raw-hpk"), include_awg31=True
    )
    assert "HeaderProtectionKey = raw-hpk" in config
    assert "ContentPaddingAddition = 0-64" in config
    assert "RekeyAfterTime = 120" in config
    assert "RekeyTimeout = 5" in config
    assert "RejectAfterTime = 180" in config
    assert "KeepaliveTimeout = 10" in config
    assert "MaxHandshakeAttempts = 20" in config
    assert "RandomTrailers = on" in config
    assert "DisableCookies = on" in config


def test_awg3_secret_is_absent_from_repr_and_safe_metadata():
    raw = "never-log-header-protection-key"
    value = awg3_input()
    metadata = value.safe_metadata()
    assert raw not in repr(value)
    assert raw not in json.dumps(metadata)
    assert metadata == {
        "header_protection_key_fingerprint": "sha256:" + "b" * 64,
        "protocol_version": "awg3",
    }


def test_invalid_resolved_secret_never_appears_in_error():
    raw = "raw-secret\nInjected = true"
    with pytest.raises(ValueError) as exc_info:
        render_awg3_client_config(awg3_input(), resolver=StaticResolver(raw))
    assert raw not in str(exc_info.value)


def test_resolver_failure_is_redacted():
    raw = "resolver-leaked-raw-secret"

    class FailingResolver:
        def resolve(self, reference: str) -> str:
            raise RuntimeError(raw)

    with pytest.raises(ValueError, match="could not be resolved") as exc_info:
        render_awg3_client_config(awg3_input(), resolver=FailingResolver())
    assert raw not in str(exc_info.value)
