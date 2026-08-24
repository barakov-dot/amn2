import pytest

from app.vpn.protocol_versions import (
    NEW_ISSUANCE_PROTOCOLS,
    ProtocolVersion,
    config_version_for_protocol,
    normalize_protocol_version,
)


def test_new_issuance_protocols_are_exactly_awg2_and_awg3():
    assert NEW_ISSUANCE_PROTOCOLS == (
        ProtocolVersion.AWG2,
        ProtocolVersion.AWG3,
    )


def test_protocol_normalization_is_exact_and_fail_closed():
    assert normalize_protocol_version("awg2") is ProtocolVersion.AWG2
    assert normalize_protocol_version("awg3") is ProtocolVersion.AWG3
    for value in ("", "AWG3", "latest", "amneziawg_v1_5", None):
        with pytest.raises(ValueError, match="unsupported protocol_version"):
            normalize_protocol_version(value)


def test_protocol_to_config_schema_mapping_does_not_alias_awg3_to_awg2():
    assert config_version_for_protocol(ProtocolVersion.AWG2) == "amneziawg_v2"
    assert config_version_for_protocol(ProtocolVersion.AWG3) == "amneziawg_v3_1"
