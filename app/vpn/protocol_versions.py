from enum import StrEnum


class ProtocolVersion(StrEnum):
    AWG2 = "awg2"
    AWG3 = "awg3"


AWG3_ACTIVE_REVISION = "3.1"
AWG3_ACTIVE_CONFIG_VERSION = "amneziawg_v3_1"
AWG3_REQUIRED_RUNTIME_CAPABILITIES = ("disable_cookies", "random_trailers")


NEW_ISSUANCE_PROTOCOLS = (ProtocolVersion.AWG2, ProtocolVersion.AWG3)


def normalize_protocol_version(value: object) -> ProtocolVersion:
    if not isinstance(value, str):
        raise ValueError("unsupported protocol_version")
    try:
        return ProtocolVersion(value)
    except ValueError as exc:
        raise ValueError("unsupported protocol_version") from exc


def config_version_for_protocol(protocol: ProtocolVersion) -> str:
    return {
        ProtocolVersion.AWG2: "amneziawg_v2",
        ProtocolVersion.AWG3: AWG3_ACTIVE_CONFIG_VERSION,
    }[protocol]
