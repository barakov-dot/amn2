from enum import StrEnum


class ProtocolVersion(StrEnum):
    AWG2 = "awg2"
    AWG3 = "awg3"


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
        ProtocolVersion.AWG3: "amneziawg_v3",
    }[protocol]
