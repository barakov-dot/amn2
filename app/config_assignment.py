from dataclasses import dataclass


DEDICATED_DEVICE = "dedicated_device"
OWNER_SHARED = "owner_shared"
RECIPIENT_UNASSIGNED = "recipient_unassigned"
CONFIG_ASSIGNMENT_MODES = (DEDICATED_DEVICE, OWNER_SHARED, RECIPIENT_UNASSIGNED)


@dataclass(frozen=True)
class ConfigAssignmentPolicy:
    mode: str
    physical_device_limit: int | None
    physical_device_count_enforceable: bool
    unique_peer_per_physical_device: bool
    passport_required: bool


def validate_config_assignment_mode(value: str) -> str:
    normalized = value.strip()
    if normalized not in CONFIG_ASSIGNMENT_MODES:
        raise ValueError(f"Unsupported config assignment mode: {value}")
    return normalized


def config_assignment_policy(value: str) -> ConfigAssignmentPolicy:
    mode = validate_config_assignment_mode(value)
    if mode == OWNER_SHARED:
        return ConfigAssignmentPolicy(
            mode=mode,
            physical_device_limit=None,
            physical_device_count_enforceable=False,
            unique_peer_per_physical_device=False,
            passport_required=True,
        )
    if mode == RECIPIENT_UNASSIGNED:
        return ConfigAssignmentPolicy(
            mode=mode,
            physical_device_limit=None,
            physical_device_count_enforceable=True,
            unique_peer_per_physical_device=False,
            passport_required=False,
        )
    return ConfigAssignmentPolicy(
        mode=mode,
        physical_device_limit=1,
        physical_device_count_enforceable=True,
        unique_peer_per_physical_device=True,
        passport_required=True,
    )
