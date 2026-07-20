import pytest

from app.config_assignment import (
    DEDICATED_DEVICE,
    OWNER_SHARED,
    RECIPIENT_UNASSIGNED,
    config_assignment_policy,
    validate_config_assignment_mode,
)


def test_dedicated_device_policy_is_one_peer_per_physical_device():
    policy = config_assignment_policy(DEDICATED_DEVICE)

    assert policy.physical_device_limit == 1
    assert policy.physical_device_count_enforceable is True
    assert policy.unique_peer_per_physical_device is True
    assert policy.passport_required is True


def test_owner_shared_policy_is_explicitly_unbounded_and_not_enforceable():
    policy = config_assignment_policy(OWNER_SHARED)

    assert policy.physical_device_limit is None
    assert policy.physical_device_count_enforceable is False
    assert policy.unique_peer_per_physical_device is False
    assert policy.passport_required is True


def test_recipient_unassigned_policy_is_counted_without_fake_device_identity():
    policy = config_assignment_policy(RECIPIENT_UNASSIGNED)

    assert policy.physical_device_limit is None
    assert policy.physical_device_count_enforceable is True
    assert policy.unique_peer_per_physical_device is False
    assert policy.passport_required is False


def test_config_assignment_mode_rejects_unknown_and_normalizes_padding():
    with pytest.raises(ValueError, match="Unsupported config assignment mode"):
        validate_config_assignment_mode("shared_for_customer")

    assert validate_config_assignment_mode(" owner_shared ") == OWNER_SHARED
