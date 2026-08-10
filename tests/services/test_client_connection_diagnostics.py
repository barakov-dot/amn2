from __future__ import annotations

from dataclasses import FrozenInstanceError, fields, replace

import pytest

from app.services.client_connection_diagnostics import (
    ClientConnectionObservation,
    ClientConnectionResult,
    classify_client_connection,
)


def _successful_observation(
    *,
    short_probe_failures_present: bool = False,
) -> ClientConnectionObservation:
    return ClientConnectionObservation(
        site_successes=6,
        site_attempts=6,
        telegram_successes=6,
        telegram_attempts=6,
        telegram_connect_max_seconds=0.8,
        telegram_ttfb_max_seconds=1.2,
        sustained_transfer_completed=True,
        sustained_transfer_bytes=2_097_152,
        sustained_transfer_seconds=8.9,
        short_probe_failures_present=short_probe_failures_present,
    )


def _stale_partial_observation() -> ClientConnectionObservation:
    return ClientConnectionObservation(
        site_successes=1,
        site_attempts=2,
        telegram_successes=0,
        telegram_attempts=0,
        telegram_connect_max_seconds=None,
        telegram_ttfb_max_seconds=None,
        sustained_transfer_completed=False,
        sustained_transfer_bytes=0,
        sustained_transfer_seconds=None,
        short_probe_failures_present=True,
        observation_fresh=False,
    )


@pytest.mark.parametrize(
    ("field_name", "malformed_value"),
    [
        ("sustained_transfer_completed", "false"),
        ("short_probe_failures_present", "false"),
        ("observation_fresh", "false"),
        ("site_successes", True),
        ("site_attempts", True),
        ("telegram_successes", True),
        ("telegram_attempts", True),
        ("sustained_transfer_bytes", True),
        ("telegram_connect_max_seconds", float("inf")),
        ("telegram_ttfb_max_seconds", float("inf")),
        ("sustained_transfer_seconds", float("inf")),
        ("site_attempts", "6"),
    ],
)
def test_observation_rejects_malformed_runtime_evidence(
    field_name: str,
    malformed_value: object,
):
    with pytest.raises(ValueError, match=field_name):
        replace(
            _successful_observation(),
            **{field_name: malformed_value},
        )


def test_realistic_success_with_latency_is_a_nonblocking_warning():
    observation = ClientConnectionObservation(
        site_successes=6,
        site_attempts=6,
        telegram_successes=6,
        telegram_attempts=6,
        telegram_connect_max_seconds=7.3,
        telegram_ttfb_max_seconds=9.2,
        sustained_transfer_completed=True,
        sustained_transfer_bytes=2_097_152,
        sustained_transfer_seconds=8.9,
        short_probe_failures_present=True,
    )

    result = classify_client_connection(observation)

    assert result.status == "PASS_WITH_PERFORMANCE_WARNING"
    assert result.tunnel_drop_proven is False
    assert result.mutation_recommended is False
    assert result.next_action == "collect_readonly_repeatable_latency_evidence"
    assert result.root_cause is None
    assert result.root_cause_confidence == "NONE"


def test_short_probe_failures_do_not_override_realistic_success():
    result = classify_client_connection(
        _successful_observation(short_probe_failures_present=True)
    )

    assert result.status == "PASS_WITH_PERFORMANCE_WARNING"
    assert result.tunnel_drop_proven is False


def test_complete_success_without_probe_failures_passes():
    result = classify_client_connection(_successful_observation())

    assert result.status == "PASS"
    assert result.next_action is None
    assert result.mutation_recommended is False


def test_partial_or_stale_observation_never_claims_root_cause():
    result = classify_client_connection(_stale_partial_observation())

    assert result.status == "INSUFFICIENT_EVIDENCE"
    assert result.root_cause is None
    assert result.root_cause_confidence == "NONE"
    assert result.tunnel_drop_proven is False
    assert result.mutation_recommended is False


def test_fresh_failed_realistic_checks_report_failure_without_diagnosing_cause():
    observation = ClientConnectionObservation(
        site_successes=0,
        site_attempts=6,
        telegram_successes=0,
        telegram_attempts=6,
        telegram_connect_max_seconds=None,
        telegram_ttfb_max_seconds=None,
        sustained_transfer_completed=False,
        sustained_transfer_bytes=0,
        sustained_transfer_seconds=None,
        short_probe_failures_present=True,
    )

    result = classify_client_connection(observation)

    assert result.status == "FAILURE_OBSERVED"
    assert result.root_cause is None
    assert result.root_cause_confidence == "NONE"
    assert result.tunnel_drop_proven is False
    assert result.mutation_recommended is False
    assert result.next_action is None


def test_incomplete_fresh_observation_is_insufficient_evidence():
    observation = ClientConnectionObservation(
        site_successes=0,
        site_attempts=0,
        telegram_successes=0,
        telegram_attempts=0,
        telegram_connect_max_seconds=None,
        telegram_ttfb_max_seconds=None,
        sustained_transfer_completed=False,
        sustained_transfer_bytes=0,
        sustained_transfer_seconds=None,
        short_probe_failures_present=False,
    )

    result = classify_client_connection(observation)

    assert result.status == "INSUFFICIENT_EVIDENCE"
    assert result.root_cause is None


def test_observation_and_result_models_are_immutable():
    observation = _successful_observation()
    result = classify_client_connection(observation)

    with pytest.raises(FrozenInstanceError):
        observation.site_successes = 0  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        result.status = "FAILURE_OBSERVED"  # type: ignore[misc]


def test_models_carry_no_secret_or_stable_target_identity_fields():
    forbidden = {
        "endpoint",
        "key",
        "payload",
        "telegram_id",
        "raw_log",
        "fingerprint",
        "mtu",
        "config",
        "peer",
        "server",
        "client",
    }

    for model in (ClientConnectionObservation, ClientConnectionResult):
        field_names = {field.name for field in fields(model)}
        assert field_names.isdisjoint(forbidden)
