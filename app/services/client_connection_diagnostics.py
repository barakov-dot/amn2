from __future__ import annotations

from dataclasses import dataclass
from math import isfinite
from typing import Literal


ClientConnectionStatus = Literal[
    "PASS",
    "PASS_WITH_PERFORMANCE_WARNING",
    "INSUFFICIENT_EVIDENCE",
    "FAILURE_OBSERVED",
]
RootCauseConfidence = Literal["NONE", "LOW", "MEDIUM", "HIGH"]
WarningNextAction = Literal["collect_readonly_repeatable_latency_evidence"]


@dataclass(frozen=True, slots=True)
class ClientConnectionObservation:
    site_successes: int
    site_attempts: int
    telegram_successes: int
    telegram_attempts: int
    telegram_connect_max_seconds: float | None
    telegram_ttfb_max_seconds: float | None
    sustained_transfer_completed: bool
    sustained_transfer_bytes: int
    sustained_transfer_seconds: float | None
    short_probe_failures_present: bool
    observation_fresh: bool = True

    def __post_init__(self) -> None:
        for field_name in (
            "sustained_transfer_completed",
            "short_probe_failures_present",
            "observation_fresh",
        ):
            if type(getattr(self, field_name)) is not bool:
                raise ValueError(field_name)

        for field_name in (
            "site_successes",
            "site_attempts",
            "telegram_successes",
            "telegram_attempts",
            "sustained_transfer_bytes",
        ):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(field_name)

        for field_name in (
            "telegram_connect_max_seconds",
            "telegram_ttfb_max_seconds",
            "sustained_transfer_seconds",
        ):
            value = getattr(self, field_name)
            if value is None:
                continue
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or (isinstance(value, float) and not isfinite(value))
            ):
                raise ValueError(field_name)


@dataclass(frozen=True, slots=True)
class ClientConnectionResult:
    status: ClientConnectionStatus
    root_cause: str | None
    root_cause_confidence: RootCauseConfidence
    tunnel_drop_proven: bool
    mutation_recommended: bool
    next_action: WarningNextAction | None


def classify_client_connection(
    observation: ClientConnectionObservation,
) -> ClientConnectionResult:
    if not observation.observation_fresh or not _attempt_evidence_is_complete(
        observation
    ):
        return _result("INSUFFICIENT_EVIDENCE")

    realistic_failure_observed = (
        observation.site_successes < observation.site_attempts
        or observation.telegram_successes < observation.telegram_attempts
        or not observation.sustained_transfer_completed
    )
    if realistic_failure_observed:
        return _result("FAILURE_OBSERVED")

    if not _latency_evidence_is_complete(observation):
        return _result("INSUFFICIENT_EVIDENCE")

    if observation.short_probe_failures_present:
        return _result(
            "PASS_WITH_PERFORMANCE_WARNING",
            next_action="collect_readonly_repeatable_latency_evidence",
        )

    return _result("PASS")


def _attempt_evidence_is_complete(
    observation: ClientConnectionObservation,
) -> bool:
    return (
        observation.site_attempts > 0
        and observation.telegram_attempts > 0
        and 0 <= observation.site_successes <= observation.site_attempts
        and 0 <= observation.telegram_successes <= observation.telegram_attempts
        and observation.sustained_transfer_bytes >= 0
    )


def _latency_evidence_is_complete(
    observation: ClientConnectionObservation,
) -> bool:
    return (
        observation.telegram_connect_max_seconds is not None
        and observation.telegram_connect_max_seconds >= 0
        and observation.telegram_ttfb_max_seconds is not None
        and observation.telegram_ttfb_max_seconds >= 0
        and observation.sustained_transfer_bytes > 0
        and observation.sustained_transfer_seconds is not None
        and observation.sustained_transfer_seconds > 0
    )


def _result(
    status: ClientConnectionStatus,
    *,
    next_action: WarningNextAction | None = None,
) -> ClientConnectionResult:
    return ClientConnectionResult(
        status=status,
        root_cause=None,
        root_cause_confidence="NONE",
        tunnel_drop_proven=False,
        mutation_recommended=False,
        next_action=next_action,
    )
