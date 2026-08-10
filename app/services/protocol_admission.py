from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal

from app.services.client_compatibility import (
    ClientCompatibilityEvidence,
    ClientIdentity,
    CompatibilityAdmissionState,
    CompatibilityEvidenceStatus,
    SourceReleaseKind,
    classify_awg3_compatibility,
)
from app.services.vpn_runtime_instances import RuntimeInstanceSpec
from app.vpn.protocol_versions import ProtocolVersion


AdmissionDecision = Literal[
    "admitted_awg2",
    "admitted_awg3",
    "candidate_awg3",
    "blocked_unknown_client",
    "blocked_unverified_version",
    "blocked_unsupported_platform",
    "blocked_runtime_not_accepted",
    "blocked_evidence_stale_or_failed",
]


@dataclass(frozen=True)
class AdmissionResult:
    decision: AdmissionDecision
    protocol_version: ProtocolVersion
    runtime_instance_id: str | None
    compatibility_evidence_id: str | None

    @property
    def admitted(self) -> bool:
        return self.decision in {"admitted_awg2", "admitted_awg3"}


@dataclass(frozen=True)
class AdmissionRequest:
    client: ClientIdentity
    protocol_version: ProtocolVersion

    def __post_init__(self) -> None:
        if not isinstance(self.client, ClientIdentity):
            raise ValueError("client")
        if not isinstance(self.protocol_version, ProtocolVersion):
            raise ValueError("protocol_version")


class ProtocolAdmissionService:
    def __init__(
        self,
        *,
        evidence: tuple[ClientCompatibilityEvidence, ...],
        runtimes: tuple[RuntimeInstanceSpec, ...],
        now: datetime,
        max_evidence_age: timedelta = timedelta(days=90),
    ) -> None:
        if not isinstance(now, datetime) or now.utcoffset() is None:
            raise ValueError("now")
        if max_evidence_age < timedelta(0):
            raise ValueError("max_evidence_age")
        self._evidence = evidence
        self._runtimes = runtimes
        self._now = now
        self._max_evidence_age = max_evidence_age

    def decide(self, request: AdmissionRequest) -> AdmissionResult:
        known_apps = {item.client.application for item in self._evidence}
        if request.client.application not in known_apps:
            return AdmissionResult(
                "blocked_unknown_client", request.protocol_version, None, None
            )
        known_platforms = {
            item.client.platform
            for item in self._evidence
            if item.client.application == request.client.application
        }
        if request.client.platform not in known_platforms:
            return AdmissionResult(
                "blocked_unsupported_platform", request.protocol_version, None, None
            )

        exact = tuple(
            item
            for item in self._evidence
            if item.client == request.client
            and item.protocol_version is request.protocol_version
        )
        stale_or_failed = any(
            item.status
            in {
                CompatibilityEvidenceStatus.FAILED,
                CompatibilityEvidenceStatus.SUPERSEDED,
            }
            or not timedelta(0)
            <= self._now - item.observed_at
            <= self._max_evidence_age
            for item in exact
        )
        if request.protocol_version is ProtocolVersion.AWG3:
            compatibility = classify_awg3_compatibility(
                exact,
                client=request.client,
                now=self._now,
                max_evidence_age=self._max_evidence_age,
            )
            if compatibility is CompatibilityAdmissionState.CANDIDATE:
                if stale_or_failed:
                    return AdmissionResult(
                        "blocked_evidence_stale_or_failed",
                        request.protocol_version,
                        None,
                        None,
                    )
                runtime = next(
                    (
                        item
                        for item in self._runtimes
                        if item.protocol_version is request.protocol_version
                    ),
                    None,
                )
                return AdmissionResult(
                    "candidate_awg3",
                    request.protocol_version,
                    runtime.runtime_instance_id if runtime is not None else None,
                    None,
                )
            if compatibility is CompatibilityAdmissionState.REJECTED:
                decision: AdmissionDecision = (
                    "blocked_evidence_stale_or_failed"
                    if stale_or_failed
                    else "blocked_unverified_version"
                )
                return AdmissionResult(decision, request.protocol_version, None, None)
        passed = next(
            (
                item
                for item in sorted(exact, key=lambda value: value.observed_at, reverse=True)
                if item.status is CompatibilityEvidenceStatus.PASSED
                and (
                    request.protocol_version is not ProtocolVersion.AWG3
                    or (
                        item.source_kind == "full_data"
                        and item.client.build_id is not None
                        and item.release_kind is SourceReleaseKind.STABLE
                    )
                )
                and timedelta(0)
                <= self._now - item.observed_at
                <= self._max_evidence_age
            ),
            None,
        )
        if passed is None:
            decision: AdmissionDecision = (
                "blocked_evidence_stale_or_failed"
                if stale_or_failed
                else "blocked_unverified_version"
            )
            return AdmissionResult(decision, request.protocol_version, None, None)

        runtime = next(
            (
                item
                for item in self._runtimes
                if item.protocol_version is request.protocol_version
            ),
            None,
        )
        if runtime is None:
            return AdmissionResult(
                "blocked_runtime_not_accepted",
                request.protocol_version,
                None,
                passed.evidence_id,
            )
        if runtime.lifecycle_state != "accepted" or not runtime.acceptance_receipt:
            decision = (
                "candidate_awg3"
                if request.protocol_version is ProtocolVersion.AWG3
                else "blocked_runtime_not_accepted"
            )
            return AdmissionResult(
                decision,
                request.protocol_version,
                runtime.runtime_instance_id,
                passed.evidence_id,
            )
        decision = (
            "admitted_awg3"
            if request.protocol_version is ProtocolVersion.AWG3
            else "admitted_awg2"
        )
        return AdmissionResult(
            decision,
            request.protocol_version,
            runtime.runtime_instance_id,
            passed.evidence_id,
        )
