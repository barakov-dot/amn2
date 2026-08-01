from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Literal

from app.db.repositories import Repository
from app.services.peer_inventory import (
    PeerInventoryCollector,
    PeerInventoryError,
    RemotePeer,
)


DriftState = Literal[
    "aligned",
    "missing_remote",
    "unexpected_remote",
    "stale_observation",
    "observation_failed",
    "unknown",
]

RecommendedAction = Literal[
    "none",
    "collect_fresh_observation",
    "inspect_observation_failure",
    "review_missing_remote_before_apply",
    "review_unexpected_remote_before_apply",
    "manual_review",
]


@dataclass(frozen=True)
class DesiredPeerState:
    peer_expected: bool | None
    peer_public_key: str | None
    allowed_ips: tuple[str, ...]
    device_status: str | None
    protocol_version: str | None = None
    runtime_instance_id: str | None = None
    compatibility_evidence_id: str | None = None
    compatibility_status: str | None = None
    runtime_state: str | None = None

    def safe_metadata(self) -> dict[str, object]:
        return {
            "peer_expected": self.peer_expected,
            "peer_public_key_fingerprint": _fingerprint(self.peer_public_key),
            "allowed_ips": list(self.allowed_ips),
            "device_status": self.device_status,
            "protocol_version": self.protocol_version,
            "runtime_instance_id": self.runtime_instance_id,
            "compatibility_evidence_id": self.compatibility_evidence_id,
            "compatibility_status": self.compatibility_status,
            "runtime_state": self.runtime_state,
        }


@dataclass(frozen=True)
class ObservedPeerState:
    peer_present: bool | None
    peer_public_key: str | None
    allowed_ips: tuple[str, ...]
    observation_succeeded: bool
    protocol_version: str | None = None
    runtime_instance_id: str | None = None

    def safe_metadata(self) -> dict[str, object]:
        return {
            "peer_present": self.peer_present,
            "peer_public_key_fingerprint": _fingerprint(self.peer_public_key),
            "allowed_ips": list(self.allowed_ips),
            "observation_succeeded": self.observation_succeeded,
            "protocol_version": self.protocol_version,
            "runtime_instance_id": self.runtime_instance_id,
        }


@dataclass(frozen=True, order=True)
class ReconciliationEvidence:
    source: str
    reference: str
    collected_at: datetime

    def safe_metadata(self) -> dict[str, str]:
        return {
            "source": self.source,
            "reference": self.reference,
            "collected_at": _format_datetime(self.collected_at),
        }


@dataclass(frozen=True)
class ReconciliationSnapshot:
    subject_id: str
    desired_state: DesiredPeerState
    observed_state: ObservedPeerState
    drift_state: DriftState
    drift_reason: str
    last_observed_at: datetime | None
    evidence: tuple[ReconciliationEvidence, ...]
    recommended_next_action: RecommendedAction

    @property
    def freshness(self) -> str:
        if self.drift_state == "stale_observation":
            return "stale"
        if self.drift_state == "observation_failed":
            return "failed"
        if self.last_observed_at is None:
            return "unknown"
        return "fresh"

    def safe_metadata(self) -> dict[str, object]:
        return {
            "subject_id": self.subject_id,
            "desired_state": self.desired_state.safe_metadata(),
            "observed_state": self.observed_state.safe_metadata(),
            "drift_state": self.drift_state,
            "drift_reason": self.drift_reason,
            "last_observed_at": (
                _format_datetime(self.last_observed_at)
                if self.last_observed_at is not None
                else None
            ),
            "freshness": self.freshness,
            "evidence": [item.safe_metadata() for item in sorted(self.evidence)],
            "recommended_next_action": self.recommended_next_action,
        }


class DriftDiagnosticsService:
    """Builds report-only snapshots from local desired and remote observed state."""

    def __init__(
        self,
        repo: Repository,
        *,
        stale_after: timedelta = timedelta(minutes=5),
    ) -> None:
        if stale_after <= timedelta(0):
            raise ValueError("stale_after must be positive")
        self._repo = repo
        self._stale_after = stale_after

    def diagnose_server(
        self,
        server_id: int,
        collector: PeerInventoryCollector,
        *,
        observed_at: datetime,
        now: datetime | None = None,
    ) -> tuple[ReconciliationSnapshot, ...]:
        current_time = _as_utc(now or datetime.now(timezone.utc))
        observation_time = _as_utc(observed_at)
        local_rows = self._repo.list_active_devices_for_server(server_id)

        try:
            remote_peers = collector.collect(server_id)
        except PeerInventoryError:
            return tuple(
                classify_reconciliation(
                    subject_id=f"device:{int(row['id'])}",
                    desired=_desired_from_row(row),
                    observed=ObservedPeerState(
                        peer_present=None,
                        peer_public_key=None,
                        allowed_ips=(),
                        observation_succeeded=False,
                    ),
                    observed_at=observation_time,
                    now=current_time,
                    stale_after=self._stale_after,
                    evidence=(
                        _local_evidence(row, observation_time),
                        ReconciliationEvidence(
                            source="awg_peer_inventory",
                            reference="collection_failed",
                            collected_at=observation_time,
                        ),
                    ),
                )
                for row in local_rows
            )

        return self._diagnose_inventory(
            local_rows=local_rows,
            remote_peers=remote_peers,
            observation_time=observation_time,
            current_time=current_time,
        )

    def diagnose_inventory(
        self,
        server_id: int,
        remote_peers: list[RemotePeer] | tuple[RemotePeer, ...],
        *,
        observed_at: datetime,
        now: datetime | None = None,
    ) -> tuple[ReconciliationSnapshot, ...]:
        return self._diagnose_inventory(
            local_rows=self._repo.list_active_devices_for_server(server_id),
            remote_peers=remote_peers,
            observation_time=_as_utc(observed_at),
            current_time=_as_utc(now or datetime.now(timezone.utc)),
        )

    def _diagnose_inventory(
        self,
        *,
        local_rows,
        remote_peers: list[RemotePeer] | tuple[RemotePeer, ...],
        observation_time: datetime,
        current_time: datetime,
    ) -> tuple[ReconciliationSnapshot, ...]:

        remote_by_key = {peer.peer_public_key: peer for peer in remote_peers}
        local_keys = {str(row["peer_public_key"]) for row in local_rows}
        snapshots: list[ReconciliationSnapshot] = []

        for row in local_rows:
            key = str(row["peer_public_key"])
            remote = remote_by_key.get(key)
            evidence = [_local_evidence(row, observation_time)]
            if remote is not None:
                evidence.append(_remote_evidence(remote, observation_time))
            snapshots.append(
                classify_reconciliation(
                    subject_id=f"device:{int(row['id'])}",
                    desired=_desired_from_row(row),
                    observed=_observed_from_remote(remote),
                    observed_at=observation_time,
                    now=current_time,
                    stale_after=self._stale_after,
                    evidence=tuple(evidence),
                )
            )

        for remote in remote_peers:
            if remote.peer_public_key in local_keys:
                continue
            snapshots.append(
                classify_reconciliation(
                    subject_id=f"remote:{_fingerprint(remote.peer_public_key)}",
                    desired=DesiredPeerState(
                        peer_expected=False,
                        peer_public_key=None,
                        allowed_ips=(),
                        device_status=None,
                    ),
                    observed=_observed_from_remote(remote),
                    observed_at=observation_time,
                    now=current_time,
                    stale_after=self._stale_after,
                    evidence=(_remote_evidence(remote, observation_time),),
                )
            )

        return tuple(sorted(snapshots, key=lambda item: item.subject_id))


def classify_reconciliation(
    *,
    subject_id: str,
    desired: DesiredPeerState,
    observed: ObservedPeerState,
    observed_at: datetime,
    now: datetime,
    stale_after: timedelta,
    evidence: tuple[ReconciliationEvidence, ...] = (),
) -> ReconciliationSnapshot:
    observation_time = _as_utc(observed_at)
    current_time = _as_utc(now)

    if not observed.observation_succeeded:
        drift_state: DriftState = "observation_failed"
        reason = "remote_observation_failed"
        action: RecommendedAction = "inspect_observation_failure"
    elif current_time - observation_time > stale_after:
        drift_state = "stale_observation"
        reason = "remote_observation_is_older_than_policy"
        action = "collect_fresh_observation"
    elif (
        desired.protocol_version is not None
        and observed.protocol_version is not None
        and desired.protocol_version != observed.protocol_version
    ):
        drift_state = "unknown"
        reason = "protocol_version_mismatch"
        action = "manual_review"
    elif (
        desired.runtime_instance_id is not None
        and observed.runtime_instance_id is not None
        and desired.runtime_instance_id != observed.runtime_instance_id
    ):
        drift_state = "unknown"
        reason = "runtime_instance_mismatch"
        action = "manual_review"
    elif desired.peer_expected and desired.compatibility_status == "stale":
        drift_state = "unknown"
        reason = "compatibility_evidence_stale"
        action = "manual_review"
    elif (
        desired.peer_expected
        and desired.protocol_version is not None
        and desired.compatibility_evidence_id is None
    ):
        drift_state = "unknown"
        reason = "compatibility_evidence_missing"
        action = "manual_review"
    elif desired.peer_expected and desired.runtime_state not in {None, "accepted"}:
        drift_state = "unknown"
        reason = "runtime_not_accepted"
        action = "manual_review"
    elif desired.peer_expected is None or observed.peer_present is None:
        drift_state = "unknown"
        reason = "desired_or_observed_state_is_incomplete"
        action = "manual_review"
    elif desired.peer_expected and not observed.peer_present:
        drift_state = "missing_remote"
        reason = "desired_peer_is_absent_from_remote_inventory"
        action = "review_missing_remote_before_apply"
    elif not desired.peer_expected and observed.peer_present:
        drift_state = "unexpected_remote"
        reason = "remote_peer_has_no_desired_local_record"
        action = "review_unexpected_remote_before_apply"
    elif desired.peer_expected and observed.peer_present and not _states_match(
        desired,
        observed,
    ):
        drift_state = "unexpected_remote"
        reason = "remote_peer_does_not_match_desired_identity_or_allowed_ips"
        action = "review_unexpected_remote_before_apply"
    else:
        drift_state = "aligned"
        reason = "desired_and_observed_peer_state_match"
        action = "none"

    return ReconciliationSnapshot(
        subject_id=subject_id,
        desired_state=desired,
        observed_state=observed,
        drift_state=drift_state,
        drift_reason=reason,
        last_observed_at=observation_time,
        evidence=tuple(sorted(evidence)),
        recommended_next_action=action,
    )


def _desired_from_row(row) -> DesiredPeerState:
    return DesiredPeerState(
        peer_expected=True,
        peer_public_key=str(row["peer_public_key"]),
        allowed_ips=(f"{row['vpn_ip']}/32",),
        device_status=str(row["status"]),
        protocol_version=_optional_row_text(row, "protocol_version"),
        runtime_instance_id=_optional_row_text(row, "runtime_instance_id"),
        compatibility_evidence_id=_optional_row_text(
            row, "compatibility_evidence_id"
        ),
        compatibility_status=_optional_row_text(
            row, "client_identity_evidence_status"
        ),
        runtime_state=_optional_row_text(row, "runtime_state"),
    )


def _observed_from_remote(remote: RemotePeer | None) -> ObservedPeerState:
    if remote is None:
        return ObservedPeerState(
            peer_present=False,
            peer_public_key=None,
            allowed_ips=(),
            observation_succeeded=True,
        )
    return ObservedPeerState(
        peer_present=True,
        peer_public_key=remote.peer_public_key,
        allowed_ips=_normalize_allowed_ips(remote.allowed_ips),
        observation_succeeded=True,
    )


def _states_match(desired: DesiredPeerState, observed: ObservedPeerState) -> bool:
    return (
        desired.peer_public_key == observed.peer_public_key
        and tuple(sorted(desired.allowed_ips)) == tuple(sorted(observed.allowed_ips))
    )


def _normalize_allowed_ips(value: str) -> tuple[str, ...]:
    if value == "(none)":
        return ()
    return tuple(sorted(token.strip() for token in value.split(",") if token.strip()))


def _local_evidence(row, collected_at: datetime) -> ReconciliationEvidence:
    return ReconciliationEvidence(
        source="local_device_record",
        reference=f"device:{int(row['id'])}",
        collected_at=collected_at,
    )


def _remote_evidence(
    remote: RemotePeer,
    collected_at: datetime,
) -> ReconciliationEvidence:
    return ReconciliationEvidence(
        source="awg_peer_inventory",
        reference=f"peer:{_fingerprint(remote.peer_public_key)}",
        collected_at=collected_at,
    )


def _fingerprint(value: str | None) -> str | None:
    if value is None:
        return None
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _optional_row_text(row, key: str) -> str | None:
    value = row[key] if key in row.keys() else None
    return str(value) if value is not None else None


def _format_datetime(value: datetime) -> str:
    return _as_utc(value).isoformat().replace("+00:00", "Z")


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
