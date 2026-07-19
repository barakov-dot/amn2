from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Literal

from app.db.repositories import Repository


LifecycleStage = Literal[
    "issued",
    "claimed",
    "config_ready",
    "delivered",
    "acceptance_verified",
]
LifecycleStatus = Literal["completed", "failed"]

LIFECYCLE_STAGES: tuple[LifecycleStage, ...] = (
    "issued",
    "claimed",
    "config_ready",
    "delivered",
    "acceptance_verified",
)
MAX_SAFE_DURATION = timedelta(days=30)


@dataclass(frozen=True)
class LifecycleEvidence:
    source: str
    reference: str

    def safe_metadata(self) -> dict[str, str]:
        return {"source": self.source, "reference": self.reference}


@dataclass(frozen=True)
class DeviceLifecycleEvent:
    event_id: int
    ticket_id: str | None
    passport_device_id: str | None
    stage: LifecycleStage
    status: LifecycleStatus
    occurred_at: datetime
    duration_ms: int
    failure_stage: LifecycleStage | None
    evidence: LifecycleEvidence

    def safe_metadata(self) -> dict[str, object]:
        return {
            "event_id": self.event_id,
            "ticket_id": self.ticket_id,
            "passport_device_id": self.passport_device_id,
            "stage": self.stage,
            "status": self.status,
            "occurred_at": _format_datetime(self.occurred_at),
            "duration_ms": self.duration_ms,
            "failure_stage": self.failure_stage,
            "evidence": self.evidence.safe_metadata(),
        }


def record_device_lifecycle_stage(
    repo: Repository,
    *,
    stage: LifecycleStage,
    status: LifecycleStatus,
    occurred_at: datetime,
    started_at: datetime,
    evidence: LifecycleEvidence,
    ticket_id: str | None = None,
    passport_device_id: str | None = None,
) -> DeviceLifecycleEvent:
    if stage not in LIFECYCLE_STAGES:
        raise ValueError("unsupported device lifecycle stage")
    if status not in {"completed", "failed"}:
        raise ValueError("unsupported device lifecycle status")
    if ticket_id is None and passport_device_id is None:
        raise ValueError("ticket_id or passport_device_id is required")
    _validate_evidence(evidence)

    actual_occurred_at = _as_utc(occurred_at)
    actual_started_at = _as_utc(started_at)
    duration = actual_occurred_at - actual_started_at
    if duration < timedelta(0) or duration > MAX_SAFE_DURATION:
        raise ValueError("device lifecycle duration is outside the safe range")

    existing = list_device_lifecycle_events(
        repo,
        ticket_id=ticket_id,
        passport_device_id=passport_device_id,
    )
    if status == "completed":
        for event in existing:
            if event.stage == stage and event.status == "completed":
                return event
        stage_index = LIFECYCLE_STAGES.index(stage)
        if stage_index > 0:
            previous = LIFECYCLE_STAGES[stage_index - 1]
            operator_config_ready = (
                stage == "config_ready"
                and ticket_id is None
                and passport_device_id is not None
            )
            if not operator_config_ready and not any(
                event.stage == previous and event.status == "completed"
                for event in existing
            ):
                raise ValueError(f"lifecycle stage {stage} requires {previous}")

    event_id = repo.record_device_lifecycle_event(
        ticket_id=ticket_id,
        passport_device_id=passport_device_id,
        stage=stage,
        status=status,
        occurred_at=_format_datetime(actual_occurred_at),
        duration_ms=int(duration.total_seconds() * 1000),
        failure_stage=stage if status == "failed" else None,
        evidence=evidence.safe_metadata(),
    )
    return next(
        event
        for event in list_device_lifecycle_events(
            repo,
            ticket_id=ticket_id,
            passport_device_id=passport_device_id,
        )
        if event.event_id == event_id
    )


def list_device_lifecycle_events(
    repo: Repository,
    *,
    ticket_id: str | None = None,
    passport_device_id: str | None = None,
) -> tuple[DeviceLifecycleEvent, ...]:
    return tuple(
        _event_from_row(row)
        for row in repo.list_device_lifecycle_events(
            ticket_id=ticket_id,
            passport_device_id=passport_device_id,
        )
    )


def _event_from_row(row) -> DeviceLifecycleEvent:
    payload = json.loads(str(row["evidence_json"]))
    return DeviceLifecycleEvent(
        event_id=int(row["id"]),
        ticket_id=str(row["ticket_id"]) if row["ticket_id"] is not None else None,
        passport_device_id=(
            str(row["passport_device_id"])
            if row["passport_device_id"] is not None
            else None
        ),
        stage=str(row["stage"]),
        status=str(row["status"]),
        occurred_at=_parse_datetime(str(row["occurred_at"])),
        duration_ms=int(row["duration_ms"]),
        failure_stage=(
            str(row["failure_stage"]) if row["failure_stage"] is not None else None
        ),
        evidence=LifecycleEvidence(
            source=str(payload["source"]),
            reference=str(payload["reference"]),
        ),
    )


def _validate_evidence(evidence: LifecycleEvidence) -> None:
    for value in (evidence.source, evidence.reference):
        if not value.strip() or len(value) > 200:
            raise ValueError("lifecycle evidence value is invalid")
        if any(character in value for character in ("\r", "\n", "\t")):
            raise ValueError("lifecycle evidence must be one line")


def _parse_datetime(value: str) -> datetime:
    return _as_utc(datetime.fromisoformat(value.replace("Z", "+00:00")))


def _format_datetime(value: datetime) -> str:
    return _as_utc(value).isoformat().replace("+00:00", "Z")


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
