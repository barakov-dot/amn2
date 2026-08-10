from __future__ import annotations

import re
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from enum import StrEnum

from app.db.repositories import Repository
from app.services.client_compatibility import (
    ClientCompatibilityEvidence,
    ClientIdentity,
    CompatibilityAdmissionState,
    classify_awg3_compatibility,
    current_awg3_compatibility_evidence,
)


_RUNTIME_RECEIPT_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")


class ClientBuildState(StrEnum):
    CANDIDATE = "candidate"
    ACCEPTED = "accepted"
    SUPERSEDED = "superseded"
    COMPATIBILITY_REJECTED = "compatibility_rejected"
    SECURITY_REVOKED = "security_revoked"


@dataclass(frozen=True)
class Awg3ControlState:
    runtime_accepted: bool
    global_accepted: bool
    issuance_enabled: bool
    emergency_suspended: bool
    runtime_receipt: str | None

    @property
    def permits_new_issuance(self) -> bool:
        return (
            self.runtime_accepted
            and self.global_accepted
            and self.issuance_enabled
            and not self.emergency_suspended
        )


class Awg3ControlService:
    def __init__(
        self,
        repo: Repository,
        *,
        now: datetime,
        max_evidence_age: timedelta = timedelta(days=90),
    ) -> None:
        if not isinstance(now, datetime) or now.utcoffset() is None:
            raise ValueError("now")
        if max_evidence_age < timedelta(0):
            raise ValueError("max_evidence_age")
        self._repo = repo
        self._now = now
        self._max_evidence_age = max_evidence_age

    def accept_runtime(
        self,
        *,
        runtime_receipt: str,
        actor_id: int,
        reason: str,
    ) -> Awg3ControlState:
        self._validate_runtime_receipt(runtime_receipt)
        with self._repo.transaction():
            state = replace(
                self._state(),
                runtime_accepted=True,
                issuance_enabled=False,
                runtime_receipt=runtime_receipt,
            )
            return self._save(state, actor_id=actor_id, reason=reason)

    def accept_build(
        self,
        *,
        client: ClientIdentity,
        evidence: tuple[ClientCompatibilityEvidence, ...],
        actor_id: int,
        reason: str,
    ) -> ClientBuildState:
        if not isinstance(client, ClientIdentity) or client.build_id is None:
            raise ValueError("exact client build is required")
        compatibility = classify_awg3_compatibility(
            evidence,
            client=client,
            now=self._now,
            max_evidence_age=self._max_evidence_age,
        )
        current = current_awg3_compatibility_evidence(evidence, client=client)
        current_kinds = {item.source_kind for item in current}
        if (
            compatibility is CompatibilityAdmissionState.ACCEPTED
            and current_kinds == {"official_release", "local_import", "full_data"}
        ):
            state = ClientBuildState.ACCEPTED
        elif compatibility is CompatibilityAdmissionState.CANDIDATE:
            state = ClientBuildState.CANDIDATE
        else:
            state = ClientBuildState.COMPATIBILITY_REJECTED
        with self._repo.transaction():
            self._repo.upsert_client_build_acceptance(
                application=client.application,
                platform=client.platform,
                client_version=client.version,
                client_build=client.build_id,
                state=state.value,
                evidence_ids=tuple(item.evidence_id for item in current),
                actor_id=actor_id,
                reason=reason,
            )
            if state is ClientBuildState.ACCEPTED:
                control = replace(self._state(), global_accepted=True)
                self._save(control, actor_id=actor_id, reason=reason)
        return state

    def set_issuance_enabled(
        self,
        enabled: bool,
        *,
        accepted_build: ClientIdentity | None = None,
        actor_id: int,
        reason: str,
    ) -> Awg3ControlState:
        with self._repo.transaction():
            state = self._state()
            if enabled:
                if not state.runtime_accepted or not self._is_valid_receipt(
                    state.runtime_receipt
                ):
                    raise ValueError("runtime acceptance is required")
                if accepted_build is None or accepted_build.build_id is None:
                    raise ValueError("accepted exact build is required")
                build = self._repo.get_client_build_acceptance(
                    application=accepted_build.application,
                    platform=accepted_build.platform,
                    client_version=accepted_build.version,
                    client_build=accepted_build.build_id,
                )
                if (
                    build is None
                    or build["state"] != ClientBuildState.ACCEPTED.value
                ):
                    raise ValueError("accepted exact build is required")
                if not state.global_accepted:
                    raise ValueError("global acceptance is required")
                if state.emergency_suspended:
                    raise ValueError("runtime suspension must be cleared")
            return self._save(
                replace(state, issuance_enabled=enabled),
                actor_id=actor_id,
                reason=reason,
            )

    def emergency_suspend(
        self,
        *,
        actor_id: int,
        reason: str,
    ) -> Awg3ControlState:
        with self._repo.transaction():
            state = replace(
                self._state(),
                issuance_enabled=False,
                emergency_suspended=True,
            )
            return self._save(state, actor_id=actor_id, reason=reason)

    def resume_after_preflight(
        self,
        *,
        runtime_receipt: str,
        actor_id: int,
        reason: str,
    ) -> Awg3ControlState:
        self._validate_runtime_receipt(runtime_receipt)
        with self._repo.transaction():
            current = self._state()
            if runtime_receipt == current.runtime_receipt:
                raise ValueError("fresh runtime receipt is required")
            resumed = replace(
                current,
                runtime_accepted=True,
                issuance_enabled=False,
                emergency_suspended=False,
                runtime_receipt=runtime_receipt,
            )
            return self._save(resumed, actor_id=actor_id, reason=reason)

    def _state(self) -> Awg3ControlState:
        row = self._repo.get_awg3_control_state()
        return Awg3ControlState(
            runtime_accepted=bool(row["runtime_accepted"]),
            global_accepted=bool(row["global_accepted"]),
            issuance_enabled=bool(row["issuance_enabled"]),
            emergency_suspended=bool(row["emergency_suspended"]),
            runtime_receipt=row["runtime_receipt"],
        )

    def _save(
        self,
        state: Awg3ControlState,
        *,
        actor_id: int,
        reason: str,
    ) -> Awg3ControlState:
        self._repo.update_awg3_control_state(
            runtime_accepted=state.runtime_accepted,
            global_accepted=state.global_accepted,
            issuance_enabled=state.issuance_enabled,
            emergency_suspended=state.emergency_suspended,
            runtime_receipt=state.runtime_receipt,
            actor_id=actor_id,
            reason=reason,
        )
        return state

    @staticmethod
    def _is_valid_receipt(runtime_receipt: object) -> bool:
        return isinstance(runtime_receipt, str) and bool(
            _RUNTIME_RECEIPT_PATTERN.fullmatch(runtime_receipt)
        )

    @classmethod
    def _validate_runtime_receipt(cls, runtime_receipt: object) -> None:
        if not cls._is_valid_receipt(runtime_receipt):
            raise ValueError("valid runtime receipt is required")
