from __future__ import annotations

import json
from dataclasses import dataclass

from app.db.repositories import Repository
from app.server.operations import OperationPlan
from app.services.awg3_control import ClientBuildState
from app.services.client_compatibility import ClientIdentity
from app.services.device_revoke import build_protocol_config_revoke_plan
from app.services.dual_protocol_profiles import (
    DualProtocolProfileService,
    ProtocolProfile,
)
from app.vpn.protocol_versions import ProtocolVersion


BUILD_STATE_EFFECTS = {
    ClientBuildState.SUPERSEDED: ("continue", "offer_update"),
    ClientBuildState.COMPATIBILITY_REJECTED: (
        "review_required",
        "no_auto_revoke",
    ),
    ClientBuildState.SECURITY_REVOKED: (
        "continue",
        "emergency_proposal_required",
    ),
}

_PASSPORT_PAGE_SIZE = 100


@dataclass(frozen=True)
class ProtocolLifecycleTarget:
    profile_id: int
    passport_device_id: str
    protocol_version: ProtocolVersion
    local_device_id: int
    plan: OperationPlan

    def safe_metadata(self) -> dict[str, object]:
        return {
            "profile_id": self.profile_id,
            "passport_device_id": self.passport_device_id,
            "protocol_version": self.protocol_version.value,
            "local_device_id": self.local_device_id,
            "operation_plan": self.plan.to_safe_metadata(),
        }


@dataclass(frozen=True)
class BuildStateProjection:
    state: ClientBuildState
    new_issuance_allowed: bool
    existing_config_action: str
    operator_action: str
    configs_revoked: int
    emergency_proposal_required: bool
    affected_profiles: tuple[ProtocolProfile, ...]


class ProtocolConfigLifecycleService:
    def __init__(self, repo: Repository) -> None:
        self._repo = repo
        self._profiles = DualProtocolProfileService(repo)

    def disable_user(
        self,
        *,
        user_id: int,
        actor_id: int,
        reason: str,
    ) -> tuple[ProtocolLifecycleTarget, ...]:
        self._validate_actor_reason(actor_id, reason)
        self._repo.get_user(user_id)
        targets: list[ProtocolLifecycleTarget] = []
        for passport in self._passport_rows(owner_user_id=user_id):
            targets.extend(self._targets_for_passport(str(passport["device_id"])))
        return tuple(
            sorted(
                targets,
                key=lambda item: (
                    item.passport_device_id,
                    item.protocol_version.value,
                ),
            )
        )

    def disable_device(
        self,
        *,
        passport_device_id: str,
        actor_id: int,
        reason: str,
    ) -> tuple[ProtocolLifecycleTarget, ...]:
        self._validate_actor_reason(actor_id, reason)
        if self._repo.get_device_passport(passport_device_id) is None:
            raise LookupError("device passport not found")
        return self._targets_for_passport(passport_device_id)

    def revoke_config(
        self,
        *,
        local_device_id: int,
        actor_id: int,
        reason: str,
    ) -> tuple[ProtocolLifecycleTarget, ...]:
        self._validate_actor_reason(actor_id, reason)
        profile = self._profiles.by_local_device_id(local_device_id)
        return (self._target(profile),)

    def apply_build_state(
        self,
        build: ClientIdentity,
        state: str | ClientBuildState,
    ) -> BuildStateProjection:
        if not isinstance(build, ClientIdentity) or build.build_id is None:
            raise ValueError("exact client build is required")
        actual_state = ClientBuildState(state)
        if actual_state not in BUILD_STATE_EFFECTS:
            raise ValueError("build state has no lifecycle projection")
        current = self._repo.get_client_build_acceptance(
            application=build.application,
            platform=build.platform,
            client_version=build.version,
            client_build=build.build_id,
        )
        if current is None:
            raise LookupError("client build acceptance not found")
        evidence_ids = tuple(json.loads(str(current["evidence_ids_json"])))
        with self._repo.transaction():
            self._repo.upsert_client_build_acceptance(
                application=build.application,
                platform=build.platform,
                client_version=build.version,
                client_build=build.build_id,
                state=actual_state.value,
                evidence_ids=evidence_ids,
                actor_id=0,
                reason=f"lifecycle projection: {actual_state.value}",
            )
            affected = (
                self._project_review_required(build)
                if actual_state is ClientBuildState.COMPATIBILITY_REJECTED
                else ()
            )
        existing_action, operator_action = BUILD_STATE_EFFECTS[actual_state]
        return BuildStateProjection(
            state=actual_state,
            new_issuance_allowed=False,
            existing_config_action=existing_action,
            operator_action=operator_action,
            configs_revoked=0,
            emergency_proposal_required=(
                actual_state is ClientBuildState.SECURITY_REVOKED
            ),
            affected_profiles=affected,
        )

    def project_emergency_suspend(
        self,
        *,
        actor_id: int,
        reason: str,
    ) -> tuple[ProtocolProfile, ...]:
        self._validate_actor_reason(actor_id, reason)
        projected: list[ProtocolProfile] = []
        for passport in self._passport_rows():
            row = self._repo.get_device_protocol_profile(
                passport_device_id=str(passport["device_id"]),
                protocol_version=ProtocolVersion.AWG3.value,
            )
            if row is None or str(row["lifecycle_state"]) == "revoked":
                continue
            profile = self._profiles.get(int(row["id"]))
            if profile.lifecycle_state == "temporarily_unavailable":
                projected.append(profile)
                continue
            projected.append(
                self._profiles.mark_temporarily_unavailable(
                    profile.profile_id,
                    actor_id=actor_id,
                    reason=reason,
                    actor_kind="admin",
                )
            )
        return tuple(
            sorted(projected, key=lambda item: item.passport_device_id)
        )

    def profile(self, local_device_id: int) -> ProtocolProfile:
        return self._profiles.by_local_device_id(local_device_id)

    def _targets_for_passport(
        self, passport_device_id: str
    ) -> tuple[ProtocolLifecycleTarget, ...]:
        return tuple(
            self._target(profile)
            for profile in self._profiles.for_passport(passport_device_id)
            if profile.lifecycle_state != "revoked"
        )

    def _target(self, profile: ProtocolProfile) -> ProtocolLifecycleTarget:
        return ProtocolLifecycleTarget(
            profile_id=profile.profile_id,
            passport_device_id=profile.passport_device_id,
            protocol_version=profile.protocol_version,
            local_device_id=profile.local_device_id,
            plan=build_protocol_config_revoke_plan(
                self._repo,
                local_device_id=profile.local_device_id,
            ),
        )

    def _project_review_required(
        self, build: ClientIdentity
    ) -> tuple[ProtocolProfile, ...]:
        projected: list[ProtocolProfile] = []
        seen: set[int] = set()
        for passport in self._passport_rows():
            passport_device_id = str(passport["device_id"])
            for attempt in self._repo.list_protocol_issuance_attempts(
                passport_device_id=passport_device_id,
                protocol_version=ProtocolVersion.AWG3.value,
            ):
                if (
                    str(attempt["state"]) != "completed"
                    or str(attempt["client_application"]) != build.application
                    or str(attempt["client_platform"]) != build.platform
                    or str(attempt["client_version"]) != build.version
                    or str(attempt["client_build"]) != build.build_id
                ):
                    continue
                local_device_id = attempt["local_device_id"]
                if local_device_id is None:
                    continue
                profile = self._profiles.by_local_device_id(int(local_device_id))
                if profile.profile_id in seen or profile.lifecycle_state == "revoked":
                    continue
                seen.add(profile.profile_id)
                projected.append(
                    self._profiles.mark_review_required(
                        profile.profile_id,
                        reason="exact build compatibility rejected",
                    )
                )
        return tuple(projected)

    def _passport_rows(self, *, owner_user_id: int | None = None):
        offset = 0
        while True:
            if owner_user_id is None:
                rows = self._repo.list_device_passports(
                    limit=_PASSPORT_PAGE_SIZE,
                    offset=offset,
                )
            else:
                rows = self._repo.list_device_passports_for_owner(
                    owner_user_id,
                    limit=_PASSPORT_PAGE_SIZE,
                    offset=offset,
                )
            if not rows:
                return
            yield from rows
            offset += len(rows)

    @staticmethod
    def _validate_actor_reason(actor_id: int, reason: str) -> None:
        if isinstance(actor_id, bool) or not isinstance(actor_id, int) or actor_id < 0:
            raise ValueError("actor_id")
        normalized = " ".join(reason.split())
        if not normalized or len(normalized) > 200:
            raise ValueError("reason")
