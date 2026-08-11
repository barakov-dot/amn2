from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from app.db.repositories import Repository
from app.vpn.protocol_versions import (
    ProtocolVersion,
    config_version_for_protocol,
    normalize_protocol_version,
)


ActorKind = Literal["user", "admin", "system"]


@dataclass(frozen=True)
class ProtocolProfile:
    profile_id: int
    passport_device_id: str
    protocol_version: ProtocolVersion
    local_device_id: int
    lifecycle_state: str
    replacement_device_id: int | None

    def safe_metadata(self) -> dict[str, object]:
        return {
            "profile_id": self.profile_id,
            "protocol_version": self.protocol_version.value,
            "local_device_id": self.local_device_id,
            "lifecycle_state": self.lifecycle_state,
            "replacement_device_id": self.replacement_device_id,
        }


class _ProfileChangedConcurrently(RuntimeError):
    pass


class DualProtocolProfileService:
    def __init__(self, repo: Repository) -> None:
        self._repo = repo

    def attach_active(
        self,
        passport_device_id: str,
        protocol_version: ProtocolVersion,
        local_device_id: int,
        *,
        actor_kind: ActorKind = "system",
        actor_id: int = 0,
        reason: str = "protocol profile attached",
    ) -> ProtocolProfile:
        protocol = normalize_protocol_version(protocol_version)
        with self._repo.transaction():
            self._validate_local_device(
                passport_device_id,
                local_device_id,
                protocol,
            )
            if self._repo.get_device_protocol_profile(
                passport_device_id=passport_device_id,
                protocol_version=protocol.value,
            ) is not None:
                raise ValueError(f"active {protocol.value} profile already exists")
            profile_id = self._repo.create_device_protocol_profile(
                passport_device_id=passport_device_id,
                protocol_version=protocol.value,
                local_device_id=local_device_id,
                lifecycle_state="active",
            )
            self._repo.append_protocol_config_event(
                event_type="protocol_profile_attached",
                actor_kind=actor_kind,
                actor_id=actor_id,
                reason=reason,
                passport_device_id=passport_device_id,
                protocol_version=protocol.value,
                local_device_id=local_device_id,
                metadata={
                    "profile_id": profile_id,
                    "lifecycle_state": "active",
                },
            )
        return self.get(profile_id)

    def get(self, profile_id: int) -> ProtocolProfile:
        return _profile_from_row(self._require_row(profile_id))

    def by_local_device_id(self, local_device_id: int) -> ProtocolProfile:
        current = self._repo.get_device_protocol_profile_by_local_device_id(
            local_device_id
        )
        if current is not None:
            return _profile_from_row(current)
        retirement = self._repo.get_latest_protocol_profile_retirement(
            local_device_id
        )
        if retirement is None:
            raise LookupError("protocol profile not found")
        metadata = json.loads(str(retirement["metadata_json"]))
        if metadata.get("lifecycle_state") != "revoked":
            raise LookupError("protocol profile retirement is invalid")
        return ProtocolProfile(
            profile_id=int(metadata["profile_id"]),
            passport_device_id=str(retirement["passport_device_id"]),
            protocol_version=ProtocolVersion(str(retirement["protocol_version"])),
            local_device_id=local_device_id,
            lifecycle_state="revoked",
            replacement_device_id=None,
        )

    def for_passport(self, passport_device_id: str) -> tuple[ProtocolProfile, ...]:
        profiles: list[ProtocolProfile] = []
        for protocol in ProtocolVersion:
            row = self._repo.get_device_protocol_profile(
                passport_device_id=passport_device_id,
                protocol_version=protocol.value,
            )
            if row is not None:
                profiles.append(_profile_from_row(row))
        return tuple(sorted(profiles, key=lambda item: item.protocol_version.value))

    def start_replacement(
        self,
        profile_id: int,
        *,
        replacement_device_id: int,
        actor_kind: ActorKind = "system",
        actor_id: int = 0,
        reason: str = "normal replacement requested",
    ) -> ProtocolProfile:
        with self._repo.transaction():
            row = self._require_row(profile_id)
            state = str(row["lifecycle_state"])
            if state == "pending_replacement":
                raise ValueError("replacement already pending")
            if state != "active":
                raise ValueError("only an active profile can be replaced")
            protocol = ProtocolVersion(str(row["protocol_version"]))
            self._validate_local_device(
                str(row["passport_device_id"]),
                replacement_device_id,
                protocol,
            )
            self._cas_transition(
                row,
                lifecycle_state="pending_replacement",
                local_device_id=int(row["local_device_id"]),
                replacement_device_id=replacement_device_id,
            )
            self._append_transition_event(
                row,
                event_type="protocol_profile_replacement_started",
                actor_kind=actor_kind,
                actor_id=actor_id,
                reason=reason,
                local_device_id=int(row["local_device_id"]),
                lifecycle_state="pending_replacement",
                replacement_device_id=replacement_device_id,
            )
        return self.get(profile_id)

    def activate_replacement(
        self,
        profile_id: int,
        *,
        actor_kind: ActorKind = "system",
        actor_id: int = 0,
        reason: str = "normal replacement activated",
    ) -> ProtocolProfile:
        with self._repo.transaction():
            row = self._require_row(profile_id)
            if str(row["lifecycle_state"]) != "pending_replacement":
                raise ValueError("profile has no pending replacement")
            replacement_device_id = _optional_int(row["replacement_device_id"])
            if replacement_device_id is None:
                raise ValueError("profile has no pending replacement")
            self._validate_local_device(
                str(row["passport_device_id"]),
                replacement_device_id,
                ProtocolVersion(str(row["protocol_version"])),
            )
            old_local_device_id = int(row["local_device_id"])
            self._cas_transition(
                row,
                lifecycle_state="active",
                local_device_id=replacement_device_id,
                replacement_device_id=None,
            )
            self._repo.append_protocol_config_event(
                event_type="protocol_profile_retired",
                actor_kind=actor_kind,
                actor_id=actor_id,
                reason=reason,
                passport_device_id=str(row["passport_device_id"]),
                protocol_version=str(row["protocol_version"]),
                local_device_id=old_local_device_id,
                metadata={
                    "profile_id": profile_id,
                    "lifecycle_state": "revoked",
                },
            )
        return self.get(profile_id)

    def compromise_reissue(
        self,
        profile_id: int,
        *,
        replacement_factory: Callable[[ProtocolVersion], object],
        actor_id: int,
        reason: str,
        actor_kind: ActorKind = "admin",
    ) -> ProtocolProfile:
        with self._repo.transaction():
            row = self._require_row(profile_id)
            old_profile = _profile_from_row(row)
            if old_profile.lifecycle_state == "revoked":
                raise ValueError("profile is already revoked")
            self._cas_transition(
                row,
                lifecycle_state="revoked",
                local_device_id=old_profile.local_device_id,
                replacement_device_id=None,
            )
            self._append_transition_event(
                row,
                event_type="compromise_reissue_revoked",
                actor_kind=actor_kind,
                actor_id=actor_id,
                reason=reason,
                local_device_id=old_profile.local_device_id,
                lifecycle_state="revoked",
                replacement_device_id=None,
            )

        revoked = self.get(profile_id)
        try:
            factory_result = replacement_factory(old_profile.protocol_version)
            replacement_device_id = _replacement_device_id(factory_result)
            with self._repo.transaction():
                row = self._require_row(profile_id)
                self._validate_local_device(
                    old_profile.passport_device_id,
                    replacement_device_id,
                    old_profile.protocol_version,
                )
                changed = self._repo.transition_device_protocol_profile(
                    profile_id=revoked.profile_id,
                    expected_lifecycle_state=revoked.lifecycle_state,
                    expected_local_device_id=revoked.local_device_id,
                    expected_replacement_device_id=(
                        revoked.replacement_device_id
                    ),
                    lifecycle_state="active",
                    local_device_id=replacement_device_id,
                    replacement_device_id=None,
                )
                if not changed:
                    raise _ProfileChangedConcurrently(
                        "protocol profile changed concurrently"
                    )
                self._append_transition_event(
                    row,
                    event_type="compromise_reissue_completed",
                    actor_kind=actor_kind,
                    actor_id=actor_id,
                    reason=reason,
                    local_device_id=replacement_device_id,
                    lifecycle_state="active",
                    replacement_device_id=None,
                )
            return self.get(profile_id)
        except _ProfileChangedConcurrently:
            raise
        except Exception:
            self._append_failure_event(
                actor_kind=actor_kind,
                actor_id=actor_id,
                reason=reason,
                profile=revoked,
            )
            raise

    def mark_review_required(
        self,
        profile_id: int,
        *,
        actor_id: int = 0,
        reason: str = "profile review required",
        actor_kind: ActorKind = "system",
    ) -> ProtocolProfile:
        return self._change_lifecycle(
            profile_id,
            lifecycle_state="review_required",
            event_type="protocol_profile_review_required",
            actor_kind=actor_kind,
            actor_id=actor_id,
            reason=reason,
        )

    def mark_temporarily_unavailable(
        self,
        profile_id: int,
        *,
        actor_id: int = 0,
        reason: str = "profile temporarily unavailable",
        actor_kind: ActorKind = "system",
    ) -> ProtocolProfile:
        return self._change_lifecycle(
            profile_id,
            lifecycle_state="temporarily_unavailable",
            event_type="protocol_profile_temporarily_unavailable",
            actor_kind=actor_kind,
            actor_id=actor_id,
            reason=reason,
        )

    def _change_lifecycle(
        self,
        profile_id: int,
        *,
        lifecycle_state: str,
        event_type: str,
        actor_kind: ActorKind,
        actor_id: int,
        reason: str,
    ) -> ProtocolProfile:
        with self._repo.transaction():
            row = self._require_row(profile_id)
            if str(row["lifecycle_state"]) == "revoked":
                raise ValueError("profile is revoked")
            local_device_id = int(row["local_device_id"])
            replacement_device_id = _optional_int(row["replacement_device_id"])
            self._cas_transition(
                row,
                lifecycle_state=lifecycle_state,
                local_device_id=local_device_id,
                replacement_device_id=replacement_device_id,
            )
            self._append_transition_event(
                row,
                event_type=event_type,
                actor_kind=actor_kind,
                actor_id=actor_id,
                reason=reason,
                local_device_id=local_device_id,
                lifecycle_state=lifecycle_state,
                replacement_device_id=replacement_device_id,
            )
        return self.get(profile_id)

    def _cas_transition(
        self,
        row,
        *,
        lifecycle_state: str,
        local_device_id: int,
        replacement_device_id: int | None,
    ) -> None:
        changed = self._repo.transition_device_protocol_profile(
            profile_id=int(row["id"]),
            expected_lifecycle_state=str(row["lifecycle_state"]),
            expected_local_device_id=int(row["local_device_id"]),
            expected_replacement_device_id=_optional_int(
                row["replacement_device_id"]
            ),
            lifecycle_state=lifecycle_state,
            local_device_id=local_device_id,
            replacement_device_id=replacement_device_id,
        )
        if not changed:
            raise _ProfileChangedConcurrently(
                "protocol profile changed concurrently"
            )

    def _append_transition_event(
        self,
        row,
        *,
        event_type: str,
        actor_kind: ActorKind,
        actor_id: int,
        reason: str,
        local_device_id: int,
        lifecycle_state: str,
        replacement_device_id: int | None,
    ) -> None:
        self._repo.append_protocol_config_event(
            event_type=event_type,
            actor_kind=actor_kind,
            actor_id=actor_id,
            reason=reason,
            passport_device_id=str(row["passport_device_id"]),
            protocol_version=str(row["protocol_version"]),
            local_device_id=local_device_id,
            metadata={
                "profile_id": int(row["id"]),
                "lifecycle_state": lifecycle_state,
                "replacement_device_id": replacement_device_id,
            },
        )

    def _append_failure_event(
        self,
        *,
        actor_kind: ActorKind,
        actor_id: int,
        reason: str,
        profile: ProtocolProfile,
    ) -> None:
        with self._repo.transaction():
            self._repo.append_protocol_config_event(
                event_type="compromise_reissue_failed",
                actor_kind=actor_kind,
                actor_id=actor_id,
                reason=reason,
                passport_device_id=profile.passport_device_id,
                protocol_version=profile.protocol_version.value,
                local_device_id=profile.local_device_id,
                metadata={
                    "profile_id": profile.profile_id,
                    "lifecycle_state": profile.lifecycle_state,
                },
            )

    def _require_row(self, profile_id: int):
        row = self._repo.get_device_protocol_profile_by_id(profile_id)
        if row is None:
            raise LookupError("protocol profile not found")
        return row

    def _validate_local_device(
        self,
        passport_device_id: str,
        local_device_id: int,
        protocol: ProtocolVersion,
    ) -> None:
        passport = self._repo.get_device_passport(passport_device_id)
        if passport is None:
            raise LookupError("device passport not found")
        device = self._repo.get_device(local_device_id)
        if int(device["user_id"]) != int(passport["owner_user_id"]):
            raise ValueError("local device does not belong to passport owner")
        stored_protocol = device["protocol_version"]
        if stored_protocol is not None:
            if str(stored_protocol) != protocol.value:
                raise ValueError("local device protocol does not match profile")
            return
        if str(device["config_version"]) != config_version_for_protocol(protocol):
            raise ValueError("local device protocol does not match profile")


def _profile_from_row(row) -> ProtocolProfile:
    return ProtocolProfile(
        profile_id=int(row["id"]),
        passport_device_id=str(row["passport_device_id"]),
        protocol_version=ProtocolVersion(str(row["protocol_version"])),
        local_device_id=int(row["local_device_id"]),
        lifecycle_state=str(row["lifecycle_state"]),
        replacement_device_id=_optional_int(row["replacement_device_id"]),
    )


def _optional_int(value: object) -> int | None:
    return int(value) if value is not None else None


def _replacement_device_id(factory_result: object) -> int:
    value = (
        factory_result
        if isinstance(factory_result, int) and not isinstance(factory_result, bool)
        else getattr(factory_result, "local_device_id", None)
    )
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError("replacement factory did not return a local device id")
    return value
