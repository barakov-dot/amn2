from __future__ import annotations

from collections.abc import Callable, Iterator
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


class DualProtocolProfileService:
    def __init__(self, repo: Repository) -> None:
        self._repo = repo
        self._known_profiles: dict[int, tuple[str, ProtocolVersion]] = {}
        self._retired_profiles: dict[int, ProtocolProfile] = {}

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
        self._repo.get_device_passport(passport_device_id)
        self._validate_local_device_protocol(local_device_id, protocol)
        if self._repo.get_device_protocol_profile(
            passport_device_id=passport_device_id,
            protocol_version=protocol.value,
        ) is not None:
            raise ValueError(f"active {protocol.value} profile already exists")

        with self._repo.transaction():
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
        self._known_profiles[profile_id] = (passport_device_id, protocol)
        return self.get(profile_id)

    def get(self, profile_id: int) -> ProtocolProfile:
        return _profile_from_row(self._row_for_id(profile_id))

    def by_local_device_id(self, local_device_id: int) -> ProtocolProfile:
        retired = self._retired_profiles.get(local_device_id)
        if retired is not None:
            return retired
        for row in self._iter_rows():
            raw_local_device_id = int(row["local_device_id"])
            replacement_device_id = _optional_int(row["replacement_device_id"])
            lifecycle_state = str(row["lifecycle_state"])
            if (
                raw_local_device_id == local_device_id
                and replacement_device_id is not None
                and lifecycle_state != "pending_replacement"
            ):
                return ProtocolProfile(
                    profile_id=int(row["id"]),
                    passport_device_id=str(row["passport_device_id"]),
                    protocol_version=ProtocolVersion(str(row["protocol_version"])),
                    local_device_id=raw_local_device_id,
                    lifecycle_state="revoked",
                    replacement_device_id=None,
                )
            profile = _profile_from_row(row)
            if profile.local_device_id == local_device_id:
                return profile
        raise LookupError("protocol profile not found")

    def for_passport(self, passport_device_id: str) -> tuple[ProtocolProfile, ...]:
        profiles: list[ProtocolProfile] = []
        for protocol in ProtocolVersion:
            row = self._repo.get_device_protocol_profile(
                passport_device_id=passport_device_id,
                protocol_version=protocol.value,
            )
            if row is not None:
                profile = _profile_from_row(row)
                self._known_profiles[profile.profile_id] = (
                    passport_device_id,
                    protocol,
                )
                profiles.append(profile)
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
        row = self._row_for_id(profile_id)
        if str(row["lifecycle_state"]) == "pending_replacement":
            raise ValueError("replacement already pending")
        if str(row["lifecycle_state"]) != "active":
            raise ValueError("only an active profile can be replaced")
        protocol = ProtocolVersion(str(row["protocol_version"]))
        self._validate_local_device_protocol(replacement_device_id, protocol)
        return self._transition(
            row,
            lifecycle_state="pending_replacement",
            replacement_device_id=replacement_device_id,
            event_type="protocol_profile_replacement_started",
            actor_kind=actor_kind,
            actor_id=actor_id,
            reason=reason,
            event_local_device_id=int(row["local_device_id"]),
        )

    def activate_replacement(
        self,
        profile_id: int,
        *,
        actor_kind: ActorKind = "system",
        actor_id: int = 0,
        reason: str = "normal replacement activated",
    ) -> ProtocolProfile:
        row = self._row_for_id(profile_id)
        if str(row["lifecycle_state"]) != "pending_replacement":
            raise ValueError("profile has no pending replacement")
        replacement_device_id = _optional_int(row["replacement_device_id"])
        if replacement_device_id is None:
            raise ValueError("profile has no pending replacement")
        old_profile = _profile_from_row(row)
        self._retired_profiles[old_profile.local_device_id] = ProtocolProfile(
            profile_id=old_profile.profile_id,
            passport_device_id=old_profile.passport_device_id,
            protocol_version=old_profile.protocol_version,
            local_device_id=old_profile.local_device_id,
            lifecycle_state="revoked",
            replacement_device_id=None,
        )
        return self._transition(
            row,
            lifecycle_state="active",
            replacement_device_id=replacement_device_id,
            event_type="protocol_profile_replacement_activated",
            actor_kind=actor_kind,
            actor_id=actor_id,
            reason=reason,
            event_local_device_id=replacement_device_id,
        )

    def compromise_reissue(
        self,
        profile_id: int,
        *,
        replacement_factory: Callable[[ProtocolVersion], object],
        actor_id: int,
        reason: str,
        actor_kind: ActorKind = "admin",
    ) -> ProtocolProfile:
        row = self._row_for_id(profile_id)
        old_profile = _profile_from_row(row)
        if old_profile.lifecycle_state == "revoked":
            raise ValueError("profile is already revoked")
        retained_replacement_id = (
            _optional_int(row["replacement_device_id"])
            if str(row["lifecycle_state"]) != "pending_replacement"
            else None
        )
        revoked = self._transition(
            row,
            lifecycle_state="revoked",
            replacement_device_id=retained_replacement_id,
            event_type="compromise_reissue_revoked",
            actor_kind=actor_kind,
            actor_id=actor_id,
            reason=reason,
            event_local_device_id=old_profile.local_device_id,
        )
        self._retired_profiles[old_profile.local_device_id] = revoked

        try:
            factory_result = replacement_factory(old_profile.protocol_version)
            replacement_device_id = _replacement_device_id(factory_result)
            self._validate_local_device_protocol(
                replacement_device_id,
                old_profile.protocol_version,
            )
            current_row = self._row_for_id(profile_id)
            return self._transition(
                current_row,
                lifecycle_state="active",
                replacement_device_id=replacement_device_id,
                event_type="compromise_reissue_completed",
                actor_kind=actor_kind,
                actor_id=actor_id,
                reason=reason,
                event_local_device_id=replacement_device_id,
            )
        except Exception:
            self._append_event(
                event_type="compromise_reissue_failed",
                actor_kind=actor_kind,
                actor_id=actor_id,
                reason=reason,
                profile=revoked,
                local_device_id=old_profile.local_device_id,
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
        row = self._row_for_id(profile_id)
        if str(row["lifecycle_state"]) == "revoked":
            raise ValueError("profile is revoked")
        return self._transition(
            row,
            lifecycle_state="review_required",
            replacement_device_id=_optional_int(row["replacement_device_id"]),
            event_type="protocol_profile_review_required",
            actor_kind=actor_kind,
            actor_id=actor_id,
            reason=reason,
            event_local_device_id=_profile_from_row(row).local_device_id,
        )

    def mark_temporarily_unavailable(
        self,
        profile_id: int,
        *,
        actor_id: int = 0,
        reason: str = "profile temporarily unavailable",
        actor_kind: ActorKind = "system",
    ) -> ProtocolProfile:
        row = self._row_for_id(profile_id)
        if str(row["lifecycle_state"]) == "revoked":
            raise ValueError("profile is revoked")
        return self._transition(
            row,
            lifecycle_state="temporarily_unavailable",
            replacement_device_id=_optional_int(row["replacement_device_id"]),
            event_type="protocol_profile_temporarily_unavailable",
            actor_kind=actor_kind,
            actor_id=actor_id,
            reason=reason,
            event_local_device_id=_profile_from_row(row).local_device_id,
        )

    def _transition(
        self,
        row,
        *,
        lifecycle_state: str,
        replacement_device_id: int | None,
        event_type: str,
        actor_kind: ActorKind,
        actor_id: int,
        reason: str,
        event_local_device_id: int,
    ) -> ProtocolProfile:
        profile_id = int(row["id"])
        with self._repo.transaction():
            self._repo.update_device_protocol_profile(
                profile_id=profile_id,
                lifecycle_state=lifecycle_state,
                replacement_device_id=replacement_device_id,
            )
            self._repo.append_protocol_config_event(
                event_type=event_type,
                actor_kind=actor_kind,
                actor_id=actor_id,
                reason=reason,
                passport_device_id=str(row["passport_device_id"]),
                protocol_version=str(row["protocol_version"]),
                local_device_id=event_local_device_id,
                metadata={
                    "profile_id": profile_id,
                    "lifecycle_state": lifecycle_state,
                    "replacement_device_id": replacement_device_id,
                },
            )
        return self.get(profile_id)

    def _append_event(
        self,
        *,
        event_type: str,
        actor_kind: ActorKind,
        actor_id: int,
        reason: str,
        profile: ProtocolProfile,
        local_device_id: int,
    ) -> None:
        with self._repo.transaction():
            self._repo.append_protocol_config_event(
                event_type=event_type,
                actor_kind=actor_kind,
                actor_id=actor_id,
                reason=reason,
                passport_device_id=profile.passport_device_id,
                protocol_version=profile.protocol_version.value,
                local_device_id=local_device_id,
                metadata={
                    "profile_id": profile.profile_id,
                    "lifecycle_state": profile.lifecycle_state,
                },
            )

    def _row_for_id(self, profile_id: int):
        known = self._known_profiles.get(profile_id)
        if known is not None:
            row = self._repo.get_device_protocol_profile(
                passport_device_id=known[0],
                protocol_version=known[1].value,
            )
            if row is not None and int(row["id"]) == profile_id:
                return row
        for row in self._iter_rows():
            if int(row["id"]) == profile_id:
                self._known_profiles[profile_id] = (
                    str(row["passport_device_id"]),
                    ProtocolVersion(str(row["protocol_version"])),
                )
                return row
        raise LookupError("protocol profile not found")

    def _iter_rows(self) -> Iterator[object]:
        for passport in self._repo.list_device_passports(limit=100):
            passport_device_id = str(passport["device_id"])
            for protocol in ProtocolVersion:
                row = self._repo.get_device_protocol_profile(
                    passport_device_id=passport_device_id,
                    protocol_version=protocol.value,
                )
                if row is not None:
                    yield row

    def _validate_local_device_protocol(
        self,
        local_device_id: int,
        protocol: ProtocolVersion,
    ) -> None:
        device = self._repo.get_device(local_device_id)
        stored_protocol = device["protocol_version"]
        if stored_protocol is not None:
            if str(stored_protocol) != protocol.value:
                raise ValueError("local device protocol does not match profile")
            return
        if str(device["config_version"]) != config_version_for_protocol(protocol):
            raise ValueError("local device protocol does not match profile")


def _profile_from_row(row) -> ProtocolProfile:
    lifecycle_state = str(row["lifecycle_state"])
    raw_local_device_id = int(row["local_device_id"])
    stored_replacement_id = _optional_int(row["replacement_device_id"])
    replacement_is_effective = (
        stored_replacement_id is not None
        and lifecycle_state != "pending_replacement"
    )
    return ProtocolProfile(
        profile_id=int(row["id"]),
        passport_device_id=str(row["passport_device_id"]),
        protocol_version=ProtocolVersion(str(row["protocol_version"])),
        local_device_id=(
            stored_replacement_id
            if replacement_is_effective
            else raw_local_device_id
        ),
        lifecycle_state=lifecycle_state,
        replacement_device_id=(
            stored_replacement_id
            if lifecycle_state == "pending_replacement"
            else None
        ),
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
