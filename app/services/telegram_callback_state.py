from __future__ import annotations

import hashlib
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from app.db.repositories import Repository


SELECTION_PURPOSE = "select_protocol"
SELECTION_TTL = timedelta(minutes=15)
CONFIRMATION_TTL = timedelta(minutes=5)
_CLAIM_TTL = timedelta(minutes=5)


@dataclass(frozen=True)
class TelegramSelectionState:
    handle_digest: str
    owner_user_id: int
    passport_device_id: str
    client_platform: str
    client_application: str
    client_version: str
    client_build: str
    request_fingerprint: str
    claim_id_digest: str


@dataclass(frozen=True)
class TelegramConfirmationState:
    token_digest: str
    selection_handle_digest: str
    owner_user_id: int
    passport_device_id: str
    client_platform: str
    client_application: str
    client_version: str
    client_build: str
    request_fingerprint: str
    claim_id_digest: str


@dataclass(frozen=True)
class TelegramExpiredSelectionState:
    owner_user_id: int
    passport_device_id: str
    client_platform: str
    client_application: str
    client_version: str
    client_build: str
    request_fingerprint: str


@dataclass(frozen=True)
class TelegramExpiredConfirmationState:
    owner_user_id: int
    passport_device_id: str
    client_platform: str
    client_application: str
    client_version: str
    client_build: str
    request_fingerprint: str


class TelegramCallbackStateService:
    def __init__(
        self,
        *,
        repo: Repository,
        now: Callable[[], datetime] | None = None,
        selection_ttl: timedelta = SELECTION_TTL,
        confirmation_ttl: timedelta = CONFIRMATION_TTL,
        opaque_factory: Callable[[], str] | None = None,
        confirmation_factory: Callable[[], str] | None = None,
        claim_factory: Callable[[], str] | None = None,
    ) -> None:
        if selection_ttl <= timedelta(0):
            raise ValueError("selection_ttl")
        if confirmation_ttl <= timedelta(0):
            raise ValueError("confirmation_ttl")
        self._repo = repo
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._selection_ttl = selection_ttl
        self._confirmation_ttl = confirmation_ttl
        self._opaque_factory = opaque_factory or (lambda: secrets.token_urlsafe(16))
        self._confirmation_factory = confirmation_factory or self._opaque_factory
        self._claim_factory = claim_factory or (lambda: secrets.token_urlsafe(16))

    def create_selection(
        self,
        *,
        owner_user_id: int,
        passport_device_id: str,
        client_platform: str,
        client_application: str,
        client_version: str,
        client_build: str | None,
        request_fingerprint: str,
    ) -> str:
        if not client_build:
            raise ValueError("client_build")
        handle = self._new_opaque(self._opaque_factory, "selection handle")
        now = self._utc_now()
        self._repo.prune_expired_phase15_callback_state(_timestamp(now))
        self._repo.create_callback_handle(
            handle_digest=_digest(handle),
            purpose=SELECTION_PURPOSE,
            owner_user_id=owner_user_id,
            passport_device_id=passport_device_id,
            client_platform=client_platform,
            client_application=client_application,
            client_version=client_version,
            client_build=client_build,
            request_fingerprint=request_fingerprint,
            created_at=_timestamp(now),
            expires_at=_timestamp(now + self._selection_ttl),
        )
        return handle

    def claim_selection(
        self, handle: str, *, owner_user_id: int
    ) -> TelegramSelectionState | None:
        if not _is_opaque(handle):
            return None
        now = self._utc_now()
        claim_id_digest = self._new_claim_digest()
        row = self._repo.claim_callback_handle(
            _digest(handle),
            owner_user_id,
            _timestamp(now),
            claim_id_digest=claim_id_digest,
            claim_expires_at=_timestamp(now + _CLAIM_TTL),
        )
        if row is None:
            return None
        state = _selection_state(row, claim_id_digest)
        if str(row["purpose"]) != SELECTION_PURPOSE:
            if not self.consume_selection(
                state, terminal_reason="invalid_purpose"
            ):
                raise RuntimeError("invalid-purpose selection was not consumed")
            return None
        return state

    def consume_expired_selection(
        self, handle: str, *, owner_user_id: int
    ) -> TelegramExpiredSelectionState | None:
        if not _is_opaque(handle):
            return None
        row = self._repo.consume_expired_callback_handle(
            _digest(handle),
            owner_user_id,
            _timestamp(self._utc_now()),
            expected_purpose=SELECTION_PURPOSE,
        )
        return None if row is None else _expired_selection_state(row)

    def release_selection(self, state: TelegramSelectionState) -> bool:
        return (
            self._repo.release_callback_handle_claim(
                state.handle_digest,
                state.owner_user_id,
                _timestamp(self._utc_now()),
                claim_id_digest=state.claim_id_digest,
            )
            is not None
        )

    def consume_selection(
        self, state: TelegramSelectionState, *, terminal_reason: str
    ) -> bool:
        return (
            self._repo.consume_callback_handle(
                state.handle_digest,
                state.owner_user_id,
                _timestamp(self._utc_now()),
                terminal_reason,
                claim_id_digest=state.claim_id_digest,
            )
            is not None
        )

    def create_confirmation(self, selection: TelegramSelectionState) -> str:
        token = self._new_opaque(self._confirmation_factory, "confirmation token")
        now = self._utc_now()
        self._repo.create_issuance_confirmation(
            token_digest=_digest(token),
            selection_handle_digest=selection.handle_digest,
            owner_user_id=selection.owner_user_id,
            passport_device_id=selection.passport_device_id,
            client_platform=selection.client_platform,
            client_application=selection.client_application,
            client_version=selection.client_version,
            client_build=selection.client_build,
            request_fingerprint=selection.request_fingerprint,
            created_at=_timestamp(now),
            expires_at=_timestamp(now + self._confirmation_ttl),
        )
        return token

    def claim_confirmation(
        self, token: str, *, owner_user_id: int
    ) -> TelegramConfirmationState | None:
        if not _is_opaque(token):
            return None
        now = self._utc_now()
        claim_id_digest = self._new_claim_digest()
        row = self._repo.claim_issuance_confirmation(
            _digest(token),
            owner_user_id,
            _timestamp(now),
            claim_id_digest=claim_id_digest,
            claim_expires_at=_timestamp(now + _CLAIM_TTL),
        )
        return (
            None
            if row is None
            else _confirmation_state(row, claim_id_digest)
        )

    def consume_expired_confirmation(
        self, token: str, *, owner_user_id: int
    ) -> TelegramExpiredConfirmationState | None:
        if not _is_opaque(token):
            return None
        row = self._repo.consume_expired_issuance_confirmation(
            _digest(token),
            owner_user_id,
            _timestamp(self._utc_now()),
        )
        return None if row is None else _expired_confirmation_state(row)

    def release_confirmation(self, state: TelegramConfirmationState) -> bool:
        return (
            self._repo.release_issuance_confirmation_claim(
                state.token_digest,
                state.owner_user_id,
                _timestamp(self._utc_now()),
                claim_id_digest=state.claim_id_digest,
            )
            is not None
        )

    def consume_confirmation(
        self, state: TelegramConfirmationState, *, terminal_reason: str
    ) -> bool:
        return (
            self._repo.consume_issuance_confirmation(
                state.token_digest,
                state.owner_user_id,
                _timestamp(self._utc_now()),
                terminal_reason,
                claim_id_digest=state.claim_id_digest,
            )
            is not None
        )

    def _new_claim_digest(self) -> str:
        return _digest(self._new_opaque(self._claim_factory, "claim id"))

    def _utc_now(self) -> datetime:
        value = self._now()
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise ValueError("now must return a timezone-aware datetime")
        return value.astimezone(timezone.utc)

    @staticmethod
    def _new_opaque(factory: Callable[[], str], label: str) -> str:
        value = factory()
        if not _is_opaque(value):
            raise ValueError(f"{label} factory returned an invalid value")
        return value


def _selection_state(
    row: Mapping[str, object], claim_id_digest: str
) -> TelegramSelectionState:
    values = tuple(
        str(row[field])
        for field in (
            "client_platform",
            "client_application",
            "client_version",
            "client_build",
        )
    )
    return TelegramSelectionState(
        handle_digest=str(row["handle_digest"]),
        owner_user_id=int(row["owner_user_id"]),
        passport_device_id=str(row["passport_device_id"]),
        client_platform=values[0],
        client_application=values[1],
        client_version=values[2],
        client_build=values[3],
        request_fingerprint=str(row["request_fingerprint"]),
        claim_id_digest=claim_id_digest,
    )


def _confirmation_state(
    row: Mapping[str, object], claim_id_digest: str
) -> TelegramConfirmationState:
    return TelegramConfirmationState(
        token_digest=str(row["token_digest"]),
        selection_handle_digest=str(row["selection_handle_digest"]),
        owner_user_id=int(row["owner_user_id"]),
        passport_device_id=str(row["passport_device_id"]),
        client_platform=str(row["client_platform"]),
        client_application=str(row["client_application"]),
        client_version=str(row["client_version"]),
        client_build=str(row["client_build"]),
        request_fingerprint=str(row["request_fingerprint"]),
        claim_id_digest=claim_id_digest,
    )


def _expired_selection_state(
    row: Mapping[str, object],
) -> TelegramExpiredSelectionState:
    return TelegramExpiredSelectionState(
        owner_user_id=int(row["owner_user_id"]),
        passport_device_id=str(row["passport_device_id"]),
        client_platform=str(row["client_platform"]),
        client_application=str(row["client_application"]),
        client_version=str(row["client_version"]),
        client_build=str(row["client_build"]),
        request_fingerprint=str(row["request_fingerprint"]),
    )


def _expired_confirmation_state(
    row: Mapping[str, object],
) -> TelegramExpiredConfirmationState:
    return TelegramExpiredConfirmationState(
        owner_user_id=int(row["owner_user_id"]),
        passport_device_id=str(row["passport_device_id"]),
        client_platform=str(row["client_platform"]),
        client_application=str(row["client_application"]),
        client_version=str(row["client_version"]),
        client_build=str(row["client_build"]),
        request_fingerprint=str(row["request_fingerprint"]),
    )


def _is_opaque(value: object) -> bool:
    return isinstance(value, str) and 22 <= len(value) <= 60 and all(
        character.isascii() and (character.isalnum() or character in "-_")
        for character in value
    )


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()
