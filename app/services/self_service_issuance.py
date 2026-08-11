from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Literal, Protocol

from app.db.repositories import Repository
from app.services.awg3_control import Awg3ControlService, Awg3ControlState
from app.services.client_compatibility import ClientIdentity
from app.services.dual_protocol_profiles import DualProtocolProfileService
from app.services.protocol_admission import (
    AdmissionRequest,
    AdmissionResult,
    ProtocolAdmissionService,
)
from app.vpn.protocol_versions import ProtocolVersion


_AWG3_COMPATIBILITY_BLOCKS = frozenset(
    {
        "candidate_awg3",
        "blocked_unknown_client",
        "blocked_unverified_version",
        "blocked_unsupported_platform",
        "blocked_evidence_stale_or_failed",
    }
)


@dataclass(frozen=True)
class SelfServiceIssuanceRequest:
    user_id: int
    telegram_id: int
    passport_device_id: str
    protocol_version: ProtocolVersion
    client: ClientIdentity

    def __post_init__(self) -> None:
        if isinstance(self.user_id, bool) or self.user_id <= 0:
            raise ValueError("user_id")
        if isinstance(self.telegram_id, bool) or self.telegram_id <= 0:
            raise ValueError("telegram_id")
        if not isinstance(self.passport_device_id, str) or not self.passport_device_id.strip():
            raise ValueError("passport_device_id")
        if not isinstance(self.protocol_version, ProtocolVersion):
            raise ValueError("protocol_version")
        if not isinstance(self.client, ClientIdentity):
            raise ValueError("client")


@dataclass(frozen=True)
class SelfServiceIssuanceResult:
    status: Literal["confirmation_required", "issued", "blocked"]
    protocol_version: ProtocolVersion
    reason_code: str
    offer_awg2: bool
    issued_device_id: int | None
    token: str | None


class ConfigIssuer(Protocol):
    def issue(
        self,
        *,
        request: SelfServiceIssuanceRequest,
        admission: AdmissionResult,
    ) -> object: ...


@dataclass(frozen=True)
class _PendingConfirmation:
    request_fingerprint: str
    expires_at: datetime


class SelfServiceIssuanceService:
    def __init__(
        self,
        *,
        repo: Repository,
        admission_service: ProtocolAdmissionService,
        control_service: Awg3ControlService,
        profile_service: DualProtocolProfileService,
        issuer: ConfigIssuer,
        now: Callable[[], datetime] | None = None,
        confirmation_ttl: timedelta = timedelta(minutes=5),
        token_factory: Callable[[], str] | None = None,
        bot_admin_telegram_id: int | None = None,
        pilot_user_id: int | None = None,
        pilot_passport_device_id: str | None = None,
        pilot_client: ClientIdentity | None = None,
    ) -> None:
        if confirmation_ttl <= timedelta(0):
            raise ValueError("confirmation_ttl")
        self._repo = repo
        self._admission = admission_service
        self._control = control_service
        self._profiles = profile_service
        self._issuer = issuer
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._confirmation_ttl = confirmation_ttl
        self._token_factory = token_factory or (lambda: secrets.token_urlsafe(24))
        self._bot_admin_telegram_id = bot_admin_telegram_id
        self._pilot_user_id = pilot_user_id
        self._pilot_passport_device_id = pilot_passport_device_id
        self._pilot_client = pilot_client
        self._pending: dict[str, _PendingConfirmation] = {}

    def decide(
        self, request: SelfServiceIssuanceRequest
    ) -> SelfServiceIssuanceResult:
        blocked, _admission = self._validate_standard(request)
        if blocked is not None:
            return blocked
        token = self._token_factory()
        if not isinstance(token, str) or not token:
            raise ValueError("confirmation token factory returned an invalid token")
        token_digest = _digest(token)
        self._pending[token_digest] = _PendingConfirmation(
            request_fingerprint=_request_fingerprint(request),
            expires_at=self._now() + self._confirmation_ttl,
        )
        return SelfServiceIssuanceResult(
            status="confirmation_required",
            protocol_version=request.protocol_version,
            reason_code="confirmation_required",
            offer_awg2=False,
            issued_device_id=None,
            token=token,
        )

    def issue_after_confirmation(
        self,
        request: SelfServiceIssuanceRequest,
        *,
        confirmation_token: str | None,
    ) -> SelfServiceIssuanceResult:
        pending, token_digest, invalid = self._validate_confirmation(
            request, confirmation_token
        )
        if invalid is not None:
            return invalid
        assert pending is not None and token_digest is not None
        blocked, admission = self._validate_standard(request)
        if blocked is not None:
            return blocked
        assert admission is not None
        consumed = self._pending.pop(token_digest, None)
        if consumed is not pending:
            return self._blocked(request, "invalid_confirmation")
        return self._issue(
            request,
            admission,
            event_type="self_service_issued",
            actor_kind="user",
            actor_id=request.telegram_id,
            reason_code="issued",
        )

    def issue_admin_pilot(
        self,
        *,
        admin_telegram_id: int,
        request: SelfServiceIssuanceRequest,
    ) -> SelfServiceIssuanceResult:
        if admin_telegram_id != self._bot_admin_telegram_id:
            return self._blocked(request, "admin_pilot_not_authorized")
        if (
            request.user_id != self._pilot_user_id
            or request.passport_device_id != self._pilot_passport_device_id
        ):
            return self._blocked(request, "pilot_identity_mismatch")
        if (
            request.protocol_version is not ProtocolVersion.AWG3
            or request.client.build_id is None
            or request.client != self._pilot_client
        ):
            return self._blocked(request, "pilot_build_mismatch")
        identity_block = self._validate_identity_and_profile(request)
        if identity_block is not None:
            if identity_block.reason_code == "profile_already_exists":
                raise ValueError("pilot profile already exists")
            return identity_block
        admission = self._admission.decide(
            AdmissionRequest(
                client=request.client,
                protocol_version=request.protocol_version,
            )
        )
        if (
            admission.decision != "candidate_awg3"
            or admission.runtime_instance_id is None
            or admission.compatibility_evidence_id is None
        ):
            return self._blocked(request, admission.decision)
        state = self._control._state()
        if not isinstance(state, Awg3ControlState) or state.emergency_suspended:
            return self._blocked(request, "blocked_runtime_suspended")
        return self._issue(
            request,
            admission,
            event_type="admin_pilot_issued",
            actor_kind="admin",
            actor_id=admin_telegram_id,
            reason_code="admin_pilot",
        )

    def _validate_standard(
        self, request: SelfServiceIssuanceRequest
    ) -> tuple[SelfServiceIssuanceResult | None, AdmissionResult | None]:
        identity_block = self._validate_identity_and_profile(request)
        if identity_block is not None:
            return identity_block, None
        admission = self._admission.decide(
            AdmissionRequest(
                client=request.client,
                protocol_version=request.protocol_version,
            )
        )
        if not admission.admitted:
            return self._blocked(request, admission.decision), None
        if request.protocol_version is ProtocolVersion.AWG3:
            gate_block = self._validate_live_awg3_gates(request)
            if gate_block is not None:
                return gate_block, None
        return None, admission

    def _validate_identity_and_profile(
        self, request: SelfServiceIssuanceRequest
    ) -> SelfServiceIssuanceResult | None:
        owner = self._repo.get_user_by_telegram_id(request.telegram_id)
        if owner is None or int(owner["id"]) != request.user_id:
            return self._blocked(request, "owner_mismatch")
        try:
            user = self._repo.get_user(request.user_id)
        except LookupError:
            return self._blocked(request, "user_not_found")
        if str(user["status"]) != "active":
            return self._blocked(request, "user_not_active")
        passport = self._repo.get_device_passport(request.passport_device_id)
        if passport is None:
            return self._blocked(request, "passport_not_found")
        if (
            int(passport["owner_user_id"]) != request.user_id
            or passport["revoked_at"] is not None
        ):
            return self._blocked(request, "passport_owner_mismatch")
        local_device_id = passport["local_device_id"]
        if local_device_id is None or self._repo.get_user_device(
            user_id=request.user_id,
            device_id=int(local_device_id),
        ) is None:
            return self._blocked(request, "device_owner_mismatch")
        if (
            str(passport["platform"]) != request.client.platform
            or str(passport["official_client_type"]) != request.client.application
        ):
            return self._blocked(request, "device_client_mismatch")
        profiles = self._profiles.for_passport(request.passport_device_id)
        if any(
            profile.protocol_version is request.protocol_version
            for profile in profiles
        ):
            return self._blocked(request, "profile_already_exists")
        return None

    def _validate_live_awg3_gates(
        self, request: SelfServiceIssuanceRequest
    ) -> SelfServiceIssuanceResult | None:
        state = self._control._state()
        if (
            not isinstance(state, Awg3ControlState)
            or not state.runtime_accepted
            or not state.global_accepted
            or not state.runtime_receipt
        ):
            return self._blocked(request, "blocked_global_acceptance")
        if not state.issuance_enabled:
            return self._blocked(request, "blocked_issuance_disabled")
        if state.emergency_suspended:
            return self._blocked(request, "blocked_runtime_suspended")
        return None

    def _validate_confirmation(
        self,
        request: SelfServiceIssuanceRequest,
        confirmation_token: str | None,
    ) -> tuple[
        _PendingConfirmation | None,
        str | None,
        SelfServiceIssuanceResult | None,
    ]:
        if not isinstance(confirmation_token, str) or not confirmation_token:
            return None, None, self._blocked(request, "invalid_confirmation")
        token_digest = _digest(confirmation_token)
        pending = self._pending.get(token_digest)
        if pending is None:
            return None, None, self._blocked(request, "invalid_confirmation")
        if not hmac.compare_digest(
            pending.request_fingerprint, _request_fingerprint(request)
        ):
            return None, None, self._blocked(request, "invalid_confirmation")
        if self._now() > pending.expires_at:
            self._pending.pop(token_digest, None)
            return None, None, self._blocked(request, "confirmation_expired")
        return pending, token_digest, None

    def _issue(
        self,
        request: SelfServiceIssuanceRequest,
        admission: AdmissionResult,
        *,
        event_type: str,
        actor_kind: str,
        actor_id: int,
        reason_code: str,
    ) -> SelfServiceIssuanceResult:
        issued = self._issuer.issue(request=request, admission=admission)
        local_device_id = getattr(
            issued, "local_device_id", getattr(issued, "device_id", None)
        )
        if (
            isinstance(local_device_id, bool)
            or not isinstance(local_device_id, int)
            or local_device_id <= 0
        ):
            raise ValueError("issuer did not return a local device id")
        with self._repo.transaction():
            profile = self._profiles.attach_active(
                request.passport_device_id,
                request.protocol_version,
                local_device_id,
                actor_kind=actor_kind,
                actor_id=actor_id,
                reason=reason_code,
            )
            self._repo.append_protocol_config_event(
                event_type=event_type,
                actor_kind=actor_kind,
                actor_id=actor_id,
                reason=reason_code,
                passport_device_id=request.passport_device_id,
                protocol_version=request.protocol_version.value,
                local_device_id=local_device_id,
                metadata={
                    "profile_id": profile.profile_id,
                    "client_application": request.client.application,
                    "client_platform": request.client.platform,
                    "client_version": request.client.version,
                    "client_build": request.client.build_id,
                },
            )
        return SelfServiceIssuanceResult(
            status="issued",
            protocol_version=request.protocol_version,
            reason_code=reason_code,
            offer_awg2=False,
            issued_device_id=local_device_id,
            token=None,
        )

    @staticmethod
    def _blocked(
        request: SelfServiceIssuanceRequest, reason_code: str
    ) -> SelfServiceIssuanceResult:
        return SelfServiceIssuanceResult(
            status="blocked",
            protocol_version=request.protocol_version,
            reason_code=reason_code,
            offer_awg2=(
                request.protocol_version is ProtocolVersion.AWG3
                and reason_code in _AWG3_COMPATIBILITY_BLOCKS
            ),
            issued_device_id=None,
            token=None,
        )


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _request_fingerprint(request: SelfServiceIssuanceRequest) -> str:
    canonical = json.dumps(
        {
            "user_id": request.user_id,
            "telegram_id": request.telegram_id,
            "passport_device_id": request.passport_device_id,
            "protocol_version": request.protocol_version.value,
            "client_application": request.client.application,
            "client_platform": request.client.platform,
            "client_version": request.client.version,
            "client_build": request.client.build_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return _digest(canonical)
