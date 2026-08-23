from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Literal, Protocol

from app.db.repositories import ProtocolIssuanceExecutionBlocked, Repository
from app.services.awg3_control import Awg3ControlState
from app.services.client_compatibility import ClientIdentity
from app.services.dual_protocol_profiles import DualProtocolProfileService
from app.services.protocol_admission import (
    AdmissionRequest,
    AdmissionResult,
)
from app.services.telegram_callback_state import (
    TelegramCallbackStateService,
    TelegramConfirmationState,
    TelegramExpiredConfirmationState,
    TelegramExpiredSelectionState,
    TelegramSelectionState,
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


class _RecoveryEnrichmentError(RuntimeError):
    pass


class _ConfirmationTerminalizationLost(RuntimeError):
    pass


class IssuerUnavailableBeforeSideEffect(RuntimeError):
    pass


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


class SelfServiceIssuanceService:
    def __init__(
        self,
        *,
        repo: Repository,
        admission_provider: Callable[
            [AdmissionRequest], tuple[AdmissionResult, Awg3ControlState | None]
        ],
        profile_service: DualProtocolProfileService,
        issuer: ConfigIssuer,
        now: Callable[[], datetime] | None = None,
        confirmation_ttl: timedelta = timedelta(minutes=5),
        token_factory: Callable[[], str] | None = None,
        callback_state: TelegramCallbackStateService | None = None,
        bot_admin_telegram_id: int | None = None,
        pilot_user_id: int | None = None,
        pilot_passport_device_id: str | None = None,
        pilot_client: ClientIdentity | None = None,
    ) -> None:
        if confirmation_ttl <= timedelta(0):
            raise ValueError("confirmation_ttl")
        if not callable(admission_provider):
            raise ValueError("admission_provider")
        self._repo = repo
        self._admission_provider = admission_provider
        self._profiles = profile_service
        self._issuer = issuer
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._callback_state = callback_state or TelegramCallbackStateService(
            repo=repo,
            now=self._now,
            confirmation_ttl=confirmation_ttl,
            confirmation_factory=token_factory,
        )
        self._bot_admin_telegram_id = bot_admin_telegram_id
        self._pilot_user_id = pilot_user_id
        self._pilot_passport_device_id = pilot_passport_device_id
        self._pilot_client = pilot_client

    def decide(
        self, request: SelfServiceIssuanceRequest
    ) -> SelfServiceIssuanceResult:
        blocked, _admission = self._validate_standard(request)
        if blocked is not None:
            return blocked
        handle = self._callback_state.create_selection(
            owner_user_id=request.user_id,
            passport_device_id=request.passport_device_id,
            client_platform=request.client.platform,
            client_application=request.client.application,
            client_version=request.client.version,
            client_build=request.client.build_id,
            request_fingerprint=request_fingerprint(request),
        )
        selection = self._callback_state.claim_selection(
            handle, owner_user_id=request.user_id
        )
        if selection is None:
            raise RuntimeError("new confirmation selection could not be claimed")
        return self._create_confirmation(request, selection)

    def decide_from_selection(
        self,
        *,
        owner_user_id: int,
        telegram_id: int,
        selection_handle: str,
    ) -> SelfServiceIssuanceResult | None:
        selection = self._callback_state.claim_selection(
            selection_handle, owner_user_id=owner_user_id
        )
        if selection is None:
            expired = self._callback_state.consume_expired_selection(
                selection_handle, owner_user_id=owner_user_id
            )
            if expired is None:
                return None
            expired_request = self._request_from_selection(
                expired, telegram_id=telegram_id
            )
            return (
                None
                if expired_request is None
                else self._blocked(expired_request, "selection_expired")
            )
        try:
            request = self._request_from_selection(selection, telegram_id=telegram_id)
            if request is None:
                if not self._callback_state.consume_selection(
                    selection, terminal_reason="invalid_selection"
                ):
                    raise RuntimeError("invalid selection was not consumed")
                return None
            blocked, _admission = self._validate_standard(request)
            if blocked is not None:
                return blocked if self._finish_selection(selection, blocked) else None
        except BaseException as exc:
            if not self._callback_state.release_selection(selection):
                raise RuntimeError("selection claim release failed") from exc
            raise
        return self._create_confirmation(request, selection)

    def _create_confirmation(
        self,
        request: SelfServiceIssuanceRequest,
        selection: TelegramSelectionState,
    ) -> SelfServiceIssuanceResult:
        try:
            token = self._callback_state.create_confirmation(selection)
        except BaseException as exc:
            if not self._callback_state.release_selection(selection):
                raise RuntimeError("selection claim release failed") from exc
            raise
        if not self._callback_state.consume_selection(
            selection, terminal_reason="confirmation_created"
        ):
            raise RuntimeError("confirmation selection was not consumed")
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
        request: SelfServiceIssuanceRequest | None = None,
        *,
        owner_user_id: int | None = None,
        confirmation_token: str | None,
    ) -> SelfServiceIssuanceResult | None:
        resolved_owner_id = request.user_id if request is not None else owner_user_id
        if resolved_owner_id is None:
            raise ValueError("owner_user_id")
        confirmation = self._callback_state.claim_confirmation(
            confirmation_token or "", owner_user_id=resolved_owner_id
        )
        if confirmation is None:
            expired = self._callback_state.consume_expired_confirmation(
                confirmation_token or "", owner_user_id=resolved_owner_id
            )
            if expired is None:
                return (
                    self._blocked(request, "invalid_confirmation")
                    if request is not None
                    else None
                )
            resolved_expired_request = request or self._request_from_confirmation(
                expired
            )
            if resolved_expired_request is None or not self._confirmation_matches_request(
                expired, resolved_expired_request
            ):
                return (
                    self._blocked(request, "invalid_confirmation")
                    if request is not None
                    else None
                )
            return self._blocked(resolved_expired_request, "confirmation_expired")
        try:
            resolved_request = request or self._request_from_confirmation(confirmation)
            if resolved_request is None or not self._confirmation_matches_request(
                confirmation, resolved_request
            ):
                consumed = self._callback_state.consume_confirmation(
                    confirmation, terminal_reason="invalid_confirmation"
                )
                return (
                    self._blocked(request, "invalid_confirmation")
                    if request is not None and consumed
                    else None
                )
            blocked, admission = self._validate_standard(resolved_request)
            if blocked is not None:
                return (
                    blocked
                    if self._finish_confirmation(confirmation, blocked)
                    else None
                )
            assert admission is not None
            if not self._callback_state.renew_confirmation(confirmation):
                expired = self._blocked(resolved_request, "confirmation_expired")
                return (
                    expired
                    if self._finish_confirmation(confirmation, expired)
                    else None
                )
            result = self._reserve_and_issue_serialized(
                resolved_request,
                admission,
                event_type="self_service_issued",
                actor_kind="user",
                actor_id=resolved_request.telegram_id,
                reason_code="issued",
                confirmation=confirmation,
            )
        except _ConfirmationTerminalizationLost:
            return None
        except BaseException as exc:
            if not self._callback_state.release_confirmation(confirmation):
                raise RuntimeError("confirmation claim release failed") from exc
            raise
        if result.status == "issued":
            return result
        return result if self._finish_confirmation(confirmation, result) else None

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
        admission, state = self._fresh_admission_view(request)
        if admission is None:
            return self._blocked(request, "admission_view_unavailable")
        if (
            admission.decision != "candidate_awg3"
            or admission.runtime_instance_id is None
            or admission.compatibility_evidence_id is None
        ):
            return self._blocked(request, admission.decision)
        if not isinstance(state, Awg3ControlState) or state.emergency_suspended:
            return self._blocked(request, "blocked_runtime_suspended")
        return self._reserve_and_issue_serialized(
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
        admission, state = self._fresh_admission_view(request)
        if admission is None:
            return self._blocked(request, "admission_view_unavailable"), None
        if not admission.admitted:
            return self._blocked(request, admission.decision), None
        if request.protocol_version is ProtocolVersion.AWG3:
            gate_block = self._validate_live_awg3_gates(request, state)
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
        if self._repo.get_protocol_issuance_user_barrier(request.user_id) is not None:
            return self._blocked(request, "user_issuance_blocked")
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
        self,
        request: SelfServiceIssuanceRequest,
        state: Awg3ControlState | None,
    ) -> SelfServiceIssuanceResult | None:
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

    def _fresh_admission_view(
        self, request: SelfServiceIssuanceRequest
    ) -> tuple[AdmissionResult | None, Awg3ControlState | None]:
        try:
            view = self._admission_provider(
                AdmissionRequest(
                    client=request.client,
                    protocol_version=request.protocol_version,
                )
            )
        except Exception:
            return None, None
        if not isinstance(view, tuple) or len(view) != 2:
            return None, None
        admission, state = view
        if not isinstance(admission, AdmissionResult):
            return None, None
        if state is not None and not isinstance(state, Awg3ControlState):
            return None, None
        return admission, state

    def _request_from_selection(
        self,
        selection: TelegramSelectionState | TelegramExpiredSelectionState,
        *,
        telegram_id: int,
    ) -> SelfServiceIssuanceRequest | None:
        try:
            user = self._repo.get_user(selection.owner_user_id)
            request = SelfServiceIssuanceRequest(
                user_id=selection.owner_user_id,
                telegram_id=telegram_id,
                passport_device_id=selection.passport_device_id,
                protocol_version=ProtocolVersion.AWG3,
                client=ClientIdentity(
                    selection.client_application,
                    selection.client_platform,
                    selection.client_version,
                    build_id=selection.client_build,
                ),
            )
        except (LookupError, ValueError):
            return None
        if int(user["telegram_id"]) != telegram_id:
            return None
        return (
            request
            if selection.request_fingerprint == request_fingerprint(request)
            else None
        )

    def _request_from_confirmation(
        self,
        confirmation: TelegramConfirmationState | TelegramExpiredConfirmationState,
    ) -> SelfServiceIssuanceRequest | None:
        try:
            user = self._repo.get_user(confirmation.owner_user_id)
            return SelfServiceIssuanceRequest(
                user_id=confirmation.owner_user_id,
                telegram_id=int(user["telegram_id"]),
                passport_device_id=confirmation.passport_device_id,
                protocol_version=ProtocolVersion.AWG3,
                client=ClientIdentity(
                    confirmation.client_application,
                    confirmation.client_platform,
                    confirmation.client_version,
                    build_id=confirmation.client_build,
                ),
            )
        except (LookupError, ValueError):
            return None

    @staticmethod
    def _confirmation_matches_request(
        confirmation: TelegramConfirmationState | TelegramExpiredConfirmationState,
        request: SelfServiceIssuanceRequest,
    ) -> bool:
        return (
            confirmation.owner_user_id == request.user_id
            and confirmation.passport_device_id == request.passport_device_id
            and confirmation.client_platform == request.client.platform
            and confirmation.client_application == request.client.application
            and confirmation.client_version == request.client.version
            and confirmation.client_build == request.client.build_id
            and confirmation.request_fingerprint == request_fingerprint(request)
        )

    def _finish_selection(
        self,
        selection: TelegramSelectionState,
        result: SelfServiceIssuanceResult,
    ) -> bool:
        if _is_terminal_callback_result(result):
            return self._callback_state.consume_selection(
                selection, terminal_reason=result.reason_code
            )
        return self._callback_state.release_selection(selection)

    def _finish_confirmation(
        self,
        confirmation: TelegramConfirmationState,
        result: SelfServiceIssuanceResult,
    ) -> bool:
        if result.status == "issued" or _is_terminal_callback_result(result):
            return self._callback_state.consume_confirmation(
                confirmation, terminal_reason=result.reason_code
            )
        return self._callback_state.release_confirmation(confirmation)

    def _reserve(
        self,
        request: SelfServiceIssuanceRequest,
        admission: AdmissionResult,
        *,
        actor_kind: str,
        actor_id: int,
    ):
        attempt = self._repo.reserve_protocol_issuance_attempt(
            owner_user_id=request.user_id,
            intended_passport_device_id=request.passport_device_id,
            passport_device_id=request.passport_device_id,
            protocol_version=request.protocol_version.value,
            request_fingerprint=request_fingerprint(request),
            actor_kind=actor_kind,
            actor_id=actor_id,
            client_application=request.client.application,
            client_platform=request.client.platform,
            client_version=request.client.version,
            client_build=request.client.build_id,
            runtime_instance_id=admission.runtime_instance_id,
            compatibility_evidence_id=admission.compatibility_evidence_id,
        )
        if attempt is not None:
            return attempt, None
        blocking = self._repo.get_blocking_protocol_issuance_attempt(
            intended_passport_device_id=request.passport_device_id,
            protocol_version=request.protocol_version.value,
        )
        if blocking is not None:
            reason_code = (
                "issuance_recovery_required"
                if str(blocking["state"]) == "recovery_required"
                else "issuance_in_progress"
            )
            return None, self._blocked(request, reason_code)
        if self._repo.get_device_protocol_profile(
            passport_device_id=request.passport_device_id,
            protocol_version=request.protocol_version.value,
        ) is not None:
            return None, self._blocked(request, "profile_already_exists")
        return None, self._blocked(request, "issuance_in_progress")

    def _reserve_and_issue_serialized(
        self,
        request: SelfServiceIssuanceRequest,
        admission: AdmissionResult,
        *,
        event_type: str,
        actor_kind: str,
        actor_id: int,
        reason_code: str,
        confirmation: TelegramConfirmationState | None = None,
    ) -> SelfServiceIssuanceResult:
        attempt, execution_lease, reservation_block = (
            self._prepare_execution_marker(
                request,
                admission,
                actor_kind=actor_kind,
                actor_id=actor_id,
                confirmation=confirmation,
            )
        )
        if reservation_block is not None:
            return reservation_block
        assert attempt is not None and execution_lease is not None
        failure: Exception | None = None
        result: SelfServiceIssuanceResult | None = None
        try:
            with self._repo.transaction():
                self._repo.bind_protocol_issuance_execution_lease(
                    int(attempt["id"]), execution_lease
                )
                try:
                    result = self._issue_reserved(
                        request,
                        admission,
                        attempt_id=int(attempt["id"]),
                        execution_lease=execution_lease,
                        event_type=event_type,
                        actor_kind=actor_kind,
                        actor_id=actor_id,
                        reason_code=reason_code,
                        confirmation=confirmation,
                    )
                except Exception as exc:
                    failure = exc
        except ProtocolIssuanceExecutionBlocked as exc:
            return self._blocked(request, exc.reason_code)
        if failure is not None:
            raise failure
        assert result is not None
        return result

    def _prepare_execution_marker(
        self,
        request: SelfServiceIssuanceRequest,
        admission: AdmissionResult,
        *,
        actor_kind: str,
        actor_id: int,
        confirmation: TelegramConfirmationState | None = None,
    ):
        with self._repo.transaction():
            attempt, reservation_block = self._reserve(
                request,
                admission,
                actor_kind=actor_kind,
                actor_id=actor_id,
            )
            if reservation_block is not None:
                return None, None, reservation_block
            assert attempt is not None
            if confirmation is not None and not (
                self._callback_state.bind_confirmation_attempt(
                    confirmation, attempt_id=int(attempt["id"])
                )
            ):
                raise RuntimeError("confirmation attempt binding failed")
            self._repo.mark_protocol_issuance_attempt_recovery_required(
                int(attempt["id"]),
                local_device_id=None,
                reason_code="issuer_in_progress",
            )
            execution_lease = (
                self._repo.create_protocol_issuance_execution_lease(
                    int(attempt["id"])
                )
            )
            return attempt, execution_lease, None

    def _issue_reserved(
        self,
        request: SelfServiceIssuanceRequest,
        admission: AdmissionResult,
        *,
        attempt_id: int,
        execution_lease: object,
        event_type: str,
        actor_kind: str,
        actor_id: int,
        reason_code: str,
        confirmation: TelegramConfirmationState | None = None,
    ) -> SelfServiceIssuanceResult:
        try:
            issued = self._issuer.issue(request=request, admission=admission)
        except IssuerUnavailableBeforeSideEffect:
            self._repo.cancel_protocol_issuance_attempt_before_side_effect(
                attempt_id,
                reason_code="issuer_unavailable_before_side_effect",
                execution_lease=execution_lease,
            )
            return self._blocked(request, "admission_view_unavailable")
        except Exception:
            self._record_recovery_required(
                request,
                attempt_id=attempt_id,
                actor_kind=actor_kind,
                actor_id=actor_id,
                local_device_id=None,
                reason_code="issuer_failed",
            )
            raise
        local_device_id = getattr(
            issued, "local_device_id", getattr(issued, "device_id", None)
        )
        if (
            isinstance(local_device_id, bool)
            or not isinstance(local_device_id, int)
            or local_device_id <= 0
        ):
            self._record_recovery_required(
                request,
                attempt_id=attempt_id,
                actor_kind=actor_kind,
                actor_id=actor_id,
                local_device_id=None,
                reason_code="issuer_result_invalid",
            )
            raise ValueError("issuer did not return a local device id")
        try:
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
                self._repo.complete_protocol_issuance_attempt(
                    attempt_id,
                    local_device_id=local_device_id,
                    execution_lease=execution_lease,
                )
                if confirmation is not None and not (
                    self._callback_state.consume_bound_confirmation(
                        confirmation,
                        attempt_id=attempt_id,
                        terminal_reason=reason_code,
                    )
                ):
                    raise _ConfirmationTerminalizationLost(
                        "confirmation terminalization failed"
                    )
        except Exception:
            self._record_recovery_required(
                request,
                attempt_id=attempt_id,
                actor_kind=actor_kind,
                actor_id=actor_id,
                local_device_id=local_device_id,
                reason_code="finalization_failed",
            )
            raise
        return SelfServiceIssuanceResult(
            status="issued",
            protocol_version=request.protocol_version,
            reason_code=reason_code,
            offer_awg2=False,
            issued_device_id=local_device_id,
            token=None,
        )

    def _record_recovery_required(
        self,
        request: SelfServiceIssuanceRequest,
        *,
        attempt_id: int,
        actor_kind: str,
        actor_id: int,
        local_device_id: int | None,
        reason_code: str,
    ) -> None:
        try:
            self._repo.mark_protocol_issuance_attempt_recovery_required(
                attempt_id,
                local_device_id=local_device_id,
                reason_code=reason_code,
            )
        except Exception as exc:
            raise _RecoveryEnrichmentError(str(exc)) from exc
        with self._repo.transaction():
            self._repo.append_protocol_config_event(
                event_type="protocol_issuance_recovery_required",
                actor_kind=actor_kind,
                actor_id=actor_id,
                reason=reason_code,
                passport_device_id=request.passport_device_id,
                protocol_version=request.protocol_version.value,
                local_device_id=local_device_id,
                metadata={
                    "attempt_id": attempt_id,
                    "reason_code": reason_code,
                },
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


def request_fingerprint(request: SelfServiceIssuanceRequest) -> str:
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
    return "sha256:" + _digest(canonical)


def _is_terminal_callback_result(result: SelfServiceIssuanceResult) -> bool:
    return result.status == "blocked" and result.reason_code in {
        "invalid_confirmation",
        "confirmation_expired",
        "owner_mismatch",
        "user_not_found",
        "user_not_active",
        "user_issuance_blocked",
        "passport_not_found",
        "passport_owner_mismatch",
        "device_owner_mismatch",
        "device_client_mismatch",
        "profile_already_exists",
        "issuance_recovery_required",
    }
