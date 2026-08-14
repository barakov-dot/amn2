from __future__ import annotations

import importlib
import hashlib
import json
import sqlite3
import threading
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.bot.delivery import ConfigDeliveryPackage
from app.bot.workflows import BotWorkflow
from app.db.connection import connect
from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.services.awg3_control import Awg3ControlState
from app.services.client_compatibility import ClientIdentity
from app.services.client_compatibility import (
    ClientCompatibilityEvidence,
    CompatibilityEvidenceStatus,
    SourceReleaseKind,
)
from app.services.device_passports import create_device_passport
from app.services.dual_protocol_profiles import DualProtocolProfileService
from app.services.protocol_admission import AdmissionResult, ProtocolAdmissionService
from app.services.protocol_issuance_barrier import ProtocolIssuanceBarrierService
from app.services.vpn_runtime_instances import RuntimeInstanceSpec
from app.vpn.protocol_versions import ProtocolVersion


NOW = datetime(2026, 8, 10, 12, 0, tzinfo=timezone.utc)
ACCEPTED_CLIENT = ClientIdentity(
    "amnezia_vpn", "windows", "5.0.0.5", build_id="accepted-build"
)
CANDIDATE_CLIENT = ClientIdentity(
    "amnezia_vpn", "windows", "5.0.0.6", build_id="candidate-build"
)


class StaticAdmissionService:
    def __init__(self, results, order=None):
        self.results = results
        self.calls = []
        self.order = order

    def decide(self, request):
        self.calls.append(request)
        if self.order is not None:
            self.order.append("admission")
        return self.results[request.protocol_version]


class MutableControlService:
    def __init__(self, state: Awg3ControlState, order=None):
        self.state = state
        self.calls = 0
        self.order = order

    def _state(self):
        self.calls += 1
        if self.order is not None:
            self.order.append("control")
        return self.state


class FreshAdmissionProvider:
    def __init__(self, admission, control):
        self.admission = admission
        self.control = control
        self.calls = []

    def __call__(self, request):
        self.calls.append(request)
        return self.admission.decide(request), self.control._state()


class SyntheticIssuer:
    def __init__(self, repo: Repository, *, user_id: int, server_id: int):
        self.repo = repo
        self.user_id = user_id
        self.server_id = server_id
        self.calls = []
        self.callback = None

    def issue(self, *, request, admission):
        self.calls.append((request, admission))
        callback = self.callback
        self.callback = None
        if callback is not None:
            callback()
        sequence = len(self.calls) + 20
        local_device_id = self.repo.create_device(
            user_id=self.user_id,
            server_id=self.server_id,
            name=f"synthetic-self-service-{sequence}",
            duration_days=30,
            vpn_ip=f"10.214.0.{sequence}",
            peer_public_key=f"synthetic-public-{sequence}",
            peer_private_key_encrypted=f"synthetic-encrypted-private-{sequence}",
            preshared_key_encrypted=f"synthetic-encrypted-psk-{sequence}",
            config_version=(
                "amneziawg_v3"
                if request.protocol_version is ProtocolVersion.AWG3
                else "amneziawg_v2"
            ),
            protocol_version=request.protocol_version.value,
            runtime_instance_id=admission.runtime_instance_id,
            compatibility_evidence_id=admission.compatibility_evidence_id,
            client_identity_evidence_status="verified",
        )
        return SimpleNamespace(local_device_id=local_device_id)


class InvalidResultIssuer:
    def __init__(self):
        self.calls = []

    def issue(self, *, request, admission):
        self.calls.append((request, admission))
        return SimpleNamespace(local_device_id=None)


class RaisingIssuer:
    def __init__(self):
        self.calls = []

    def issue(self, *, request, admission):
        self.calls.append((request, admission))
        raise RuntimeError("synthetic issuer boundary failed")


class FailNextCommitConnection:
    def __init__(self, delegate):
        self._delegate = delegate
        self._fail_next_commit = True

    def commit(self):
        marker_exists = self._delegate.execute(
            "SELECT EXISTS(SELECT 1 FROM protocol_issuance_attempts "
            "WHERE state = 'recovery_required' AND reason_code = 'issuer_in_progress')"
        ).fetchone()[0]
        if self._fail_next_commit and marker_exists:
            self._fail_next_commit = False
            raise RuntimeError("synthetic phase-a commit failed")
        return self._delegate.commit()

    def __getattr__(self, name):
        return getattr(self._delegate, name)


@dataclass
class Harness:
    conn: sqlite3.Connection
    repo: Repository
    user_id: int
    telegram_id: int
    server_id: int
    passport_device_id: str


@pytest.fixture
def harness():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    initialize_schema(conn)
    repo = Repository(conn)
    telegram_id = 9307
    user_id = repo.upsert_user(
        telegram_id=telegram_id,
        username="self-service-user",
        first_name="Self",
        last_name="Service",
    )
    server_id = repo.ensure_default_server(
        name="self-service-server",
        network_cidr="10.214.0.0/24",
    )
    awg2_device_id = repo.create_device(
        user_id=user_id,
        server_id=server_id,
        name="synthetic-existing-awg2",
        duration_days=30,
        vpn_ip="10.214.0.2",
        peer_public_key="synthetic-existing-public",
        peer_private_key_encrypted="synthetic-existing-encrypted-private",
        preshared_key_encrypted="synthetic-existing-encrypted-psk",
        config_version="amneziawg_v2",
        protocol_version="awg2",
    )
    passport = create_device_passport(
        repo,
        owner_user_id=user_id,
        local_device_id=awg2_device_id,
        platform="windows",
        official_client_type="amnezia_vpn",
        import_method="conf_file",
        config_schema_version="amneziawg_v2",
        config_text="synthetic-existing-config-fingerprint-source",
        protocol_version="awg2",
    )
    try:
        yield Harness(
            conn=conn,
            repo=repo,
            user_id=user_id,
            telegram_id=telegram_id,
            server_id=server_id,
            passport_device_id=passport.device_id,
        )
    finally:
        conn.close()


def _module():
    return importlib.import_module("app.services.self_service_issuance")


def _callback_module():
    return importlib.import_module("app.services.telegram_callback_state")


def _admitted(protocol: ProtocolVersion = ProtocolVersion.AWG3):
    return AdmissionResult(
        decision="admitted_awg3" if protocol is ProtocolVersion.AWG3 else "admitted_awg2",
        protocol_version=protocol,
        runtime_instance_id=f"rt-synthetic-{protocol.value}",
        compatibility_evidence_id=f"compat-synthetic-{protocol.value}",
    )


def _candidate():
    return AdmissionResult(
        decision="candidate_awg3",
        protocol_version=ProtocolVersion.AWG3,
        runtime_instance_id="rt-synthetic-awg3-candidate",
        compatibility_evidence_id="compat-synthetic-awg3-fresh",
    )


def _permitting_state():
    return Awg3ControlState(
        runtime_accepted=True,
        global_accepted=True,
        issuance_enabled=True,
        emergency_suspended=False,
        runtime_receipt="sha256:" + "a" * 64,
    )


def _request(harness: Harness, *, protocol=ProtocolVersion.AWG3, client=None):
    module = _module()
    return module.SelfServiceIssuanceRequest(
        user_id=harness.user_id,
        telegram_id=harness.telegram_id,
        passport_device_id=harness.passport_device_id,
        protocol_version=protocol,
        client=client or ACCEPTED_CLIENT,
    )


def _service(
    harness: Harness,
    *,
    admission=None,
    control=None,
    issuer=None,
    now=None,
    token_factory=None,
    admission_provider=None,
):
    module = _module()
    admission = admission or StaticAdmissionService(
        {
            ProtocolVersion.AWG2: _admitted(ProtocolVersion.AWG2),
            ProtocolVersion.AWG3: _admitted(ProtocolVersion.AWG3),
        }
    )
    control = control or MutableControlService(_permitting_state())
    issuer = issuer or SyntheticIssuer(
        harness.repo, user_id=harness.user_id, server_id=harness.server_id
    )
    admission_provider = admission_provider or FreshAdmissionProvider(admission, control)
    service = module.SelfServiceIssuanceService(
        repo=harness.repo,
        admission_provider=admission_provider,
        profile_service=DualProtocolProfileService(harness.repo),
        issuer=issuer,
        now=now or (lambda: NOW),
        confirmation_ttl=timedelta(minutes=5),
        token_factory=token_factory,
        bot_admin_telegram_id=700,
        pilot_user_id=harness.user_id,
        pilot_passport_device_id=harness.passport_device_id,
        pilot_client=CANDIDATE_CLIENT,
    )
    service.issuer = issuer
    service.admission_provider = admission_provider
    return service


def _attempts(harness: Harness):
    return harness.conn.execute(
        "SELECT * FROM protocol_issuance_attempts ORDER BY id"
    ).fetchall()


def _awg3_delivery():
    return ConfigDeliveryPackage(
        template_key="config_ready",
        message_text="synthetic ready",
        config_filename="synthetic-awg3.conf",
        config_bytes=b"synthetic-config-payload",
        qr_filename="synthetic-awg3.qr.png",
        qr_png_bytes=b"synthetic-qr-payload",
        vpn_import_link="synthetic-import-reference",
        config_caption="synthetic config",
        qr_caption="synthetic qr",
    )


def _seed_file_backed_harness(database_path):
    conn = connect(database_path)
    initialize_schema(conn)
    repo = Repository(conn)
    telegram_id = 9317
    user_id = repo.upsert_user(
        telegram_id=telegram_id,
        username="self-service-race-user",
        first_name="Self",
        last_name="Race",
    )
    server_id = repo.ensure_default_server(
        name="self-service-race-server",
        network_cidr="10.217.0.0/24",
    )
    awg2_device_id = repo.create_device(
        user_id=user_id,
        server_id=server_id,
        name="synthetic-race-awg2",
        duration_days=30,
        vpn_ip="10.217.0.2",
        peer_public_key="synthetic-race-existing-public",
        peer_private_key_encrypted="synthetic-race-encrypted-private",
        preshared_key_encrypted="synthetic-race-encrypted-psk",
        config_version="amneziawg_v2",
        protocol_version="awg2",
    )
    passport = create_device_passport(
        repo,
        owner_user_id=user_id,
        local_device_id=awg2_device_id,
        platform="windows",
        official_client_type="amnezia_vpn",
        import_method="conf_file",
        config_schema_version="amneziawg_v2",
        config_text="synthetic-race-config-fingerprint-source",
        protocol_version="awg2",
    )
    conn.close()
    return user_id, telegram_id, server_id, passport.device_id


def test_decide_checks_owner_user_device_profile_admission_and_gates_in_order(
    harness, monkeypatch
):
    order = []
    for method_name, label in (
        ("get_user_by_telegram_id", "owner"),
        ("get_user", "user"),
        ("get_device_passport", "passport"),
        ("get_device_protocol_profile", "profile"),
    ):
        original = getattr(harness.repo, method_name)

        def tracked(*args, _original=original, _label=label, **kwargs):
            order.append(_label)
            return _original(*args, **kwargs)

        monkeypatch.setattr(harness.repo, method_name, tracked)
    admission = StaticAdmissionService(
        {ProtocolVersion.AWG3: _admitted()}, order=order
    )
    control = MutableControlService(_permitting_state(), order=order)

    result = _service(harness, admission=admission, control=control).decide(
        _request(harness)
    )

    assert result.status == "confirmation_required"
    assert order[:3] == ["owner", "user", "passport"]
    assert order.index("profile") < order.index("admission") < order.index("control")


def test_compatible_awg3_issues_without_per_user_admin_approval(harness):
    service = _service(harness)
    request = _request(harness)

    decision = service.decide(request)
    result = service.issue_after_confirmation(
        request, confirmation_token=decision.token
    )

    assert decision.status == "confirmation_required"
    assert result.status == "issued"
    assert result.protocol_version is ProtocolVersion.AWG3
    assert result.issued_device_id is not None
    assert len(service.issuer.calls) == 1
    attempt = _attempts(harness)[0]
    assert attempt["state"] == "completed"
    assert attempt["local_device_id"] == result.issued_device_id


def test_incompatible_awg3_only_offers_awg2_without_issuing(harness):
    admission = StaticAdmissionService(
        {
            ProtocolVersion.AWG3: AdmissionResult(
                "blocked_unverified_version",
                ProtocolVersion.AWG3,
                None,
                None,
            )
        }
    )
    service = _service(harness, admission=admission)

    result = service.decide(_request(harness, client=CANDIDATE_CLIENT))

    assert result.status == "blocked"
    assert result.offer_awg2 is True
    assert result.issued_device_id is None
    assert result.token is None
    assert service.issuer.calls == []


def test_awg2_offer_never_silently_falls_back_or_reuses_awg3_confirmation(harness):
    admission = StaticAdmissionService(
        {
            ProtocolVersion.AWG3: AdmissionResult(
                "blocked_unverified_version", ProtocolVersion.AWG3, None, None
            ),
            ProtocolVersion.AWG2: _admitted(ProtocolVersion.AWG2),
        }
    )
    service = _service(harness, admission=admission)
    awg3 = _request(harness)
    awg2 = _request(harness, protocol=ProtocolVersion.AWG2)

    blocked = service.decide(awg3)
    invalid = service.issue_after_confirmation(
        awg2, confirmation_token=blocked.token
    )
    fresh = service.decide(awg2)

    assert invalid.status == "blocked"
    assert invalid.reason_code == "invalid_confirmation"
    assert fresh.status == "confirmation_required"
    assert fresh.protocol_version is ProtocolVersion.AWG2
    assert service.issuer.calls == []


def test_confirmation_is_short_lived_request_bound_and_one_time(harness):
    clock = [NOW]
    service = _service(harness, now=lambda: clock[0])
    request = _request(harness)
    decision = service.decide(request)
    changed_request = replace(request, client=CANDIDATE_CLIENT)

    mismatched = service.issue_after_confirmation(
        changed_request, confirmation_token=decision.token
    )
    assert mismatched.reason_code == "invalid_confirmation"
    assert service.issuer.calls == []

    expiring = service.decide(request)
    clock[0] = NOW + timedelta(minutes=6)
    expired = service.issue_after_confirmation(
        request, confirmation_token=expiring.token
    )
    assert expired.reason_code == "confirmation_expired"
    assert service.issuer.calls == []

    clock[0] = NOW
    fresh = service.decide(request)
    issued = service.issue_after_confirmation(request, confirmation_token=fresh.token)
    replay = service.issue_after_confirmation(request, confirmation_token=fresh.token)
    assert issued.status == "issued"
    assert replay.reason_code == "invalid_confirmation"
    assert len(service.issuer.calls) == 1


def test_awg3_callback_state_is_short_digest_only_exact_and_ttl_bound(harness):
    callback_service = _callback_module().TelegramCallbackStateService(
        repo=harness.repo,
        now=lambda: NOW,
        opaque_factory=lambda: "A" * 22,
    )
    request = _request(harness)

    handle = callback_service.create_selection(
        owner_user_id=request.user_id,
        passport_device_id=request.passport_device_id,
        client_platform=request.client.platform,
        client_application=request.client.application,
        client_version=request.client.version,
        client_build=request.client.build_id,
        request_fingerprint=_module().request_fingerprint(request),
    )
    state = callback_service.claim_selection(handle, owner_user_id=request.user_id)

    assert state is not None
    assert len(f"a3s:{handle}".encode("utf-8")) <= 64
    assert tuple(
        getattr(state, field)
        for field in (
            "owner_user_id",
            "passport_device_id",
            "client_platform",
            "client_application",
            "client_version",
            "client_build",
            "request_fingerprint",
        )
    ) == (
        request.user_id,
        request.passport_device_id,
        "windows",
        "amnezia_vpn",
        "5.0.0.5",
        "accepted-build",
        _module().request_fingerprint(request),
    )
    row = harness.conn.execute("SELECT * FROM telegram_callback_handles").fetchone()
    assert row["handle_digest"] == hashlib.sha256(handle.encode()).hexdigest()
    assert handle not in tuple(str(value) for value in row)
    assert datetime.fromisoformat(row["expires_at"]) - datetime.fromisoformat(
        row["created_at"]
    ) == timedelta(minutes=15)


def test_awg3_callback_state_rejects_opaque_values_below_128_bit_length(harness):
    callback_service = _callback_module().TelegramCallbackStateService(
        repo=harness.repo,
        now=lambda: NOW,
        opaque_factory=lambda: "too-short",
    )
    request = _request(harness)

    with pytest.raises(ValueError, match="selection handle"):
        callback_service.create_selection(
            owner_user_id=request.user_id,
            passport_device_id=request.passport_device_id,
            client_platform=request.client.platform,
            client_application=request.client.application,
            client_version=request.client.version,
            client_build=request.client.build_id,
            request_fingerprint=_module().request_fingerprint(request),
        )

    short_confirmation = _callback_module().TelegramCallbackStateService(
        repo=harness.repo,
        now=lambda: NOW,
        opaque_factory=lambda: "A" * 22,
        confirmation_factory=lambda: "too-short",
    )
    handle = short_confirmation.create_selection(
        owner_user_id=request.user_id,
        passport_device_id=request.passport_device_id,
        client_platform=request.client.platform,
        client_application=request.client.application,
        client_version=request.client.version,
        client_build=request.client.build_id,
        request_fingerprint=_module().request_fingerprint(request),
    )
    selection = short_confirmation.claim_selection(
        handle, owner_user_id=request.user_id
    )
    with pytest.raises(ValueError, match="confirmation token"):
        short_confirmation.create_confirmation(selection)

    short_claim = _callback_module().TelegramCallbackStateService(
        repo=harness.repo,
        now=lambda: NOW,
        opaque_factory=lambda: "B" * 22,
        claim_factory=lambda: "too-short",
    )
    claim_handle = short_claim.create_selection(
        owner_user_id=request.user_id,
        passport_device_id=request.passport_device_id,
        client_platform=request.client.platform,
        client_application=request.client.application,
        client_version=request.client.version,
        client_build=request.client.build_id,
        request_fingerprint=_module().request_fingerprint(request),
    )
    with pytest.raises(ValueError, match="claim id"):
        short_claim.claim_selection(claim_handle, owner_user_id=request.user_id)


def test_awg3_invalid_purpose_fails_closed_if_terminal_consume_is_lost(
    harness, monkeypatch
):
    callback_service = _callback_module().TelegramCallbackStateService(
        repo=harness.repo,
        now=lambda: NOW,
    )
    request = _request(harness)
    handle = "C" * 22
    harness.repo.create_callback_handle(
        handle_digest=hashlib.sha256(handle.encode()).hexdigest(),
        purpose="wrong_purpose",
        owner_user_id=request.user_id,
        passport_device_id=request.passport_device_id,
        client_platform=request.client.platform,
        client_application=request.client.application,
        client_version=request.client.version,
        client_build=request.client.build_id,
        request_fingerprint=_module().request_fingerprint(request),
        created_at=NOW.isoformat(),
        expires_at=(NOW + timedelta(minutes=15)).isoformat(),
    )
    monkeypatch.setattr(
        callback_service,
        "consume_selection",
        lambda _state, *, terminal_reason: False,
    )

    with pytest.raises(RuntimeError, match="invalid-purpose selection"):
        callback_service.claim_selection(handle, owner_user_id=request.user_id)


def test_awg3_invalid_selection_fails_closed_if_terminal_consume_is_lost(
    harness, monkeypatch
):
    service = _service(harness)
    request = _request(harness)
    handle = service._callback_state.create_selection(
        owner_user_id=request.user_id,
        passport_device_id=request.passport_device_id,
        client_platform=request.client.platform,
        client_application=request.client.application,
        client_version=request.client.version,
        client_build=request.client.build_id,
        request_fingerprint="sha256:" + "f" * 64,
    )
    monkeypatch.setattr(
        service._callback_state,
        "consume_selection",
        lambda _state, *, terminal_reason: False,
    )

    with pytest.raises(RuntimeError, match="invalid selection"):
        service.decide_from_selection(
            owner_user_id=request.user_id,
            telegram_id=request.telegram_id,
            selection_handle=handle,
        )


def test_awg3_selection_terminal_consume_loss_returns_no_result(
    harness, monkeypatch
):
    service = _service(harness)
    request = _request(harness)
    handle = service._callback_state.create_selection(
        owner_user_id=request.user_id,
        passport_device_id=request.passport_device_id,
        client_platform=request.client.platform,
        client_application=request.client.application,
        client_version=request.client.version,
        client_build=request.client.build_id,
        request_fingerprint=_module().request_fingerprint(request),
    )
    harness.repo.set_user_status_for_admin(harness.user_id, "blocked")
    monkeypatch.setattr(
        service._callback_state,
        "consume_selection",
        lambda _state, *, terminal_reason: False,
    )

    result = service.decide_from_selection(
        owner_user_id=request.user_id,
        telegram_id=request.telegram_id,
        selection_handle=handle,
    )

    assert result is None


def test_awg3_expired_wrong_purpose_selection_stays_unconsumed(harness):
    callback_service = _callback_module().TelegramCallbackStateService(
        repo=harness.repo,
        now=lambda: NOW,
    )
    request = _request(harness)
    handle = "W" * 22
    handle_digest = hashlib.sha256(handle.encode()).hexdigest()
    harness.repo.create_callback_handle(
        handle_digest=handle_digest,
        purpose="wrong_purpose",
        owner_user_id=request.user_id,
        passport_device_id=request.passport_device_id,
        client_platform=request.client.platform,
        client_application=request.client.application,
        client_version=request.client.version,
        client_build=request.client.build_id,
        request_fingerprint=_module().request_fingerprint(request),
        created_at=(NOW - timedelta(minutes=16)).isoformat(),
        expires_at=(NOW - timedelta(minutes=1)).isoformat(),
    )

    assert callback_service.consume_expired_selection(
        handle, owner_user_id=request.user_id
    ) is None
    row = harness.conn.execute(
        "SELECT consumed_at, terminal_reason FROM telegram_callback_handles "
        "WHERE handle_digest = ?",
        (handle_digest,),
    ).fetchone()
    assert tuple(row) == (None, None)


def test_awg3_selection_wrong_owner_does_not_consume_owner_state(harness):
    service = _service(harness)
    request = _request(harness)
    callback_state = service._callback_state
    handle = callback_state.create_selection(
        owner_user_id=request.user_id,
        passport_device_id=request.passport_device_id,
        client_platform=request.client.platform,
        client_application=request.client.application,
        client_version=request.client.version,
        client_build=request.client.build_id,
        request_fingerprint=_module().request_fingerprint(request),
    )
    other_owner_id = harness.repo.upsert_user(
        telegram_id=9308,
        username="other-owner",
        first_name="Other",
        last_name="Owner",
    )

    assert service.decide_from_selection(
        owner_user_id=other_owner_id,
        telegram_id=9308,
        selection_handle=handle,
    ) is None
    owner_result = service.decide_from_selection(
        owner_user_id=request.user_id,
        telegram_id=request.telegram_id,
        selection_handle=handle,
    )

    assert owner_result.status == "confirmation_required"


def test_awg3_expired_selection_is_owner_terminal_and_wrong_owner_safe(harness):
    clock = [NOW]
    service = _service(harness, now=lambda: clock[0])
    request = _request(harness)
    handle = service._callback_state.create_selection(
        owner_user_id=request.user_id,
        passport_device_id=request.passport_device_id,
        client_platform=request.client.platform,
        client_application=request.client.application,
        client_version=request.client.version,
        client_build=request.client.build_id,
        request_fingerprint=_module().request_fingerprint(request),
    )
    other_owner_id = harness.repo.upsert_user(
        telegram_id=9308,
        username="other-owner",
        first_name="Other",
        last_name="Owner",
    )
    clock[0] = NOW + timedelta(minutes=16)

    assert service.decide_from_selection(
        owner_user_id=other_owner_id,
        telegram_id=9308,
        selection_handle=handle,
    ) is None
    assert harness.conn.execute(
        "SELECT consumed_at FROM telegram_callback_handles"
    ).fetchone()[0] is None

    owner_result = service.decide_from_selection(
        owner_user_id=request.user_id,
        telegram_id=request.telegram_id,
        selection_handle=handle,
    )

    assert owner_result.status == "blocked"
    assert owner_result.reason_code == "selection_expired"
    assert harness.conn.execute(
        "SELECT terminal_reason FROM telegram_callback_handles"
    ).fetchone()[0] == "expired"


def test_awg3_confirmation_survives_service_restart_and_is_owner_bound(harness):
    first = _service(harness)
    request = _request(harness)
    decision = first.decide(request)
    other_owner_id = harness.repo.upsert_user(
        telegram_id=9308,
        username="other-owner",
        first_name="Other",
        last_name="Owner",
    )

    restarted = _service(harness, issuer=first.issuer)
    wrong_owner = restarted.issue_after_confirmation(
        owner_user_id=other_owner_id,
        confirmation_token=decision.token,
    )
    issued = restarted.issue_after_confirmation(
        owner_user_id=harness.user_id,
        confirmation_token=decision.token,
    )
    replay = restarted.issue_after_confirmation(
        owner_user_id=harness.user_id,
        confirmation_token=decision.token,
    )

    assert wrong_owner is None
    assert issued.status == "issued"
    assert replay is None
    assert len(first.issuer.calls) == 1
    confirmation = harness.conn.execute(
        "SELECT * FROM protocol_issuance_confirmations"
    ).fetchone()
    selection = harness.conn.execute(
        "SELECT * FROM telegram_callback_handles"
    ).fetchone()
    assert confirmation["selection_handle_digest"] == selection["handle_digest"]
    assert confirmation["consumed_at"] is not None
    assert datetime.fromisoformat(confirmation["expires_at"]) - datetime.fromisoformat(
        confirmation["created_at"]
    ) == timedelta(minutes=5)


def test_awg3_reopened_database_fresh_service_and_workflow_complete_callback(
    tmp_path,
):
    database_path = tmp_path / "awg3-workflow-restart.sqlite3"
    user_id, telegram_id, server_id, passport_device_id = (
        _seed_file_backed_harness(database_path)
    )
    first_conn = connect(database_path)
    first_repo = Repository(first_conn)
    first_harness = Harness(
        conn=first_conn,
        repo=first_repo,
        user_id=user_id,
        telegram_id=telegram_id,
        server_id=server_id,
        passport_device_id=passport_device_id,
    )
    client = ACCEPTED_CLIENT
    first_service = _service(first_harness)
    first_workflow = BotWorkflow(
        repo=first_repo,
        admin_telegram_ids=set(),
        self_service_issuance_service=first_service,
        awg3_client_choices=(client,),
    )
    choice = first_workflow.list_awg3_client_choices(
        telegram_id=telegram_id,
        passport_device_id=passport_device_id,
    )[0]
    token = first_workflow.request_awg3(
        telegram_id=telegram_id,
        selection_handle=choice.selection_handle,
    ).token
    first_conn.close()

    restarted_conn = connect(database_path)
    try:
        restarted_repo = Repository(restarted_conn)
        restarted_harness = Harness(
            conn=restarted_conn,
            repo=restarted_repo,
            user_id=user_id,
            telegram_id=telegram_id,
            server_id=server_id,
            passport_device_id=passport_device_id,
        )
        issuer = SyntheticIssuer(
            restarted_repo, user_id=user_id, server_id=server_id
        )
        restarted_service = _service(restarted_harness, issuer=issuer)
        restarted_workflow = BotWorkflow(
            repo=restarted_repo,
            admin_telegram_ids=set(),
            self_service_issuance_service=restarted_service,
            awg3_client_choices=(client,),
            awg3_delivery_builder=lambda _device_id: _awg3_delivery(),
        )

        confirmed = restarted_workflow.confirm_awg3(
            telegram_id=telegram_id,
            confirmation_token=token,
        )

        assert confirmed.result.status == "issued"
        assert confirmed.delivery.config_filename == "synthetic-awg3.conf"
        assert len(issuer.calls) == 1
    finally:
        restarted_conn.close()


def test_awg3_competing_connection_cannot_reach_issuer_with_live_claim(tmp_path):
    database_path = tmp_path / "awg3-competing-claim.sqlite3"
    user_id, telegram_id, server_id, passport_device_id = (
        _seed_file_backed_harness(database_path)
    )
    first_conn = connect(database_path)
    first_repo = Repository(first_conn)
    first_harness = Harness(
        conn=first_conn,
        repo=first_repo,
        user_id=user_id,
        telegram_id=telegram_id,
        server_id=server_id,
        passport_device_id=passport_device_id,
    )
    first_issuer = SyntheticIssuer(
        first_repo, user_id=user_id, server_id=server_id
    )
    first_service = _service(first_harness, issuer=first_issuer)
    token = first_service.decide(_request(first_harness)).token
    live_claim = first_service._callback_state.claim_confirmation(
        token, owner_user_id=user_id
    )
    assert live_claim is not None

    second_conn = connect(database_path)
    try:
        second_repo = Repository(second_conn)
        second_harness = Harness(
            conn=second_conn,
            repo=second_repo,
            user_id=user_id,
            telegram_id=telegram_id,
            server_id=server_id,
            passport_device_id=passport_device_id,
        )
        second_issuer = SyntheticIssuer(
            second_repo, user_id=user_id, server_id=server_id
        )
        second_service = _service(second_harness, issuer=second_issuer)

        duplicate = second_service.issue_after_confirmation(
            owner_user_id=user_id,
            confirmation_token=token,
        )

        assert duplicate is None
        assert second_issuer.calls == []
    finally:
        second_conn.close()

    assert first_service._callback_state.release_confirmation(live_claim) is True
    issued = first_service.issue_after_confirmation(
        owner_user_id=user_id,
        confirmation_token=token,
    )
    assert issued.status == "issued"
    assert len(first_issuer.calls) == 1
    first_conn.close()


def test_awg3_inflight_confirmation_survives_expired_duplicate_and_prune(
    harness,
):
    clock = [NOW]
    issuer = SyntheticIssuer(
        harness.repo, user_id=harness.user_id, server_id=harness.server_id
    )
    worker_a = _service(harness, issuer=issuer, now=lambda: clock[0])
    duplicate_worker = _service(harness, issuer=issuer, now=lambda: clock[0])
    request = _request(harness)
    token = worker_a.decide(request).token
    observations = {}

    def duplicate_and_prune_after_ttl():
        clock[0] = NOW + timedelta(minutes=6)
        observations["duplicate"] = duplicate_worker.issue_after_confirmation(
            owner_user_id=harness.user_id,
            confirmation_token=token,
        )
        observations["new_selection"] = duplicate_worker.decide(request)

    issuer.callback = duplicate_and_prune_after_ttl

    issued = worker_a.issue_after_confirmation(
        owner_user_id=harness.user_id,
        confirmation_token=token,
    )

    row = harness.conn.execute(
        "SELECT consumed_at, terminal_reason FROM protocol_issuance_confirmations "
        "WHERE token_digest = ?",
        (hashlib.sha256(token.encode()).hexdigest(),),
    ).fetchone()
    assert observations["duplicate"] is None
    assert observations["new_selection"].status == "confirmation_required"
    assert issued.status == "issued"
    assert len(issuer.calls) == 1
    assert tuple(row) == (clock[0].isoformat(), "issued")


def test_awg3_inflight_selection_survives_expired_duplicate_and_prune(harness):
    clock = [NOW]
    worker_a = _service(harness, now=lambda: clock[0])
    duplicate_worker = _service(harness, now=lambda: clock[0])
    request = _request(harness)
    handle = worker_a._callback_state.create_selection(
        owner_user_id=request.user_id,
        passport_device_id=request.passport_device_id,
        client_platform=request.client.platform,
        client_application=request.client.application,
        client_version=request.client.version,
        client_build=request.client.build_id,
        request_fingerprint=_module().request_fingerprint(request),
    )
    claimed = worker_a._callback_state.claim_selection(
        handle, owner_user_id=request.user_id
    )
    assert claimed is not None
    clock[0] = NOW + timedelta(minutes=16)

    duplicate = duplicate_worker.decide_from_selection(
        owner_user_id=request.user_id,
        telegram_id=request.telegram_id,
        selection_handle=handle,
    )
    duplicate_worker._callback_state.create_selection(
        owner_user_id=request.user_id,
        passport_device_id=request.passport_device_id,
        client_platform=request.client.platform,
        client_application=request.client.application,
        client_version=request.client.version,
        client_build=request.client.build_id,
        request_fingerprint=_module().request_fingerprint(request),
    )

    assert duplicate is None
    assert worker_a._callback_state.consume_selection(
        claimed, terminal_reason="protocol-selected"
    ) is True


def test_awg3_duplicate_confirmation_never_calls_issuer_twice(harness):
    issuer = SyntheticIssuer(
        harness.repo, user_id=harness.user_id, server_id=harness.server_id
    )
    first = _service(harness, issuer=issuer)
    second = _service(harness, issuer=issuer)
    request = _request(harness)
    token = first.decide(request).token
    duplicate = {}
    issuer.callback = lambda: duplicate.setdefault(
        "result",
        second.issue_after_confirmation(
            owner_user_id=harness.user_id,
            confirmation_token=token,
        ),
    )

    issued = first.issue_after_confirmation(
        owner_user_id=harness.user_id,
        confirmation_token=token,
    )

    assert issued.status == "issued"
    assert duplicate["result"] is None
    assert len(issuer.calls) == 1


def test_awg3_claimed_confirmation_finalizes_after_row_and_claim_ttl(harness):
    clock = [NOW]
    issuer = SyntheticIssuer(
        harness.repo, user_id=harness.user_id, server_id=harness.server_id
    )
    service = _service(harness, issuer=issuer, now=lambda: clock[0])
    request = _request(harness)
    token = service.decide(request).token
    issuer.callback = lambda: clock.__setitem__(0, NOW + timedelta(minutes=6))

    result = service.issue_after_confirmation(
        owner_user_id=harness.user_id,
        confirmation_token=token,
    )

    row = harness.conn.execute(
        "SELECT consumed_at, terminal_reason FROM protocol_issuance_confirmations"
    ).fetchone()
    assert result.status == "issued"
    assert tuple(row) == (
        (NOW + timedelta(minutes=6)).isoformat(),
        "issued",
    )


def test_awg3_issued_result_fails_closed_when_exact_claim_is_lost(harness):
    issuer = SyntheticIssuer(
        harness.repo, user_id=harness.user_id, server_id=harness.server_id
    )
    service = _service(harness, issuer=issuer)
    request = _request(harness)
    token = service.decide(request).token
    issuer.callback = lambda: harness.conn.execute(
        "UPDATE protocol_issuance_confirmations SET claim_id_digest = ?",
        ("f" * 64,),
    )

    result = service.issue_after_confirmation(
        owner_user_id=harness.user_id,
        confirmation_token=token,
    )

    assert result is None
    assert len(issuer.calls) == 1
    row = harness.conn.execute(
        "SELECT consumed_at, claim_id_digest FROM protocol_issuance_confirmations"
    ).fetchone()
    assert tuple(row) == (None, "f" * 64)


def test_awg3_transient_result_fails_closed_when_claim_release_fails(
    harness, monkeypatch
):
    control = MutableControlService(_permitting_state())
    service = _service(harness, control=control)
    request = _request(harness)
    token = service.decide(request).token
    control.state = replace(control.state, issuance_enabled=False)
    monkeypatch.setattr(
        service._callback_state,
        "release_confirmation",
        lambda _state: False,
    )

    result = service.issue_after_confirmation(
        owner_user_id=harness.user_id,
        confirmation_token=token,
    )

    assert result is None


def test_awg3_confirmation_terminal_consume_loss_returns_no_result(
    harness, monkeypatch
):
    service = _service(harness)
    request = _request(harness)
    token = service.decide(request).token
    harness.repo.set_user_status_for_admin(harness.user_id, "blocked")
    monkeypatch.setattr(
        service._callback_state,
        "consume_confirmation",
        lambda _state, *, terminal_reason: False,
    )

    result = service.issue_after_confirmation(
        owner_user_id=harness.user_id,
        confirmation_token=token,
    )

    assert result is None


def test_issue_rechecks_gate_drift_before_consuming_token_or_calling_issuer(harness):
    control = MutableControlService(_permitting_state())
    service = _service(harness, control=control)
    request = _request(harness)
    decision = service.decide(request)
    control.state = replace(control.state, issuance_enabled=False)

    blocked = service.issue_after_confirmation(
        request, confirmation_token=decision.token
    )

    assert blocked.status == "blocked"
    assert blocked.reason_code == "blocked_issuance_disabled"
    assert service.issuer.calls == []
    control.state = _permitting_state()
    issued = service.issue_after_confirmation(
        request, confirmation_token=decision.token
    )
    assert issued.status == "issued"
    assert len(service.issuer.calls) == 1


def test_existing_profile_blocks_before_admission_or_issuer(harness):
    profile_service = DualProtocolProfileService(harness.repo)
    local_device_id = harness.repo.create_device(
        user_id=harness.user_id,
        server_id=harness.server_id,
        name="synthetic-existing-awg3",
        duration_days=30,
        vpn_ip="10.214.0.19",
        peer_public_key="synthetic-existing-awg3-public",
        peer_private_key_encrypted="synthetic-existing-awg3-private",
        preshared_key_encrypted="synthetic-existing-awg3-psk",
        config_version="amneziawg_v3",
        protocol_version="awg3",
    )
    profile_service.attach_active(
        harness.passport_device_id,
        ProtocolVersion.AWG3,
        local_device_id,
    )
    admission = StaticAdmissionService({ProtocolVersion.AWG3: _admitted()})
    service = _service(harness, admission=admission)

    result = service.decide(_request(harness))

    assert result.reason_code == "profile_already_exists"
    assert admission.calls == []
    assert service.issuer.calls == []


def test_issued_profile_and_event_contain_only_safe_metadata(harness):
    service = _service(harness)
    request = _request(harness)
    decision = service.decide(request)

    result = service.issue_after_confirmation(request, confirmation_token=decision.token)

    profile = DualProtocolProfileService(harness.repo).for_passport(
        harness.passport_device_id
    )[0]
    assert profile.local_device_id == result.issued_device_id
    row = harness.conn.execute(
        "SELECT * FROM protocol_config_events WHERE event_type = 'self_service_issued'"
    ).fetchone()
    assert row is not None
    metadata = json.loads(str(row["metadata_json"]))
    assert metadata == {
        "client_application": "amnezia_vpn",
        "client_build": "accepted-build",
        "client_platform": "windows",
        "client_version": "5.0.0.5",
        "profile_id": profile.profile_id,
    }
    assert not ({"config", "private_key", "preshared_key", "qr"} & set(metadata))


def test_admin_pilot_allows_one_exact_candidate_profile_without_general_enable(
    harness,
):
    disabled = Awg3ControlState(
        runtime_accepted=False,
        global_accepted=False,
        issuance_enabled=False,
        emergency_suspended=False,
        runtime_receipt=None,
    )
    control = MutableControlService(disabled)
    admission = StaticAdmissionService({ProtocolVersion.AWG3: _candidate()})
    service = _service(harness, admission=admission, control=control)
    request = _request(harness, client=CANDIDATE_CLIENT)

    result = service.issue_admin_pilot(admin_telegram_id=700, request=request)

    assert result.status == "issued"
    assert result.reason_code == "admin_pilot"
    assert control.state == disabled
    assert len(service.issuer.calls) == 1
    assert _attempts(harness)[0]["state"] == "completed"
    with pytest.raises(ValueError, match="pilot profile already exists"):
        service.issue_admin_pilot(admin_telegram_id=700, request=request)
    assert len(service.issuer.calls) == 1


@pytest.mark.parametrize(
    ("admin_id", "request_change", "reason"),
    [
        (701, {}, "admin_pilot_not_authorized"),
        (700, {"telegram_id": 9308}, "owner_mismatch"),
        (700, {"passport_device_id": "wrong-device"}, "pilot_identity_mismatch"),
        (700, {"client": ACCEPTED_CLIENT}, "pilot_build_mismatch"),
    ],
)
def test_admin_pilot_rejects_every_non_exact_boundary_before_issuer(
    harness, admin_id, request_change, reason
):
    service = _service(
        harness,
        admission=StaticAdmissionService({ProtocolVersion.AWG3: _candidate()}),
        control=MutableControlService(
            Awg3ControlState(False, False, False, False, None)
        ),
    )
    request = replace(
        _request(harness, client=CANDIDATE_CLIENT), **request_change
    )

    result = service.issue_admin_pilot(
        admin_telegram_id=admin_id, request=request
    )

    assert result.status == "blocked"
    assert result.reason_code == reason
    assert result.offer_awg2 is False
    assert service.issuer.calls == []


@pytest.mark.parametrize(
    "candidate_result",
    [
        AdmissionResult("candidate_awg3", ProtocolVersion.AWG3, None, "fresh"),
        AdmissionResult("candidate_awg3", ProtocolVersion.AWG3, "runtime", None),
        AdmissionResult("blocked_evidence_stale_or_failed", ProtocolVersion.AWG3, None, None),
    ],
)
def test_admin_pilot_never_bypasses_fresh_evidence_or_candidate_runtime(
    harness, candidate_result
):
    service = _service(
        harness,
        admission=StaticAdmissionService({ProtocolVersion.AWG3: candidate_result}),
        control=MutableControlService(
            Awg3ControlState(False, False, False, False, None)
        ),
    )

    result = service.issue_admin_pilot(
        admin_telegram_id=700,
        request=_request(harness, client=CANDIDATE_CLIENT),
    )

    assert result.status == "blocked"
    assert service.issuer.calls == []


def test_admin_pilot_never_bypasses_emergency_suspension(harness):
    service = _service(
        harness,
        admission=StaticAdmissionService({ProtocolVersion.AWG3: _candidate()}),
        control=MutableControlService(
            Awg3ControlState(False, False, False, True, None)
        ),
    )

    result = service.issue_admin_pilot(
        admin_telegram_id=700,
        request=_request(harness, client=CANDIDATE_CLIENT),
    )

    assert result.reason_code == "blocked_runtime_suspended"
    assert service.issuer.calls == []


def test_real_candidate_admission_selects_newest_exact_evidence_for_admin_pilot(
    harness,
):
    exact = CANDIDATE_CLIENT
    other = ClientIdentity(
        exact.application,
        exact.platform,
        exact.version,
        build_id="other-build",
    )

    def evidence(
        evidence_id,
        client,
        source_kind,
        status,
        observed_at,
    ):
        return ClientCompatibilityEvidence(
            evidence_id=evidence_id,
            client=client,
            protocol_version=ProtocolVersion.AWG3,
            source_kind=source_kind,
            status=status,
            observed_at=observed_at,
            safe_reference=f"synthetic:{evidence_id}",
            scope="exact candidate admission",
            release_kind=SourceReleaseKind.PRERELEASE,
        )

    admission_service = ProtocolAdmissionService(
        evidence=(
            evidence(
                "candidate-z",
                exact,
                "official_release",
                CompatibilityEvidenceStatus.CLAIMED,
                NOW,
            ),
            evidence(
                "candidate-a",
                exact,
                "local_import",
                CompatibilityEvidenceStatus.CLAIMED,
                NOW,
            ),
            evidence(
                "candidate-failed-history",
                exact,
                "official_release",
                CompatibilityEvidenceStatus.FAILED,
                NOW - timedelta(days=1),
            ),
            evidence(
                "candidate-superseded-history",
                exact,
                "local_import",
                CompatibilityEvidenceStatus.SUPERSEDED,
                NOW - timedelta(days=1),
            ),
            evidence(
                "candidate-nonexact-newer",
                other,
                "official_release",
                CompatibilityEvidenceStatus.CLAIMED,
                NOW + timedelta(minutes=1),
            ),
        ),
        runtimes=(
            RuntimeInstanceSpec(
                runtime_instance_id="rt-synthetic-awg3-candidate",
                server_id=harness.server_id,
                protocol_version=ProtocolVersion.AWG3,
                runtime_version="3.0.3",
                interface_name="awg3",
                udp_port=30002,
                vpn_cidr="10.217.0.0/24",
                container_name="synthetic-awg3",
                service_name=None,
                config_path="/synthetic/awg3.conf",
                lifecycle_state="candidate",
                acceptance_receipt=None,
            ),
        ),
        now=NOW,
    )
    control = Awg3ControlState(False, False, False, False, None)
    service = _service(
        harness,
        admission_provider=lambda request: (
            admission_service.decide(request),
            control,
        ),
    )

    result = service.issue_admin_pilot(
        admin_telegram_id=700,
        request=_request(harness, client=CANDIDATE_CLIENT),
    )

    assert result.status == "issued"
    attempt = _attempts(harness)[0]
    assert attempt["compatibility_evidence_id"] == "candidate-a"


def test_distinct_confirmation_race_reservation_calls_issuer_once(harness):
    issuer = SyntheticIssuer(
        harness.repo, user_id=harness.user_id, server_id=harness.server_id
    )
    first = _service(
        harness,
        issuer=issuer,
        token_factory=lambda: "synthetic-confirmation-one",
    )
    second = _service(
        harness,
        issuer=issuer,
        token_factory=lambda: "synthetic-confirmation-two",
    )
    request = _request(harness)
    first_token = first.decide(request).token
    second_token = second.decide(request).token
    inner = {}
    issuer.callback = lambda: inner.setdefault(
        "result",
        second.issue_after_confirmation(
            request, confirmation_token=second_token
        ),
    )

    outer = first.issue_after_confirmation(
        request, confirmation_token=first_token
    )

    assert outer.status == "issued"
    assert inner["result"].status == "blocked"
    assert inner["result"].reason_code == "issuance_recovery_required"
    assert len(issuer.calls) == 1
    assert [row["state"] for row in _attempts(harness)] == ["completed"]


def test_admin_pilot_race_reservation_calls_issuer_once(harness):
    issuer = SyntheticIssuer(
        harness.repo, user_id=harness.user_id, server_id=harness.server_id
    )
    disabled = Awg3ControlState(False, False, False, False, None)
    first = _service(
        harness,
        admission=StaticAdmissionService({ProtocolVersion.AWG3: _candidate()}),
        control=MutableControlService(disabled),
        issuer=issuer,
    )
    second = _service(
        harness,
        admission=StaticAdmissionService({ProtocolVersion.AWG3: _candidate()}),
        control=MutableControlService(disabled),
        issuer=issuer,
    )
    request = _request(harness, client=CANDIDATE_CLIENT)
    inner = {}
    issuer.callback = lambda: inner.setdefault(
        "result",
        second.issue_admin_pilot(admin_telegram_id=700, request=request),
    )

    outer = first.issue_admin_pilot(admin_telegram_id=700, request=request)

    assert outer.status == "issued"
    assert inner["result"].status == "blocked"
    assert inner["result"].reason_code == "issuance_recovery_required"
    assert len(issuer.calls) == 1
    assert [row["state"] for row in _attempts(harness)] == ["completed"]


@pytest.mark.parametrize(
    ("fresh_result", "reason"),
    [
        (
            AdmissionResult(
                "blocked_global_acceptance",
                ProtocolVersion.AWG3,
                None,
                None,
            ),
            "blocked_global_acceptance",
        ),
        (
            AdmissionResult(
                "blocked_evidence_stale_or_failed",
                ProtocolVersion.AWG3,
                None,
                None,
            ),
            "blocked_evidence_stale_or_failed",
        ),
    ],
    ids=["security_revoked_build", "newly_stale_evidence"],
)
def test_issue_rechecks_fresh_admission_view_before_reservation_and_issuer(
    harness, fresh_result, reason
):
    admission = StaticAdmissionService({ProtocolVersion.AWG3: _admitted()})
    service = _service(harness, admission=admission)
    request = _request(harness)
    token = service.decide(request).token
    admission.results[ProtocolVersion.AWG3] = fresh_result

    result = service.issue_after_confirmation(request, confirmation_token=token)

    assert result.status == "blocked"
    assert result.reason_code == reason
    assert len(service.admission_provider.calls) == 2
    assert service.issuer.calls == []
    assert _attempts(harness) == []


def test_expired_confirmation_is_owner_terminal_then_pruned_opportunistically(
    harness,
):
    clock = [NOW]
    tokens = iter(("synthetic-old-token-opaque", "synthetic-new-token-opaque"))
    service = _service(
        harness,
        now=lambda: clock[0],
        token_factory=lambda: next(tokens),
    )
    request = _request(harness)
    old = service.decide(request).token
    clock[0] = NOW + timedelta(minutes=6)

    result = service.issue_after_confirmation(request, confirmation_token=old)

    assert result.reason_code == "confirmation_expired"
    assert service.issuer.calls == []
    expired_row = harness.conn.execute(
        "SELECT consumed_at, terminal_reason FROM protocol_issuance_confirmations "
        "WHERE token_digest = ?",
        (hashlib.sha256(old.encode()).hexdigest(),),
    ).fetchone()
    assert tuple(expired_row) == (clock[0].isoformat(), "expired")

    service.decide(request)

    assert harness.conn.execute(
        "SELECT 1 FROM protocol_issuance_confirmations WHERE token_digest = ?",
        (hashlib.sha256(old.encode()).hexdigest(),),
    ).fetchone() is None


def test_expired_confirmation_wrong_owner_cannot_consume_owner_state(harness):
    clock = [NOW]
    service = _service(harness, now=lambda: clock[0])
    request = _request(harness)
    token = service.decide(request).token
    other_owner_id = harness.repo.upsert_user(
        telegram_id=9308,
        username="other-owner",
        first_name="Other",
        last_name="Owner",
    )
    clock[0] = NOW + timedelta(minutes=6)

    assert service.issue_after_confirmation(
        owner_user_id=other_owner_id,
        confirmation_token=token,
    ) is None
    assert harness.conn.execute(
        "SELECT consumed_at FROM protocol_issuance_confirmations"
    ).fetchone()[0] is None

    owner_result = service.issue_after_confirmation(
        owner_user_id=harness.user_id,
        confirmation_token=token,
    )

    assert owner_result.reason_code == "confirmation_expired"
    assert harness.conn.execute(
        "SELECT terminal_reason FROM protocol_issuance_confirmations"
    ).fetchone()[0] == "expired"


def test_invalid_issuer_result_requires_recovery_and_blocks_fresh_token(harness):
    issuer = InvalidResultIssuer()
    first = _service(
        harness,
        issuer=issuer,
        token_factory=lambda: "synthetic-invalid-one-x",
    )
    second = _service(
        harness,
        issuer=issuer,
        token_factory=lambda: "synthetic-invalid-two-x",
    )
    request = _request(harness)
    first_token = first.decide(request).token
    second_token = second.decide(request).token

    with pytest.raises(ValueError, match="issuer did not return a local device id"):
        first.issue_after_confirmation(request, confirmation_token=first_token)

    attempt = _attempts(harness)[0]
    assert attempt["state"] == "recovery_required"
    assert attempt["reason_code"] == "issuer_result_invalid"
    blocked = second.issue_after_confirmation(
        request, confirmation_token=second_token
    )
    assert blocked.reason_code == "issuance_recovery_required"
    assert len(issuer.calls) == 1


def test_issuer_exception_requires_recovery_and_blocks_fresh_token(harness):
    issuer = RaisingIssuer()
    first = _service(
        harness,
        issuer=issuer,
        token_factory=lambda: "synthetic-exception-one",
    )
    second = _service(
        harness,
        issuer=issuer,
        token_factory=lambda: "synthetic-exception-two",
    )
    request = _request(harness)
    first_token = first.decide(request).token
    second_token = second.decide(request).token

    with pytest.raises(RuntimeError, match="synthetic issuer boundary failed"):
        first.issue_after_confirmation(request, confirmation_token=first_token)

    attempt = _attempts(harness)[0]
    assert attempt["state"] == "recovery_required"
    assert attempt["reason_code"] == "issuer_failed"
    blocked = second.issue_after_confirmation(
        request, confirmation_token=second_token
    )
    assert blocked.reason_code == "issuance_recovery_required"
    assert len(issuer.calls) == 1


def test_preissuer_recovery_marker_failure_prevents_self_service_issuer_call(
    harness,
    monkeypatch,
):
    issuer = SyntheticIssuer(
        harness.repo,
        user_id=harness.user_id,
        server_id=harness.server_id,
    )
    service = _service(harness, issuer=issuer)
    request = _request(harness)
    token = service.decide(request).token

    def fail_initial_marker(*_args, **_kwargs):
        raise RuntimeError("synthetic initial recovery marker failed")

    monkeypatch.setattr(
        harness.repo,
        "mark_protocol_issuance_attempt_recovery_required",
        fail_initial_marker,
    )

    with pytest.raises(RuntimeError, match="synthetic initial recovery marker failed"):
        service.issue_after_confirmation(request, confirmation_token=token)

    assert issuer.calls == []
    assert _attempts(harness) == []


@pytest.mark.parametrize(
    ("failure_stage", "expected_reason", "error_message"),
    [
        ("state", "issuer_in_progress", "synthetic recovery enrichment failed"),
        ("event", "issuer_failed", "synthetic recovery event write failed"),
    ],
)
def test_secondary_recovery_failure_commits_original_marker_and_blocks_retry(
    harness,
    monkeypatch,
    failure_stage,
    expected_reason,
    error_message,
):
    issuer = RaisingIssuer()
    service = _service(harness, issuer=issuer)
    request = _request(harness)
    token = service.decide(request).token

    if failure_stage == "state":
        original_mark = harness.repo.mark_protocol_issuance_attempt_recovery_required
        mark_calls = []

        def fail_recovery_enrichment(*args, **kwargs):
            mark_calls.append(kwargs["reason_code"])
            if len(mark_calls) == 2:
                raise RuntimeError(error_message)
            return original_mark(*args, **kwargs)

        monkeypatch.setattr(
            harness.repo,
            "mark_protocol_issuance_attempt_recovery_required",
            fail_recovery_enrichment,
        )
    else:
        original_append = harness.repo.append_protocol_config_event

        def fail_recovery_event(**kwargs):
            if kwargs["event_type"] == "protocol_issuance_recovery_required":
                raise RuntimeError(error_message)
            return original_append(**kwargs)

        monkeypatch.setattr(
            harness.repo,
            "append_protocol_config_event",
            fail_recovery_event,
        )

    with pytest.raises(RuntimeError, match=error_message):
        service.issue_after_confirmation(request, confirmation_token=token)

    attempts = _attempts(harness)
    assert [row["state"] for row in attempts] == ["recovery_required"]
    assert attempts[0]["reason_code"] == expected_reason
    retry_service = _service(
        harness,
        issuer=issuer,
        token_factory=lambda: "synthetic-recovery-retry-token",
    )
    retry_token = retry_service.decide(request).token
    retry = retry_service.issue_after_confirmation(
        request,
        confirmation_token=retry_token,
    )
    assert retry.status == "blocked"
    assert retry.reason_code == "issuance_recovery_required"
    assert len(issuer.calls) == 1


def test_finalization_failure_requires_recovery_and_blocks_retry(
    harness, monkeypatch
):
    issuer = SyntheticIssuer(
        harness.repo, user_id=harness.user_id, server_id=harness.server_id
    )
    first = _service(
        harness,
        issuer=issuer,
        token_factory=lambda: "synthetic-finalize-one",
    )
    second = _service(
        harness,
        issuer=issuer,
        token_factory=lambda: "synthetic-finalize-two",
    )
    request = _request(harness)
    first_token = first.decide(request).token
    second_token = second.decide(request).token
    original_append = harness.repo.append_protocol_config_event

    def fail_issuance_event(**kwargs):
        if kwargs["event_type"] == "self_service_issued":
            raise RuntimeError("synthetic finalization failure")
        return original_append(**kwargs)

    monkeypatch.setattr(
        harness.repo, "append_protocol_config_event", fail_issuance_event
    )

    with pytest.raises(RuntimeError, match="synthetic finalization failure"):
        first.issue_after_confirmation(request, confirmation_token=first_token)

    attempt = _attempts(harness)[0]
    assert attempt["state"] == "recovery_required"
    assert attempt["reason_code"] == "finalization_failed"
    assert attempt["local_device_id"] is not None
    assert harness.repo.get_device_protocol_profile(
        passport_device_id=harness.passport_device_id,
        protocol_version="awg3",
    ) is None
    recovery_event = harness.conn.execute(
        "SELECT metadata_json FROM protocol_config_events "
        "WHERE event_type = 'protocol_issuance_recovery_required'"
    ).fetchone()
    assert json.loads(recovery_event["metadata_json"]) == {
        "attempt_id": int(attempt["id"]),
        "reason_code": "finalization_failed",
    }
    blocked = second.issue_after_confirmation(
        request, confirmation_token=second_token
    )
    assert blocked.reason_code == "issuance_recovery_required"
    assert len(issuer.calls) == 1


def test_winning_issuance_holds_one_outer_transaction_through_issuer_and_completion(
    harness,
):
    class TransactionCheckingIssuer(SyntheticIssuer):
        def issue(self, *, request, admission):
            assert self.repo._transaction_depth == 1
            return super().issue(request=request, admission=admission)

    issuer = TransactionCheckingIssuer(
        harness.repo, user_id=harness.user_id, server_id=harness.server_id
    )
    service = _service(harness, issuer=issuer)
    request = _request(harness)
    token = service.decide(request).token

    result = service.issue_after_confirmation(request, confirmation_token=token)

    assert result.status == "issued"
    attempt = _attempts(harness)[0]
    assert attempt["state"] == "completed"
    assert attempt["owner_user_id"] == harness.user_id
    assert attempt["intended_passport_device_id"] == harness.passport_device_id


def test_self_service_issuance_wins_real_sqlite_race_and_block_removes_exact_peer(
    tmp_path,
):
    database_path = tmp_path / "self-service-race.sqlite3"
    user_id, telegram_id, server_id, passport_device_id = (
        _seed_file_backed_harness(database_path)
    )
    issuer_entered = threading.Event()
    allow_issuer = threading.Event()
    block_begin_seen = threading.Event()
    block_finished = threading.Event()
    known_peer_ids = set()
    removed_peer_ids = set()
    results = {}
    errors = []

    def issue_in_thread():
        conn = connect(database_path)
        repo = Repository(conn)
        thread_harness = Harness(
            conn=conn,
            repo=repo,
            user_id=user_id,
            telegram_id=telegram_id,
            server_id=server_id,
            passport_device_id=passport_device_id,
        )

        class PausingIssuer(SyntheticIssuer):
            def issue(self, *, request, admission):
                issuer_entered.set()
                if not allow_issuer.wait(timeout=3):
                    raise AssertionError("block did not reach the issuance lock")
                issued = super().issue(request=request, admission=admission)
                known_peer_ids.add(int(issued.local_device_id))
                return issued

        issuer = PausingIssuer(repo, user_id=user_id, server_id=server_id)
        try:
            service = _service(thread_harness, issuer=issuer)
            request = _request(thread_harness)
            token = service.decide(request).token
            results["issuance"] = service.issue_after_confirmation(
                request,
                confirmation_token=token,
            )
            results["issuer_calls"] = len(issuer.calls)
        except Exception as exc:
            errors.append(exc)
        finally:
            conn.close()

    def block_in_thread():
        conn = connect(database_path)
        conn.set_trace_callback(
            lambda statement: block_begin_seen.set()
            if statement.strip().upper() == "BEGIN IMMEDIATE"
            else None
        )
        repo = Repository(conn)
        try:
            barrier = ProtocolIssuanceBarrierService(repo)
            plan = barrier.begin_block(user_id)
            removed = {int(row["id"]) for row in plan.devices}
            removed_peer_ids.update(removed)
            known_peer_ids.difference_update(removed)
            results["block_complete"] = barrier.complete_block(
                user_id,
                removed_local_device_ids=removed,
            )
        except Exception as exc:
            errors.append(exc)
        finally:
            block_finished.set()
            conn.close()

    issuance_thread = threading.Thread(target=issue_in_thread)
    issuance_thread.start()
    assert issuer_entered.wait(timeout=3)
    block_thread = threading.Thread(target=block_in_thread)
    block_thread.start()
    assert block_begin_seen.wait(timeout=3)
    assert not block_finished.is_set()
    allow_issuer.set()
    issuance_thread.join(timeout=3)
    block_thread.join(timeout=3)

    assert not issuance_thread.is_alive()
    assert not block_thread.is_alive()
    assert errors == []
    issued_device_id = int(results["issuance"].issued_device_id)
    assert results["issuer_calls"] == 1
    assert issued_device_id in removed_peer_ids
    assert known_peer_ids == set()
    assert results["block_complete"] is True
    verification_conn = connect(database_path)
    verification_repo = Repository(verification_conn)
    barrier = verification_repo.get_protocol_issuance_user_barrier(user_id)
    assert barrier["state"] == "blocked"
    verification_conn.close()


def test_user_barrier_blocks_before_reservation_or_issuer(harness):
    harness.conn.execute(
        "INSERT INTO protocol_issuance_user_barriers(user_id, state) VALUES (?, 'blocking')",
        (harness.user_id,),
    )
    harness.conn.commit()
    service = _service(harness)

    result = service.decide(_request(harness))

    assert result.status == "blocked"
    assert result.reason_code == "user_issuance_blocked"
    assert service.issuer.calls == []
    assert _attempts(harness) == []


def test_self_service_phase_a_marker_is_visible_before_remote_baseexception_and_restart(
    tmp_path,
):
    database_path = tmp_path / "self-service-crash.sqlite3"
    user_id, telegram_id, server_id, passport_device_id = (
        _seed_file_backed_harness(database_path)
    )
    conn = connect(database_path)
    repo = Repository(conn)
    thread_harness = Harness(
        conn=conn,
        repo=repo,
        user_id=user_id,
        telegram_id=telegram_id,
        server_id=server_id,
        passport_device_id=passport_device_id,
    )
    observed_markers = []
    remote_side_effects = []

    class CrashingRemoteIssuer:
        def issue(self, *, request, admission):
            visibility_conn = connect(database_path)
            observed_markers.extend(
                tuple(row)
                for row in visibility_conn.execute(
                    "SELECT state, reason_code FROM protocol_issuance_attempts"
                ).fetchall()
            )
            visibility_conn.close()
            remote_side_effects.append(request.passport_device_id)
            raise SystemExit("synthetic remote crash")

    service = _service(thread_harness, issuer=CrashingRemoteIssuer())
    request = _request(thread_harness)
    token = service.decide(request).token

    with pytest.raises(SystemExit, match="synthetic remote crash"):
        service.issue_after_confirmation(request, confirmation_token=token)
    conn.close()

    assert observed_markers == [("recovery_required", "issuer_in_progress")]
    assert remote_side_effects == [passport_device_id]
    retry_conn = connect(database_path)
    retry_repo = Repository(retry_conn)
    retry_harness = Harness(
        conn=retry_conn,
        repo=retry_repo,
        user_id=user_id,
        telegram_id=telegram_id,
        server_id=server_id,
        passport_device_id=passport_device_id,
    )
    retry_issuer = SyntheticIssuer(
        retry_repo,
        user_id=user_id,
        server_id=server_id,
    )
    retry_service = _service(retry_harness, issuer=retry_issuer)
    retry_request = _request(retry_harness)
    retry_token = retry_service.decide(retry_request).token
    retry = retry_service.issue_after_confirmation(
        retry_request,
        confirmation_token=retry_token,
    )
    assert retry.status == "blocked"
    assert retry.reason_code == "issuance_recovery_required"
    assert retry_issuer.calls == []
    retry_conn.close()


def test_self_service_phase_a_commit_failure_prevents_remote_issuer(harness):
    issuer = SyntheticIssuer(
        harness.repo,
        user_id=harness.user_id,
        server_id=harness.server_id,
    )
    service = _service(harness, issuer=issuer)
    request = _request(harness)
    token = service.decide(request).token
    delegate = harness.conn
    harness.repo._conn = FailNextCommitConnection(delegate)

    try:
        with pytest.raises(RuntimeError, match="synthetic phase-a commit failed"):
            service.issue_after_confirmation(request, confirmation_token=token)
        assert issuer.calls == []
        assert delegate.in_transaction is False
        assert delegate.execute(
            "SELECT COUNT(*) FROM protocol_issuance_attempts"
        ).fetchone()[0] == 0
    finally:
        harness.repo._conn = delegate
        delegate.rollback()


def _phase_a_lease(harness):
    request = _request(harness)
    admission = _admitted()
    with harness.repo.transaction():
        attempt = harness.repo.reserve_protocol_issuance_attempt(
            owner_user_id=harness.user_id,
            intended_passport_device_id=harness.passport_device_id,
            passport_device_id=harness.passport_device_id,
            protocol_version="awg3",
            request_fingerprint="sha256:" + "1" * 64,
            actor_kind="user",
            actor_id=harness.telegram_id,
            client_application=request.client.application,
            client_platform=request.client.platform,
            client_version=request.client.version,
            client_build=request.client.build_id,
            runtime_instance_id=admission.runtime_instance_id,
            compatibility_evidence_id=admission.compatibility_evidence_id,
        )
        assert attempt is not None
        harness.repo.mark_protocol_issuance_attempt_recovery_required(
            int(attempt["id"]),
            local_device_id=None,
            reason_code="issuer_in_progress",
        )
        lease = harness.repo.create_protocol_issuance_execution_lease(
            int(attempt["id"])
        )
    issued = SyntheticIssuer(
        harness.repo,
        user_id=harness.user_id,
        server_id=harness.server_id,
    ).issue(request=request, admission=admission)
    return int(attempt["id"]), lease, int(issued.local_device_id)


def test_issuer_marker_completion_without_execution_lease_is_rejected(harness):
    request = _request(harness)
    admission = _admitted()
    with harness.repo.transaction():
        attempt = harness.repo.reserve_protocol_issuance_attempt(
            owner_user_id=harness.user_id,
            intended_passport_device_id=harness.passport_device_id,
            passport_device_id=harness.passport_device_id,
            protocol_version="awg3",
            request_fingerprint="sha256:" + "2" * 64,
            actor_kind="user",
            actor_id=harness.telegram_id,
            client_application=request.client.application,
            client_platform=request.client.platform,
            client_version=request.client.version,
            client_build=request.client.build_id,
            runtime_instance_id=admission.runtime_instance_id,
            compatibility_evidence_id=admission.compatibility_evidence_id,
        )
        assert attempt is not None
        harness.repo.mark_protocol_issuance_attempt_recovery_required(
            int(attempt["id"]),
            local_device_id=None,
            reason_code="issuer_in_progress",
        )
    issued = SyntheticIssuer(
        harness.repo,
        user_id=harness.user_id,
        server_id=harness.server_id,
    ).issue(request=request, admission=admission)

    with pytest.raises(ValueError, match="execution lease"):
        with harness.repo.transaction():
            harness.repo.complete_protocol_issuance_attempt(
                int(attempt["id"]),
                local_device_id=int(issued.local_device_id),
            )


def test_execution_lease_bound_to_prior_transaction_is_rejected(harness):
    attempt_id, lease, local_device_id = _phase_a_lease(harness)
    with harness.repo.transaction():
        harness.repo.bind_protocol_issuance_execution_lease(attempt_id, lease)

    with pytest.raises(ValueError, match="current outer transaction"):
        with harness.repo.transaction():
            harness.repo.complete_protocol_issuance_attempt(
                attempt_id,
                local_device_id=local_device_id,
                execution_lease=lease,
            )


def test_execution_lease_cannot_complete_twice_in_same_transaction(harness):
    attempt_id, lease, local_device_id = _phase_a_lease(harness)
    with harness.repo.transaction():
        harness.repo.bind_protocol_issuance_execution_lease(attempt_id, lease)
        harness.repo.complete_protocol_issuance_attempt(
            attempt_id,
            local_device_id=local_device_id,
            execution_lease=lease,
        )
        with pytest.raises(ValueError, match="already used"):
            harness.repo.complete_protocol_issuance_attempt(
                attempt_id,
                local_device_id=local_device_id,
                execution_lease=lease,
            )


def test_self_service_block_in_phase_gap_prevents_remote_issuer_and_keeps_marker(
    harness,
    monkeypatch,
):
    issuer = SyntheticIssuer(
        harness.repo,
        user_id=harness.user_id,
        server_id=harness.server_id,
    )
    service = _service(harness, issuer=issuer)
    original_prepare = getattr(
        service,
        "_prepare_execution_marker",
        lambda *_args, **_kwargs: None,
    )

    def block_after_phase_a(*args, **kwargs):
        prepared = original_prepare(*args, **kwargs)
        ProtocolIssuanceBarrierService(harness.repo).begin_block(harness.user_id)
        return prepared

    monkeypatch.setattr(
        service,
        "_prepare_execution_marker",
        block_after_phase_a,
        raising=False,
    )
    request = _request(harness)
    token = service.decide(request).token

    result = service.issue_after_confirmation(request, confirmation_token=token)

    assert result.status == "blocked"
    assert result.reason_code == "user_issuance_blocked"
    assert issuer.calls == []
    attempt = _attempts(harness)[0]
    assert attempt["state"] == "recovery_required"
    assert attempt["reason_code"] == "issuer_in_progress"
