from __future__ import annotations

import importlib
import json
import sqlite3
import threading
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.db.connection import connect
from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.services.awg3_control import Awg3ControlState
from app.services.client_compatibility import ClientIdentity
from app.services.device_passports import create_device_passport
from app.services.dual_protocol_profiles import DualProtocolProfileService
from app.services.protocol_admission import AdmissionResult
from app.services.protocol_issuance_barrier import ProtocolIssuanceBarrierService
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
    admission_provider = FreshAdmissionProvider(admission, control)
    service = module.SelfServiceIssuanceService(
        repo=harness.repo,
        admission_provider=admission_provider,
        profile_service=DualProtocolProfileService(harness.repo),
        issuer=issuer,
        now=now or (lambda: NOW),
        confirmation_ttl=timedelta(minutes=5),
        token_factory=token_factory or (lambda: "synthetic-confirmation-token"),
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

    clock[0] = NOW + timedelta(minutes=6)
    expired = service.issue_after_confirmation(
        request, confirmation_token=decision.token
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
    assert inner["result"].reason_code == "issuance_in_progress"
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
    assert inner["result"].reason_code == "issuance_in_progress"
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


def test_expired_confirmations_are_pruned_opportunistically(harness):
    clock = [NOW]
    tokens = iter(("synthetic-old-token", "synthetic-new-token"))
    service = _service(
        harness,
        now=lambda: clock[0],
        token_factory=lambda: next(tokens),
    )
    request = _request(harness)
    old = service.decide(request).token
    clock[0] = NOW + timedelta(minutes=6)

    service.decide(request)
    result = service.issue_after_confirmation(request, confirmation_token=old)

    assert result.reason_code == "invalid_confirmation"
    assert service.issuer.calls == []


def test_invalid_issuer_result_requires_recovery_and_blocks_fresh_token(harness):
    issuer = InvalidResultIssuer()
    first = _service(
        harness,
        issuer=issuer,
        token_factory=lambda: "synthetic-invalid-one",
    )
    second = _service(
        harness,
        issuer=issuer,
        token_factory=lambda: "synthetic-invalid-two",
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


@pytest.mark.parametrize(
    ("failure_stage", "expected_attempt_state", "error_message"),
    [
        ("state", None, "synthetic recovery state write failed"),
        ("event", "recovery_required", "synthetic recovery event write failed"),
    ],
)
def test_recovery_persistence_failure_never_commits_a_preissuer_reserved_attempt(
    harness,
    monkeypatch,
    failure_stage,
    expected_attempt_state,
    error_message,
):
    issuer = RaisingIssuer()
    service = _service(harness, issuer=issuer)
    request = _request(harness)
    token = service.decide(request).token

    if failure_stage == "state":
        def fail_recovery_state(*_args, **_kwargs):
            raise RuntimeError(error_message)

        monkeypatch.setattr(
            harness.repo,
            "mark_protocol_issuance_attempt_recovery_required",
            fail_recovery_state,
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
    assert all(row["state"] != "reserved" for row in attempts)
    if expected_attempt_state is None:
        assert attempts == []
    else:
        assert [row["state"] for row in attempts] == [expected_attempt_state]
        assert attempts[0]["reason_code"] == "issuer_failed"
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
