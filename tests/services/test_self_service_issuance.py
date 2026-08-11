from __future__ import annotations

import importlib
import json
import sqlite3
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.services.awg3_control import Awg3ControlState
from app.services.client_compatibility import ClientIdentity
from app.services.device_passports import create_device_passport
from app.services.dual_protocol_profiles import DualProtocolProfileService
from app.services.protocol_admission import AdmissionResult
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


class SyntheticIssuer:
    def __init__(self, repo: Repository, *, user_id: int, server_id: int):
        self.repo = repo
        self.user_id = user_id
        self.server_id = server_id
        self.calls = []

    def issue(self, *, request, admission):
        self.calls.append((request, admission))
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
    service = module.SelfServiceIssuanceService(
        repo=harness.repo,
        admission_service=admission,
        control_service=control,
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
    return service


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
