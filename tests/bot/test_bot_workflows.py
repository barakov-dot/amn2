import json

import pytest

from app.bot.workflows import BotWorkflow
from app.db.connection import connect
from app.db.repositories import Repository
from app.db.schema import initialize_schema
from app.security.crypto import SecretBox
from app.server.peer_apply import PeerApplyError
from app.services.access import AccessService, RemoteOperationPartialFailure
from app.services.traffic import PeerTraffic, TrafficService

SECRET = "bot-workflow-secret-value-with-more-than-32-chars"


def test_smoke_request_approve_delivery_traffic_and_revoke_flow(tmp_path):
    repo = _repo(tmp_path)
    repo.seed_default_plans()
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    peer_applier = RecordingPeerApplier()
    peer_remover = RecordingPeerRemover()
    workflow = BotWorkflow(
        repo=repo,
        admin_telegram_ids={9001},
        access_service=AccessService(
            repo=repo,
            secret_box=SecretBox.from_app_secret(SECRET),
            max_devices_per_user=5,
            duration_days=7,
            peer_applier=peer_applier,
        ),
        default_server_id=server_id,
        secret_box=SecretBox.from_app_secret(SECRET),
        peer_remover=peer_remover,
    )

    request = workflow.request_access(
        telegram_id=1001,
        username="alice",
        first_name="Alice",
        last_name=None,
        config_version="amneziawg_v2",
        plan_id="days_7",
    )
    approval = workflow.approve_order(
        admin_telegram_id=9001,
        order_id=request.order_id,
        config_version="amneziawg_v2",
    )
    device = repo.get_device(approval.device_id)
    TrafficService(repo).collect_and_store(
        server_id,
        StaticTrafficCollector(
            [
                PeerTraffic(
                    peer_public_key=str(device["peer_public_key"]),
                    rx_bytes=1024,
                    tx_bytes=2048,
                    collected_at="2026-05-27T12:00:00Z",
                    source="smoke",
                )
            ]
        ),
    )
    traffic_views = workflow.build_user_traffic_views(
        telegram_id=1001,
        now="2026-05-27T12:05:00Z",
    )
    revoked = workflow.revoke_user_device(
        telegram_id=1001,
        device_id=approval.device_id,
        revoked_at="2026-05-27T12:10:00Z",
    )

    assert request.order_id == 1
    assert peer_applier.calls[0]["peer_public_key"] == device["peer_public_key"]
    assert approval.delivery.config_filename.endswith(".conf")
    assert approval.delivery.qr_png_bytes.startswith(b"\x89PNG")
    assert traffic_views[0].total == "3.0 KiB"
    assert traffic_views[0].is_connected is True
    assert revoked is True
    assert peer_remover.calls == [
        {"server_id": server_id, "peer_public_key": device["peer_public_key"]}
    ]
    assert repo.get_device(approval.device_id)["status"] == "revoked"

def test_request_access_creates_order_with_selected_config_version(tmp_path):
    repo = _repo(tmp_path)
    repo.seed_default_plans()
    workflow = BotWorkflow(repo=repo, admin_telegram_ids={9001})

    result = workflow.request_access(
        telegram_id=1001,
        username="alice",
        first_name="Alice",
        last_name=None,
        config_version="amneziawg_v1_5",
        plan_id="days_14",
    )

    order = repo.get_order(result.order_id)
    assert order["requested_config_version"] == "amneziawg_v1_5"
    assert order["plan_id"] == "days_14"
    assert "AmneziaWG 1.5" in result.text
    assert "14 days" in result.text


def test_list_active_plans_returns_available_tariffs_for_bot_flow(tmp_path):
    repo = _repo(tmp_path)
    repo.seed_default_plans()
    workflow = BotWorkflow(repo=repo, admin_telegram_ids={9001})

    plans = workflow.list_active_plans()

    assert [plan["id"] for plan in plans] == [
        "days_3",
        "days_7",
        "days_10",
        "days_14",
        "days_30",
        "days_60",
        "days_90",
        "days_180",
    ]


def test_build_user_traffic_views_reads_user_devices_and_latest_stats(tmp_path):
    repo = _repo(tmp_path)
    user_id = repo.upsert_user(
        telegram_id=1001,
        username="alice",
        first_name="Alice",
        last_name=None,
    )
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    device_id = repo.create_device(
        user_id=user_id,
        server_id=server_id,
        name="phone",
        duration_days=30,
        vpn_ip="10.8.0.2",
        peer_public_key="peer-phone",
        peer_private_key_encrypted="encrypted-private-phone",
        preshared_key_encrypted="encrypted-psk-phone",
        config_version="amneziawg_v2",
    )
    repo.record_device_traffic_snapshot(
        device_id=device_id,
        server_id=server_id,
        peer_public_key="peer-phone",
        rx_bytes=1024,
        tx_bytes=2048,
        source="test",
        collected_at="2026-05-27T12:00:00Z",
    )
    workflow = BotWorkflow(repo=repo, admin_telegram_ids={9001})

    views = workflow.build_user_traffic_views(
        telegram_id=1001,
        now="2026-05-27T12:30:00Z",
    )

    assert len(views) == 1
    assert views[0].device_name == "phone"
    assert views[0].total == "3.0 KiB"


def test_build_admin_traffic_views_requires_admin(tmp_path):
    repo = _repo(tmp_path)
    workflow = BotWorkflow(repo=repo, admin_telegram_ids={9001})

    assert workflow.build_admin_traffic_views(
        admin_telegram_id=1001,
        now="2026-05-27T12:30:00Z",
    ) == []


def test_build_admin_traffic_views_reads_active_devices(tmp_path):
    repo = _repo(tmp_path)
    user_id = repo.upsert_user(
        telegram_id=1001,
        username="alice",
        first_name="Alice",
        last_name=None,
    )
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    _create_encrypted_device(repo, user_id=user_id, server_id=server_id, name="phone")
    workflow = BotWorkflow(repo=repo, admin_telegram_ids={9001})

    views = workflow.build_admin_traffic_views(
        admin_telegram_id=9001,
        now="2026-05-27T12:30:00Z",
    )

    assert len(views) == 1
    assert views[0].device_name == "phone"
    assert views[0].config_version == "amneziawg_v2"
    assert views[0].is_available is False


def test_approve_order_creates_device_with_selected_config_version(tmp_path):
    repo = _repo(tmp_path)
    user_id = repo.upsert_user(
        telegram_id=1001,
        username="alice",
        first_name="Alice",
        last_name=None,
    )
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    order_id = repo.create_order(
        user_id=user_id,
        plan_id=None,
        payment_mode="free_test",
        requested_config_version="amneziawg_v2",
    )
    workflow = BotWorkflow(
        repo=repo,
        admin_telegram_ids={9001},
        access_service=AccessService(
            repo=repo,
            secret_box=SecretBox.from_app_secret(SECRET),
            max_devices_per_user=5,
            duration_days=7,
        ),
        default_server_id=server_id,
    )

    result = workflow.approve_order(
        admin_telegram_id=9001,
        order_id=order_id,
        config_version="amneziawg_v1_5",
    )

    device = repo.get_device(result.device_id)
    assert device["config_version"] == "amneziawg_v1_5"
    assert result.user_telegram_id == 1001
    assert "Access request #1 approved" in result.admin_text
    assert "[Interface]" in result.config_text
    assert result.delivery.config_filename == f"amneziya-device-{result.device_id}.conf"
    assert result.delivery.qr_png_bytes.startswith(b"\x89PNG")
    assert "DefaultVPN" in result.delivery.message_text


def test_approve_order_records_redacted_vps_failure_audit(tmp_path):
    repo = _repo(tmp_path)
    user_id = repo.upsert_user(
        telegram_id=1001,
        username="alice",
        first_name="Alice",
        last_name=None,
    )
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    order_id = repo.create_order(
        user_id=user_id,
        plan_id=None,
        payment_mode="free_test",
        requested_config_version="amneziawg_v2",
    )
    workflow = BotWorkflow(
        repo=repo,
        admin_telegram_ids={9001},
        access_service=AccessService(
            repo=repo,
            secret_box=SecretBox.from_app_secret(SECRET),
            max_devices_per_user=5,
            duration_days=7,
            peer_applier=RecordingPeerApplier(
                error=PeerApplyError("Docker apply failed: PresharedKey = secret-psk")
            ),
        ),
        default_server_id=server_id,
    )

    with pytest.raises(PeerApplyError):
        workflow.approve_order(
            admin_telegram_id=9001,
            order_id=order_id,
            config_version="amneziawg_v2",
        )

    actions = repo.list_admin_actions_for_target_user(user_id)
    metadata = json.loads(actions[0]["metadata_json"])
    assert repo.count_active_devices(user_id) == 0
    assert repo.get_order(order_id)["status"] == "manual_review"
    assert actions[0]["action"] == "approve_order_vps_failed"
    assert metadata["operation"] == "approve_order"
    assert metadata["order_id"] == order_id
    assert metadata["server_id"] == server_id
    assert metadata["config_version"] == "amneziawg_v2"
    assert metadata["error_type"] == "PeerApplyError"
    assert "Docker apply failed" in metadata["redacted_error"]
    assert "secret-psk" not in metadata["redacted_error"]


def test_approve_order_rejects_non_admin_without_creating_device(tmp_path):
    repo = _repo(tmp_path)
    user_id = repo.upsert_user(
        telegram_id=1001,
        username="alice",
        first_name="Alice",
        last_name=None,
    )
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    order_id = repo.create_order(
        user_id=user_id,
        plan_id=None,
        payment_mode="free_test",
        requested_config_version="amneziawg_v2",
    )
    workflow = BotWorkflow(
        repo=repo,
        admin_telegram_ids={9001},
        access_service=AccessService(
            repo=repo,
            secret_box=SecretBox.from_app_secret(SECRET),
            max_devices_per_user=5,
            duration_days=7,
        ),
        default_server_id=server_id,
    )

    result = workflow.approve_order(
        admin_telegram_id=1001,
        order_id=order_id,
        config_version="amneziawg_v1_5",
    )

    assert result is None
    assert repo.count_active_devices(user_id) == 0


def test_admin_can_read_update_and_reset_config_ready_template(tmp_path):
    repo = _repo(tmp_path)
    workflow = BotWorkflow(repo=repo, admin_telegram_ids={9001})

    original = workflow.get_config_ready_template(admin_telegram_id=9001)
    workflow.set_config_ready_template(
        admin_telegram_id=9001,
        text="Custom template {device_id}",
    )
    updated = workflow.get_config_ready_template(admin_telegram_id=9001)
    workflow.reset_config_ready_template(admin_telegram_id=9001)
    reset = workflow.get_config_ready_template(admin_telegram_id=9001)

    assert "Android AmneziaVPN" in original
    assert updated == "Custom template {device_id}"
    assert reset == original


def test_resend_device_config_rebuilds_delivery_from_encrypted_device_secrets(tmp_path):
    repo = _repo(tmp_path)
    user_id = repo.upsert_user(
        telegram_id=1001,
        username="alice",
        first_name="Alice",
        last_name=None,
    )
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    order_id = repo.create_order(
        user_id=user_id,
        plan_id=None,
        payment_mode="free_test",
        requested_config_version="amneziawg_v2",
    )
    workflow = BotWorkflow(
        repo=repo,
        admin_telegram_ids={9001},
        access_service=AccessService(
            repo=repo,
            secret_box=SecretBox.from_app_secret(SECRET),
            max_devices_per_user=5,
            duration_days=7,
        ),
        default_server_id=server_id,
        secret_box=SecretBox.from_app_secret(SECRET),
    )
    approval = workflow.approve_order(
        admin_telegram_id=9001,
        order_id=order_id,
        config_version="amneziawg_v2",
    )

    resend = workflow.build_resend_delivery(
        admin_telegram_id=9001,
        device_id=approval.device_id,
    )

    assert resend.user_telegram_id == 1001
    assert resend.delivery.config_filename == f"amneziya-device-{approval.device_id}.conf"
    assert resend.delivery.qr_png_bytes.startswith(b"\x89PNG")
    assert "[Interface]" in resend.config_text


def test_resend_device_config_uses_current_external_template_for_stored_version(tmp_path):
    repo = _repo(tmp_path)
    user_id = repo.upsert_user(
        telegram_id=1001,
        username="alice",
        first_name="Alice",
        last_name=None,
    )
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    template_dir = tmp_path / "templates"
    template_dir.mkdir()
    (template_dir / "amneziawg_v1_5.conf.tpl").write_text(
        "Resend template {address} through {endpoint}\nPrivateKey = {private_key}\n",
        encoding="utf-8",
    )
    device_id = _create_encrypted_device(
        repo,
        user_id=user_id,
        server_id=server_id,
        name="phone",
        config_version="amneziawg_v1_5",
    )
    workflow = BotWorkflow(
        repo=repo,
        admin_telegram_ids={9001},
        secret_box=SecretBox.from_app_secret(SECRET),
        client_config_template_dir=str(template_dir),
    )

    resend = workflow.build_resend_delivery(
        admin_telegram_id=9001,
        device_id=device_id,
    )

    assert resend.config_text.startswith("Resend template")
    assert "through 127.0.0.1:30001" in resend.config_text


def test_user_can_resend_only_owned_device_config(tmp_path):
    repo = _repo(tmp_path)
    user_id = repo.upsert_user(
        telegram_id=1001,
        username="alice",
        first_name="Alice",
        last_name=None,
    )
    other_user_id = repo.upsert_user(
        telegram_id=2002,
        username="bob",
        first_name="Bob",
        last_name=None,
    )
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    device_id = _create_encrypted_device(
        repo,
        user_id=user_id,
        server_id=server_id,
        name="phone",
    )
    other_device_id = _create_encrypted_device(
        repo,
        user_id=other_user_id,
        server_id=server_id,
        name="tablet",
    )
    workflow = BotWorkflow(
        repo=repo,
        admin_telegram_ids={9001},
        secret_box=SecretBox.from_app_secret(SECRET),
    )

    resend = workflow.build_user_resend_delivery(
        telegram_id=1001,
        device_id=device_id,
    )
    forbidden = workflow.build_user_resend_delivery(
        telegram_id=1001,
        device_id=other_device_id,
    )

    assert resend.user_telegram_id == 1001
    assert resend.delivery.config_filename == f"amneziya-device-{device_id}.conf"
    assert forbidden is None


def test_user_can_revoke_one_owned_device(tmp_path):
    repo = _repo(tmp_path)
    user_id = repo.upsert_user(
        telegram_id=1001,
        username="alice",
        first_name="Alice",
        last_name=None,
    )
    other_user_id = repo.upsert_user(
        telegram_id=2002,
        username="bob",
        first_name="Bob",
        last_name=None,
    )
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    device_id = _create_encrypted_device(
        repo,
        user_id=user_id,
        server_id=server_id,
        name="phone",
    )
    other_device_id = _create_encrypted_device(
        repo,
        user_id=other_user_id,
        server_id=server_id,
        name="tablet",
    )
    workflow = BotWorkflow(repo=repo, admin_telegram_ids={9001})

    revoked = workflow.revoke_user_device(
        telegram_id=1001,
        device_id=device_id,
        revoked_at="2026-05-27T12:00:00Z",
    )
    forbidden = workflow.revoke_user_device(
        telegram_id=1001,
        device_id=other_device_id,
        revoked_at="2026-05-27T12:00:00Z",
    )

    assert revoked is True
    assert forbidden is False
    assert repo.get_device(device_id)["status"] == "revoked"
    assert repo.get_device(other_device_id)["status"] == "active"


def test_user_revoke_removes_peer_before_marking_device_revoked(tmp_path):
    repo = _repo(tmp_path)
    user_id = repo.upsert_user(
        telegram_id=1001,
        username="alice",
        first_name="Alice",
        last_name=None,
    )
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    device_id = _create_encrypted_device(
        repo,
        user_id=user_id,
        server_id=server_id,
        name="phone",
    )
    peer_remover = RecordingPeerRemover()
    workflow = BotWorkflow(
        repo=repo,
        admin_telegram_ids={9001},
        peer_remover=peer_remover,
    )

    revoked = workflow.revoke_user_device(
        telegram_id=1001,
        device_id=device_id,
        revoked_at="2026-05-27T12:00:00Z",
    )

    assert revoked is True
    assert peer_remover.calls == [
        {
            "server_id": server_id,
            "peer_public_key": "peer-phone",
        }
    ]
    assert repo.get_device(device_id)["status"] == "revoked"


def test_user_revoke_keeps_device_active_when_peer_remove_fails(tmp_path):
    repo = _repo(tmp_path)
    user_id = repo.upsert_user(
        telegram_id=1001,
        username="alice",
        first_name="Alice",
        last_name=None,
    )
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    device_id = _create_encrypted_device(
        repo,
        user_id=user_id,
        server_id=server_id,
        name="phone",
    )
    workflow = BotWorkflow(
        repo=repo,
        admin_telegram_ids={9001},
        peer_remover=RecordingPeerRemover(error=RuntimeError("remove failed")),
    )

    try:
        workflow.revoke_user_device(
            telegram_id=1001,
            device_id=device_id,
            revoked_at="2026-05-27T12:00:00Z",
        )
    except RuntimeError as exc:
        assert "remove failed" in str(exc)
    else:
        raise AssertionError("revoke must fail when server-side peer removal fails")

    assert repo.get_device(device_id)["status"] == "active"


def test_user_can_reset_all_owned_devices(tmp_path):
    repo = _repo(tmp_path)
    user_id = repo.upsert_user(
        telegram_id=1001,
        username="alice",
        first_name="Alice",
        last_name=None,
    )
    other_user_id = repo.upsert_user(
        telegram_id=2002,
        username="bob",
        first_name="Bob",
        last_name=None,
    )
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    first_id = _create_encrypted_device(
        repo,
        user_id=user_id,
        server_id=server_id,
        name="phone",
    )
    second_id = _create_encrypted_device(
        repo,
        user_id=user_id,
        server_id=server_id,
        name="laptop",
    )
    other_id = _create_encrypted_device(
        repo,
        user_id=other_user_id,
        server_id=server_id,
        name="tablet",
    )
    workflow = BotWorkflow(repo=repo, admin_telegram_ids={9001})

    changed = workflow.reset_user_devices(
        telegram_id=1001,
        revoked_at="2026-05-27T12:00:00Z",
    )

    assert changed == 2
    assert repo.get_device(first_id)["status"] == "revoked"
    assert repo.get_device(second_id)["status"] == "revoked"
    assert repo.get_device(other_id)["status"] == "active"


def test_user_reset_removes_all_owned_peers_before_marking_devices_revoked(tmp_path):
    repo = _repo(tmp_path)
    user_id = repo.upsert_user(
        telegram_id=1001,
        username="alice",
        first_name="Alice",
        last_name=None,
    )
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    first_id = _create_encrypted_device(
        repo,
        user_id=user_id,
        server_id=server_id,
        name="phone",
    )
    second_id = _create_encrypted_device(
        repo,
        user_id=user_id,
        server_id=server_id,
        name="laptop",
    )
    peer_remover = RecordingPeerRemover()
    workflow = BotWorkflow(
        repo=repo,
        admin_telegram_ids={9001},
        peer_remover=peer_remover,
    )

    changed = workflow.reset_user_devices(
        telegram_id=1001,
        revoked_at="2026-05-27T12:00:00Z",
    )

    assert changed == 2
    assert peer_remover.calls == [
        {"server_id": server_id, "peer_public_key": "peer-phone"},
        {"server_id": server_id, "peer_public_key": "peer-laptop"},
    ]
    assert repo.get_device(first_id)["status"] == "revoked"
    assert repo.get_device(second_id)["status"] == "revoked"


def test_user_reset_reports_partial_failure_when_one_remote_remove_succeeds_and_next_fails(tmp_path):
    repo = _repo(tmp_path)
    user_id = repo.upsert_user(
        telegram_id=1001,
        username="alice",
        first_name="Alice",
        last_name=None,
    )
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    first_id = _create_encrypted_device(
        repo,
        user_id=user_id,
        server_id=server_id,
        name="phone",
    )
    second_id = _create_encrypted_device(
        repo,
        user_id=user_id,
        server_id=server_id,
        name="laptop",
    )
    peer_remover = FailingAfterFirstPeerRemover()
    workflow = BotWorkflow(
        repo=repo,
        admin_telegram_ids={9001},
        peer_remover=peer_remover,
    )
    with pytest.raises(RemoteOperationPartialFailure) as exc_info:
        workflow.reset_user_devices(
            telegram_id=1001,
            revoked_at="2026-05-27T12:00:00Z",
        )

    failure = exc_info.value.result
    assert failure.operation_id == "bot.reset_user_devices"
    assert failure.consistency_status == "partial-failure"
    assert failure.remote_applied is True
    assert failure.local_applied is False
    assert "manual review" in failure.recovery_note.lower()
    assert peer_remover.calls == [
        {"server_id": server_id, "peer_public_key": "peer-phone"}
    ]
    assert repo.get_device(first_id)["status"] == "active"
    assert repo.get_device(second_id)["status"] == "active"


def test_database_admin_role_grants_workflow_admin_access(tmp_path):
    repo = _repo(tmp_path)
    repo.upsert_user(
        telegram_id=1001,
        username="alice",
        first_name="Alice",
        last_name=None,
    )
    repo.set_user_admin(
        telegram_id=1001,
        is_admin=True,
        granted_by_admin_telegram_id=9001,
    )
    workflow = BotWorkflow(repo=repo, admin_telegram_ids={9001})

    assert workflow.is_admin(1001) is True


def test_admin_can_delegate_admin_role_by_telegram_id(tmp_path):
    repo = _repo(tmp_path)
    workflow = BotWorkflow(repo=repo, admin_telegram_ids={9001})

    granted = workflow.grant_admin(
        admin_telegram_id=9001,
        target_telegram_id=1001,
        username="alice",
        first_name="Alice",
        last_name=None,
    )
    denied = workflow.grant_admin(
        admin_telegram_id=2002,
        target_telegram_id=3003,
        username="bob",
        first_name="Bob",
        last_name=None,
    )

    assert granted is True
    assert denied is False
    assert workflow.is_admin(1001) is True
    assert workflow.is_admin(3003) is False


def test_admin_can_create_manual_access_request_for_user(tmp_path):
    repo = _repo(tmp_path)
    repo.seed_default_plans()
    workflow = BotWorkflow(repo=repo, admin_telegram_ids={9001})

    result = workflow.create_manual_access_request(
        admin_telegram_id=9001,
        target_telegram_id=1001,
        username="alice",
        first_name="Alice",
        last_name=None,
        config_version="amneziawg_v2",
        plan_id="days_30",
    )
    denied = workflow.create_manual_access_request(
        admin_telegram_id=2002,
        target_telegram_id=3003,
        username="bob",
        first_name="Bob",
        last_name=None,
        config_version="amneziawg_v2",
        plan_id="days_30",
    )

    assert result is not None
    assert result.order_id == 1
    assert "30 days" in result.text
    assert denied is None
    assert repo.list_pending_orders()[0]["telegram_id"] == 1001


def test_admin_can_list_service_users(tmp_path):
    repo = _repo(tmp_path)
    user_id = repo.upsert_user(
        telegram_id=1001,
        username="alice",
        first_name="Alice",
        last_name=None,
    )
    repo.upsert_user(
        telegram_id=2002,
        username="bob",
        first_name="Bob",
        last_name=None,
    )
    server_id = repo.ensure_default_server(name="local", network_cidr="10.8.0.0/24")
    _create_encrypted_device(
        repo,
        user_id=user_id,
        server_id=server_id,
        name="phone",
    )
    workflow = BotWorkflow(repo=repo, admin_telegram_ids={9001})

    users = workflow.list_users(admin_telegram_id=9001)
    denied = workflow.list_users(admin_telegram_id=2002)

    assert [user["telegram_id"] for user in users] == [2002, 1001]
    assert users[1]["active_device_count"] == 1
    assert denied == []


def _repo(tmp_path):
    conn = connect(tmp_path / "bot-workflows.sqlite3")
    initialize_schema(conn)
    return Repository(conn)


def _create_encrypted_device(
    repo,
    *,
    user_id,
    server_id,
    name,
    config_version="amneziawg_v2",
):
    secret_box = SecretBox.from_app_secret(SECRET)
    return repo.create_device(
        user_id=user_id,
        server_id=server_id,
        name=name,
        duration_days=30,
        vpn_ip=f"10.8.0.{user_id + len(name)}",
        peer_public_key=f"peer-{name}",
        peer_private_key_encrypted=secret_box.encrypt_text(f"private-{name}"),
        preshared_key_encrypted=secret_box.encrypt_text(f"psk-{name}"),
        config_version=config_version,
    )


class RecordingPeerRemover:
    def __init__(self, *, error=None):
        self.calls = []
        self._error = error

    def remove_peer(self, *, server, peer_public_key):
        self.calls.append(
            {
                "server_id": int(server["id"]),
                "peer_public_key": peer_public_key,
            }
        )
        if self._error is not None:
            raise self._error


class FailingAfterFirstPeerRemover:
    def __init__(self):
        self.calls = []

    def remove_peer(self, *, server, peer_public_key):
        if self.calls:
            raise PeerApplyError("remove failed after first peer")
        self.calls.append(
            {
                "server_id": int(server["id"]),
                "peer_public_key": peer_public_key,
            }
        )


class RecordingPeerApplier:
    def __init__(self, *, error=None):
        self.calls = []
        self._error = error

    def apply_peer(self, *, server, peer_public_key, preshared_key, vpn_ip):
        self.calls.append(
            {
                "server_id": int(server["id"]),
                "peer_public_key": peer_public_key,
                "preshared_key": preshared_key,
                "vpn_ip": vpn_ip,
            }
        )
        if self._error is not None:
            raise self._error


class StaticTrafficCollector:
    def __init__(self, peers):
        self._peers = peers

    def collect(self, server_id: int):
        return self._peers
