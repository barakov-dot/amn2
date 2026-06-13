from pathlib import Path

from app.services.productization_boundary import build_productization_boundary


def test_productization_boundary_keeps_commercial_access_manual_and_gated():
    boundary = build_productization_boundary()

    commercial = boundary["commercial_access"]
    assert commercial["status"] == "manual_approval_boundary_ready"
    assert commercial["payment_processor_enabled"] is False
    assert commercial["payment_processor_gate"] == "separate named payment processor gate"
    assert commercial["current_order_modes"] == ["free_test", "manual"]
    assert commercial["current_order_statuses"] == [
        "manual_review",
        "approved",
        "fulfilled",
        "rejected",
    ]
    assert commercial["automatic_entitlement_on_payment"] is False
    assert commercial["config_delivery_on_payment"] is False
    assert commercial["manual_approval_required"] is True
    assert "payment_webhook" in commercial["blocked_future_surfaces"]
    assert "automatic_vpn_entitlement" in commercial["blocked_future_surfaces"]
    assert "payment_provider_secret_storage" in commercial["blocked_future_surfaces"]


def test_productization_boundary_splits_access_support_and_news_bots():
    boundary = build_productization_boundary()

    bots = boundary["bot_runtime_split"]
    assert bots["status"] == "separate_bot_boundary_ready"
    assert bots["access_bot"]["status"] == "current_runtime"
    assert bots["access_bot"]["owns_config_delivery"] is True
    assert bots["support_bot"]["status"] == "blocked_future"
    assert bots["support_bot"]["requires_separate_token"] is True
    assert bots["support_bot"]["may_issue_configs"] is False
    assert bots["news_bot"]["status"] == "blocked_future"
    assert bots["news_bot"]["requires_separate_token"] is True
    assert bots["news_bot"]["may_touch_user_devices"] is False
    assert bots["shared_negative_controls"] == [
        "no_access_bot_token_reuse",
        "no_live_telegram_send_by_codex",
        "no_profile_icon_apply_without_P6-I005",
        "no_config_artifact_output",
        "no_production_peer_or_user_mutation",
    ]


def test_productization_boundary_doc_exists_and_records_gate_limits():
    boundary = build_productization_boundary()

    doc_path = Path(boundary["docs"]["policy_doc"])
    text = doc_path.read_text(encoding="utf-8")
    assert "payment processor" in text
    assert "support/news" in text
    assert "P6-I005" in text
    assert "VPS_APPLY_ENABLED=false" in text
