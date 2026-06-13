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


def test_productization_boundary_records_tokenized_config_link_boundary():
    boundary = build_productization_boundary()

    config_link = boundary["config_delivery_link_boundary"]
    assert config_link["status"] == "tokenized_link_boundary_ready"
    assert config_link["short_link_runtime_enabled"] is False
    assert config_link["config_delivery_enabled"] is False
    assert config_link["requires_named_gate"] == "P6-C002 Config delivery gate"
    assert config_link["token_model"]["token_material"] == "opaque_random_token"
    assert config_link["token_model"]["storage"] == "hash_at_rest_only"
    assert config_link["token_model"]["one_time_use"] is True
    assert config_link["token_model"]["ttl_minutes"] == 15
    assert config_link["token_model"]["purpose_binding"] == "config_delivery_only"
    assert config_link["telegram_copy_ux"]["copy_text_limit"] == 256
    assert config_link["telegram_copy_ux"]["copy_short_link_only_after_gate"] is True
    assert "vpn_import_link" in config_link["blocked_secret_outputs"]
    assert "qr_code" in config_link["blocked_secret_outputs"]


def test_productization_boundary_records_entitlement_audit_without_auto_access():
    boundary = build_productization_boundary()

    entitlement = boundary["commercial_entitlement_audit"]
    assert entitlement["status"] == "entitlement_audit_boundary_ready"
    assert entitlement["payment_provider_enabled"] is False
    assert entitlement["automatic_activation_enabled"] is False
    assert entitlement["config_delivery_decoupled"] is True
    assert entitlement["manual_review_required"] is True
    assert entitlement["safe_audit_fields"] == [
        "entitlement_id",
        "order_id",
        "operator_id",
        "decision",
        "reason_code",
        "created_at",
    ]
    assert "raw_payment_payload" in entitlement["forbidden_audit_fields"]
    assert "vpn_import_link" in entitlement["forbidden_audit_fields"]
    assert "telegram_id" in entitlement["forbidden_audit_fields"]


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


def test_productization_boundary_records_profile_icon_apply_gates():
    boundary = build_productization_boundary()

    gates = boundary["telegram_profile_icon_apply"]
    assert gates["status"] == "identity_mutation_gate_ready"
    assert gates["telegram_api_enabled"] is False
    assert gates["operator_manual_apply_allowed"] is False
    assert gates["codex_apply_allowed"] is False
    assert gates["requires_named_gate"] == "P6-I005 Telegram identity mutation gate"
    assert gates["bot_kinds"] == ["access", "support", "news"]
    assert gates["allowed_default_work"] == [
        "local image validation",
        "local registry metadata",
        "operator checklist drafting",
        "safe evidence summary",
    ]
    assert gates["blocked_without_gate"] == [
        "Telegram Bot API setMyProfilePhoto",
        "Telegram Bot API deleteMyProfilePhoto",
        "BotFather/manual profile mutation by Codex",
        "live bot send",
        "Telegram token use",
    ]
    assert gates["safe_evidence_fields"] == [
        "bot_kind",
        "asset_id",
        "content_sha256",
        "mime_type",
        "width_px",
        "height_px",
        "byte_size",
        "operator_decision",
    ]


def test_productization_boundary_doc_exists_and_records_gate_limits():
    boundary = build_productization_boundary()

    doc_path = Path(boundary["docs"]["policy_doc"])
    text = doc_path.read_text(encoding="utf-8")
    assert "payment processor" in text
    assert "tokenized config link" in text
    assert "entitlement audit" in text
    assert "support/news" in text
    assert "P6-C002" in text
    assert "P6-I006" in text
    assert "P6-I005" in text
    assert "VPS_APPLY_ENABLED=false" in text
