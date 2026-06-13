from __future__ import annotations

from typing import Any


def build_productization_boundary() -> dict[str, Any]:
    return {
        "status": "policy_registry_ready",
        "commercial_access": {
            "status": "manual_approval_boundary_ready",
            "payment_processor_enabled": False,
            "payment_processor_gate": "separate named payment processor gate",
            "current_order_modes": ["free_test", "manual"],
            "current_order_statuses": [
                "manual_review",
                "approved",
                "fulfilled",
                "rejected",
            ],
            "manual_approval_required": True,
            "automatic_entitlement_on_payment": False,
            "config_delivery_on_payment": False,
            "blocked_future_surfaces": [
                "payment_webhook",
                "automatic_vpn_entitlement",
                "payment_provider_secret_storage",
                "payment_dispute_or_refund_automation",
            ],
            "safe_audit_fields": [
                "order_id",
                "operator_id",
                "decision",
                "reason_code",
                "created_at",
            ],
        },
        "bot_runtime_split": {
            "status": "separate_bot_boundary_ready",
            "access_bot": {
                "status": "current_runtime",
                "owns_config_delivery": True,
                "owns_access_request_flow": True,
                "token_reuse_allowed_by_support_news": False,
            },
            "support_bot": {
                "status": "blocked_future",
                "requires_separate_token": True,
                "requires_separate_runtime": True,
                "may_issue_configs": False,
                "may_mutate_orders_or_devices": False,
                "allowed_purpose": "support intake and public-safe help only",
            },
            "news_bot": {
                "status": "blocked_future",
                "requires_separate_token": True,
                "requires_separate_runtime": True,
                "may_touch_user_devices": False,
                "may_issue_configs": False,
                "allowed_purpose": "operator-written announcements only",
            },
            "shared_negative_controls": [
                "no_access_bot_token_reuse",
                "no_live_telegram_send_by_codex",
                "no_profile_icon_apply_without_P6-I005",
                "no_config_artifact_output",
                "no_production_peer_or_user_mutation",
            ],
        },
        "telegram_profile_icon_apply": {
            "status": "identity_mutation_gate_ready",
            "telegram_api_enabled": False,
            "operator_manual_apply_allowed": False,
            "codex_apply_allowed": False,
            "requires_named_gate": "P6-I005 Telegram identity mutation gate",
            "bot_kinds": ["access", "support", "news"],
            "allowed_default_work": [
                "local image validation",
                "local registry metadata",
                "operator checklist drafting",
                "safe evidence summary",
            ],
            "blocked_without_gate": [
                "Telegram Bot API setMyProfilePhoto",
                "Telegram Bot API deleteMyProfilePhoto",
                "BotFather/manual profile mutation by Codex",
                "live bot send",
                "Telegram token use",
            ],
            "safe_evidence_fields": [
                "bot_kind",
                "asset_id",
                "content_sha256",
                "mime_type",
                "width_px",
                "height_px",
                "byte_size",
                "operator_decision",
            ],
        },
        "docs": {
            "policy_doc": "docs/COMMERCIAL_AND_BOT_PRODUCTIZATION_BOUNDARY.ru.md",
        },
    }
