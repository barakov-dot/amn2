from pathlib import Path
import json

from app.services.public_productization_boundaries import (
    build_destructive_cleanup_gate_checklist,
    build_public_docs_api_taxonomy_boundary,
)


def test_public_docs_api_taxonomy_is_ready_without_publication_or_public_api():
    boundary = build_public_docs_api_taxonomy_boundary()

    assert boundary["status"] == "public_docs_api_taxonomy_ready"
    assert boundary["publication_enabled"] is False
    assert boundary["public_openapi_enabled"] is False
    assert boundary["public_api_exposed"] is False
    assert boundary["requires_public_exposure_gate"] == "P6-C001 Public exposure gate"
    assert boundary["taxonomy"]["public_safe"] == [
        "product_overview",
        "client_compatibility_guidance",
        "operator_only_status_summary",
        "support_intake_copy",
    ]
    assert "config_delivery" in boundary["taxonomy"]["blocked_secret_bearing"]
    assert "client_write_crud" in boundary["taxonomy"]["blocked_write"]
    assert boundary["docs"]["taxonomy_doc"] == "docs/PUBLIC_DOCS_API_TAXONOMY.ru.md"

    text = json.dumps(boundary, ensure_ascii=False)
    for marker in ("PrivateKey", "PresharedKey", "vpn://", ".conf", "Authorization"):
        assert marker not in text


def test_destructive_cleanup_gate_checklist_is_checklist_only():
    checklist = build_destructive_cleanup_gate_checklist()

    assert checklist["status"] == "destructive_cleanup_checklist_ready"
    assert checklist["mode"] == "checklist_only"
    assert checklist["destructive_execution_enabled"] is False
    assert checklist["cleanup_commands_enabled"] is False
    assert checklist["requires_named_gate"] == "P6-C007 Destructive cleanup/reinstall gate"
    assert checklist["target_reference"] == "operator_named_validation_vps"
    assert checklist["required_preconditions"] == [
        "operator opens P6-C007 by name",
        "retention and data-loss decision recorded",
        "latest AMN2 head and package choice recorded",
        "rollback or rebuild stop criteria recorded",
        "operator-local secret handoff ready",
        "second confirmation before any destructive action",
    ]
    assert "provider rebuild" in checklist["blocked_actions_without_gate"]
    assert "disk wipe" in checklist["blocked_actions_without_gate"]
    assert checklist["docs"]["checklist_doc"] == "docs/DESTRUCTIVE_CLEANUP_GATE_CHECKLIST.ru.md"

    text = json.dumps(checklist, ensure_ascii=False)
    for marker in ("rm -", "format", "wipe command", "PrivateKey", "PresharedKey"):
        assert marker not in text


def test_public_taxonomy_and_destructive_checklist_docs_exist():
    taxonomy = build_public_docs_api_taxonomy_boundary()
    checklist = build_destructive_cleanup_gate_checklist()

    taxonomy_text = Path(taxonomy["docs"]["taxonomy_doc"]).read_text(encoding="utf-8")
    checklist_text = Path(checklist["docs"]["checklist_doc"]).read_text(encoding="utf-8")

    assert "P6-N001" in taxonomy_text
    assert "publication_enabled=false" in taxonomy_text
    assert "public_api_exposed=false" in taxonomy_text
    assert "P6-C007" in checklist_text
    assert "destructive_execution_enabled=false" in checklist_text
    assert "checklist-only" in checklist_text
