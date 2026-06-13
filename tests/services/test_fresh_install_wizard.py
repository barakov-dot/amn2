import json

import pytest

from app.services.fresh_install_wizard import (
    DEFAULT_FRESH_INSTALL_ANSWERS,
    build_fresh_install_plan,
    collect_fresh_install_answers,
)


def test_build_fresh_install_plan_is_local_only_and_secret_free():
    answers = {
        **DEFAULT_FRESH_INSTALL_ANSWERS,
        "project_name": "Neobyatnaya AMNZ",
        "server_name": "local",
        "runtime": "docker",
        "vpn_protocol": "amneziawg",
        "telegram_bot": "operator_local",
        "secret_handoff": "operator_local",
    }

    plan = build_fresh_install_plan(answers)

    assert plan["status"] == "fresh_install_wizard_ready"
    assert plan["mode"] == "local_only_dry_run"
    assert plan["safety"]["live_vps_commands_enabled"] is False
    assert plan["safety"]["destructive_cleanup_enabled"] is False
    assert plan["safety"]["public_exposure_enabled"] is False
    assert plan["safety"]["config_delivery_enabled"] is False
    assert plan["safety"]["write_api_enabled"] is False
    assert plan["safety"]["vps_apply_enabled_default"] is False
    assert "python -m app.toolchain check" in plan["local_dry_run_steps"]
    assert "python -m app.cli install plan --answers fresh-install-answers.json --pretty" in plan[
        "local_dry_run_steps"
    ]
    assert plan["operator_inputs"]["telegram_bot"] == "operator_local"
    assert plan["operator_inputs"]["secret_handoff"] == "operator_local"

    plan_text = json.dumps(plan, ensure_ascii=False)
    forbidden = (
        "ssh ",
        "rm -",
        "systemctl restart",
        "docker restart",
        "VPS_APPLY_ENABLED=true",
        "PrivateKey",
        "PresharedKey",
        "vpn://",
        ".conf",
        "telegram_bot_token",
    )
    for marker in forbidden:
        assert marker not in plan_text


def test_build_fresh_install_plan_turns_gated_yes_answers_into_stop_lines():
    answers = {
        **DEFAULT_FRESH_INSTALL_ANSWERS,
        "project_name": "Neobyatnaya AMNZ",
        "server_name": "local",
        "public_exposure": "yes",
        "config_delivery": "yes",
        "write_api": "yes",
        "destructive_cleanup": "yes",
    }

    plan = build_fresh_install_plan(answers)

    assert plan["status"] == "blocked_named_gate_required"
    assert plan["mode"] == "local_only_dry_run"
    assert plan["safety"]["live_vps_commands_enabled"] is False
    assert plan["stop_lines"] == [
        "P6-C001 required before public exposure",
        "P6-C002 required before config delivery",
        "P6-C003 required before write API",
        "P6-C007 required before destructive cleanup/reinstall",
    ]


def test_collect_fresh_install_answers_uses_defaults_for_blank_answers():
    prompts: list[str] = []
    provided = iter(
        [
            "Neobyatnaya AMNZ",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
        ]
    )

    answers = collect_fresh_install_answers(
        input_fn=lambda prompt: prompts.append(prompt) or next(provided)
    )

    assert answers["project_name"] == "Neobyatnaya AMNZ"
    assert answers["server_name"] == DEFAULT_FRESH_INSTALL_ANSWERS["server_name"]
    assert answers["runtime"] == DEFAULT_FRESH_INSTALL_ANSWERS["runtime"]
    assert answers["public_exposure"] == "no"
    assert answers["destructive_cleanup"] == "no"
    assert len(prompts) == len(DEFAULT_FRESH_INSTALL_ANSWERS)


def test_fresh_install_plan_rejects_unsafe_or_blank_answers():
    with pytest.raises(ValueError, match="project_name cannot be blank"):
        build_fresh_install_plan({**DEFAULT_FRESH_INSTALL_ANSWERS, "project_name": ""})

    with pytest.raises(ValueError, match="invalid runtime"):
        build_fresh_install_plan(
            {
                **DEFAULT_FRESH_INSTALL_ANSWERS,
                "project_name": "Neobyatnaya AMNZ",
                "runtime": "kubernetes",
            }
        )
