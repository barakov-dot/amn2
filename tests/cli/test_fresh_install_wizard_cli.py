import json
from pathlib import Path

from app.cli import build_parser
from app.cli import run_fresh_install_plan


def test_cli_accepts_install_wizard_and_plan_commands():
    parser = build_parser()

    wizard = parser.parse_args(["install", "wizard", "--pretty"])
    plan = parser.parse_args(
        ["install", "plan", "--answers", "fresh-install-answers.json", "--pretty"]
    )

    assert wizard.command == "install"
    assert wizard.install_command == "wizard"
    assert wizard.pretty is True
    assert plan.command == "install"
    assert plan.install_command == "plan"
    assert plan.answers == "fresh-install-answers.json"
    assert plan.pretty is True


def test_run_fresh_install_plan_reads_answers_file_and_outputs_safe_plan(tmp_path: Path):
    answers_path = tmp_path / "answers.json"
    answers_path.write_text(
        json.dumps(
            {
                "project_name": "Neobyatnaya AMNZ",
                "server_name": "local",
                "runtime": "docker",
                "vpn_protocol": "amneziawg",
                "public_exposure": "no",
                "config_delivery": "no",
                "write_api": "no",
                "destructive_cleanup": "no",
                "telegram_bot": "operator_local",
                "secret_handoff": "operator_local",
            }
        ),
        encoding="utf-8",
    )

    payload = json.loads(run_fresh_install_plan(answers_path=answers_path, pretty=True))

    assert payload["status"] == "fresh_install_wizard_ready"
    assert payload["mode"] == "local_only_dry_run"
    assert payload["operator_inputs"]["project_name"] == "Neobyatnaya AMNZ"
    assert payload["safety"]["live_vps_commands_enabled"] is False
    assert payload["safety"]["vps_apply_enabled_default"] is False
    assert "telegram_bot_token" not in json.dumps(payload, ensure_ascii=False)
