import sys

import pytest

from app import cli
from app.cli import build_parser


def test_admin_slot_commands_are_dry_run_by_default():
    assign = build_parser().parse_args(
        [
            "admin-config",
            "assign-slot",
            "--request-id",
            "assign-001",
            "--device-id",
            "7",
            "--device-label",
            "Pixel 8",
            "--platform",
            "android",
        ]
    )
    disable = build_parser().parse_args(
        [
            "admin-config",
            "disable-slot",
            "--server",
            "Spain-Madrid",
            "--device-id",
            "7",
            "--reason",
            "operator disabled",
        ]
    )

    assert assign.apply is False
    assert disable.apply is False


def test_admin_slot_apply_checks_exact_live_gate_before_settings(monkeypatch):
    calls = []

    def stop_at_gate():
        calls.append(True)
        raise SystemExit("slot gate closed")

    monkeypatch.setattr(cli, "require_vps_apply_enabled_for_cli_apply", stop_at_gate)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "amneziya",
            "admin-config",
            "assign-slot",
            "--request-id",
            "assign-001",
            "--device-id",
            "7",
            "--device-label",
            "Pixel 8",
            "--platform",
            "android",
            "--admin-telegram-id",
            "7001",
            "--apply",
        ],
    )

    with pytest.raises(SystemExit, match="slot gate closed"):
        cli.main()
    assert calls == [True]
