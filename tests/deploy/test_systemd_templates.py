from pathlib import Path


def test_bot_systemd_template_uses_cli_module_and_project_paths():
    text = Path("deploy/systemd/amneziya-bot.service.example").read_text(
        encoding="utf-8"
    )

    assert "WorkingDirectory=/opt/amn2" in text
    assert "EnvironmentFile=/opt/amn2/.env" in text
    assert "ExecStart=/opt/amn2/venv/bin/python -m app.main" in text
    assert "Restart=on-failure" in text
    assert "User=amneziya" in text
    for required in (
        "Type=notify",
        "NotifyAccess=main",
        "WatchdogSec=60s",
        "TimeoutStartSec=135s",
        "TimeoutStopSec=30s",
        "RuntimeDirectory=amn2-bot",
        "RuntimeDirectoryMode=0750",
        "StartLimitIntervalSec=300s",
        "StartLimitBurst=3",
        "RestartSec=30s",
        "UMask=0077",
        "NoNewPrivileges=true",
        "PrivateTmp=true",
        "PrivateDevices=true",
        "ProtectSystem=strict",
        "ProtectHome=true",
        "ProtectKernelTunables=true",
        "ProtectKernelModules=true",
        "ProtectKernelLogs=true",
        "ProtectControlGroups=true",
        "ProtectHostname=true",
        "ProtectClock=true",
        "RestrictSUIDSGID=true",
        "RestrictRealtime=true",
        "LockPersonality=true",
        "MemoryDenyWriteExecute=true",
        "RestrictNamespaces=true",
        "SystemCallArchitectures=native",
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
        "CapabilityBoundingSet=",
        "AmbientCapabilities=",
        (
            "ReadWritePaths=/opt/amn2/data /opt/amn2/logs "
            "/opt/amn2/backups /opt/amn2/config_templates"
        ),
    ):
        assert required in text

    for forbidden in (
        "systemctl enable",
        "systemctl start",
        "systemctl restart",
        "awg-quick",
        "IPAddressDeny=any",
        "ReadWritePaths=/opt/amn2\n",
    ):
        assert forbidden not in text


def test_web_systemd_template_uses_web_cli_loopback_bind_and_port_3030():
    text = Path("deploy/systemd/amneziya-web.service.example").read_text(
        encoding="utf-8"
    )

    assert "WorkingDirectory=/opt/amn2" in text
    assert "EnvironmentFile=/opt/amn2/.env" in text
    assert (
        "ExecStart=/opt/amn2/venv/bin/python -m app.cli web serve "
        "--host 127.0.0.1 --port 3030"
    ) in text
    assert "--host 0.0.0.0" not in text
    assert "Restart=on-failure" in text
    assert "User=amneziya" in text
