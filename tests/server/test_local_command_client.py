import subprocess

from app.server.ssh import LocalCommandClient


def test_local_command_client_runs_trusted_command_with_stdin(monkeypatch):
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout="ok",
            stderr="",
        )

    monkeypatch.setattr("app.server.ssh.subprocess.run", fake_run)

    result = LocalCommandClient(timeout_seconds=7).run(
        "docker exec -i amnezia-awg cat",
        stdin="config",
    )

    assert result.exit_code == 0
    assert result.stdout == "ok"
    assert calls[0][0] == "docker exec -i amnezia-awg cat"
    assert calls[0][1]["shell"] is True
    assert calls[0][1]["input"] == "config"
    assert calls[0][1]["timeout"] == 7


def test_local_command_client_reports_timeout(monkeypatch):
    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=3)

    monkeypatch.setattr("app.server.ssh.subprocess.run", fake_run)

    result = LocalCommandClient(timeout_seconds=3).run("docker restart amnezia-awg")

    assert result.exit_code == 124
    assert result.stdout == ""
    assert "timed out" in result.stderr
