from dataclasses import dataclass
import os
from pathlib import Path
import subprocess
from typing import Protocol

from app.server_config.models import ServerConfig


@dataclass(frozen=True)
class CommandResult:
    exit_code: int
    stdout: str
    stderr: str


class SshClient(Protocol):
    def run(self, command: str, stdin: str | None = None) -> CommandResult:
        pass


class LocalCommandClient:
    def __init__(self, *, timeout_seconds: int = 20) -> None:
        self._timeout_seconds = timeout_seconds

    def run(self, command: str, stdin: str | None = None) -> CommandResult:
        try:
            completed = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                check=False,
                input=stdin,
                text=True,
                timeout=self._timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            return CommandResult(
                exit_code=124,
                stdout="",
                stderr=f"local command timed out after {self._timeout_seconds} seconds",
            )
        return CommandResult(
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )


class SystemSshClient:
    def __init__(
        self,
        server: ServerConfig,
        *,
        timeout_seconds: int = 20,
        password: str | None = None,
    ) -> None:
        self._server = server
        self._timeout_seconds = timeout_seconds
        self._password = password

    def run(self, command: str, stdin: str | None = None) -> CommandResult:
        if self._server.ssh.auth.type == "password":
            return self._run_with_password_auth(command, stdin=stdin)
        return self._run_with_key_auth(command, stdin=stdin)

    def _run_with_key_auth(self, command: str, stdin: str | None) -> CommandResult:
        args = [
            "ssh",
            "-p",
            str(self._server.ssh.port),
            "-o",
            "BatchMode=yes",
            "-o",
            f"ConnectTimeout={self._timeout_seconds}",
        ]
        if self._server.ssh.auth.private_key_path:
            args.extend(["-i", self._server.ssh.auth.private_key_path])
        args.extend([f"{self._server.ssh.user}@{self._server.ssh.host}", command])
        try:
            completed = subprocess.run(
                args,
                capture_output=True,
                check=False,
                input=stdin,
                text=True,
                timeout=self._timeout_seconds,
            )
        except FileNotFoundError:
            return CommandResult(
                exit_code=127,
                stdout="",
                stderr="ssh executable was not found in PATH",
            )
        except subprocess.TimeoutExpired:
            return CommandResult(
                exit_code=124,
                stdout="",
                stderr=f"ssh command timed out after {self._timeout_seconds} seconds",
            )
        return CommandResult(
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )

    def _run_with_password_auth(self, command: str, stdin: str | None) -> CommandResult:
        password = self._password_auth_value()
        if not password:
            return CommandResult(
                exit_code=125,
                stdout="",
                stderr=(
                    "Password auth is configured, but VPS_SSH_PASSWORD is not set. "
                    "Set VPS_SSH_PASSWORD in the process environment or .env, "
                    "or switch servers.yml to SSH key auth."
                ),
            )
        args = [
            "sshpass",
            "-e",
            "ssh",
            "-p",
            str(self._server.ssh.port),
            "-o",
            f"ConnectTimeout={self._timeout_seconds}",
            "-o",
            "PreferredAuthentications=password",
            "-o",
            "PubkeyAuthentication=no",
            "-o",
            "StrictHostKeyChecking=accept-new",
            f"{self._server.ssh.user}@{self._server.ssh.host}",
            command,
        ]
        env = {**os.environ, "SSHPASS": password}
        try:
            completed = subprocess.run(
                args,
                capture_output=True,
                check=False,
                input=stdin,
                text=True,
                timeout=self._timeout_seconds,
                env=env,
            )
        except FileNotFoundError:
            return CommandResult(
                exit_code=127,
                stdout="",
                stderr="sshpass executable was not found in PATH; install sshpass or use SSH key auth.",
            )
        except subprocess.TimeoutExpired:
            return CommandResult(
                exit_code=124,
                stdout="",
                stderr=f"ssh command timed out after {self._timeout_seconds} seconds",
            )
        return CommandResult(
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr.replace(password, "[REDACTED]"),
        )

    def _password_auth_value(self) -> str:
        if self._password is not None:
            return self._password.strip()
        value = os.environ.get("VPS_SSH_PASSWORD", "").strip()
        if value:
            return value
        return _read_dotenv_value("VPS_SSH_PASSWORD")


def _read_dotenv_value(key: str, *, path: Path = Path(".env")) -> str:
    if not path.is_file():
        return ""
    prefix = f"{key}="
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return ""
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or not stripped.startswith(prefix):
            continue
        value = stripped[len(prefix):].strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        return value.strip()
    return ""
