import pytest

from app.server.operation_runner import RemoteOperationRunner
from app.server.operations import (
    CommandStep,
    OperationValidationError,
    RemoteOperation,
    validate_operation,
)
from app.server.ssh import CommandResult


def test_validate_operation_allows_read_only_remote_steps():
    operation = RemoteOperation(
        id="server.health.check",
        risk_class="read-only-remote",
        server_id="debian-vps-1",
        actor_id="web-admin",
        actor_auth_method="session",
        inputs={"server_name": "debian-vps-1"},
        secret_refs=(),
        local_side_effects=("server_health_checks", "admin_actions"),
        remote_side_effects=(),
        command_policy="read-only",
        steps=(
            CommandStep(
                id="os-release",
                command="cat /etc/os-release",
                command_policy_class="read-only",
                expected_remote_effect="none",
                allowed_exit_codes=(0,),
                timeout_seconds=20,
                output_policy="internal-only",
            ),
        ),
        consistency_policy="read-only",
        audit_summary="Run read-only server health check",
        rollback_note="No rollback is needed for read-only health checks.",
        confirmation_required=False,
    )

    validate_operation(operation)
    assert operation.consistency_status == "read-only"


def _state_changing_operation(
    *,
    rollback_note: str = "Remove the peer remotely and mark local device pending review.",
    remote_side_effects: tuple[str, ...] = ("awg-peer-add", "service-reload"),
    idempotency_key: str | None = "server.peer.apply:1:7",
    consistency_status: str = "pending-remote",
) -> RemoteOperation:
    return RemoteOperation(
        id="server.peer.apply",
        risk_class="remote-state-write",
        server_id="debian-vps-1",
        actor_id="web-admin",
        actor_auth_method="session",
        inputs={
            "server_id": "1",
            "device_id": "7",
            "public_key_ref": "peer-public-key",
        },
        secret_refs=("device.preshared_key",),
        local_side_effects=("device-create", "admin-audit"),
        remote_side_effects=remote_side_effects,
        command_policy="state-write",
        steps=(
            CommandStep(
                id="apply-peer",
                command="awg set awg0 peer PEER_PUBLIC_KEY allowed-ips 10.8.0.7/32",
                command_policy_class="state-write",
                expected_remote_effect="add awg peer",
                allowed_exit_codes=(0,),
                timeout_seconds=30,
                output_policy="redact-and-store",
                stdin_secret_ref="device.preshared_key",
            ),
        ),
        consistency_policy="remote-first",
        consistency_status=consistency_status,
        audit_summary="Apply peer to server",
        rollback_note=rollback_note,
        confirmation_required=True,
        idempotency_key=idempotency_key,
    )


def test_validate_operation_allows_state_changing_operation_metadata():
    operation = _state_changing_operation()

    validate_operation(operation)

    assert operation.consistency_status == "pending-remote"
    assert operation.rollback_note.startswith("Remove the peer remotely")
    assert operation.local_side_effects == ("device-create", "admin-audit")
    assert operation.remote_side_effects == ("awg-peer-add", "service-reload")
    assert operation.idempotency_key == "server.peer.apply:1:7"


def test_validate_operation_rejects_state_changing_operation_without_recovery_metadata():
    operation = _state_changing_operation(rollback_note="", idempotency_key=None)

    with pytest.raises(OperationValidationError, match="recovery metadata"):
        validate_operation(operation)


def test_validate_operation_rejects_state_changing_operation_without_remote_side_effects():
    operation = _state_changing_operation(remote_side_effects=())

    with pytest.raises(OperationValidationError, match="remote side effect"):
        validate_operation(operation)


@pytest.mark.parametrize(
    "key",
    ["password", "private_key", "token", "preshared_key", "client_config"],
)
def test_validate_operation_rejects_secret_like_inputs(key):
    operation = RemoteOperation(
        id="server.health.check",
        risk_class="read-only-remote",
        server_id="debian-vps-1",
        actor_id="cli",
        actor_auth_method="cli",
        inputs={key: "secret-value"},
        secret_refs=(),
        local_side_effects=(),
        remote_side_effects=(),
        command_policy="read-only",
        steps=(),
        consistency_policy="read-only",
        audit_summary="Run read-only server health check",
        rollback_note="No rollback is needed for read-only health checks.",
        confirmation_required=False,
    )

    with pytest.raises(OperationValidationError, match="secret-like input"):
        validate_operation(operation)


class RecordingSshClient:
    def __init__(self, *, results=None):
        self.calls = []
        self._results = results or {}

    def run(self, command: str, stdin: str | None = None) -> CommandResult:
        self.calls.append((command, stdin))
        return self._results.get(command, CommandResult(exit_code=0, stdout="ok", stderr=""))


def _read_only_operation(command: str = "cat /etc/os-release") -> RemoteOperation:
    return RemoteOperation(
        id="server.health.check",
        risk_class="read-only-remote",
        server_id="debian-vps-1",
        actor_id="cli",
        actor_auth_method="cli",
        inputs={"server_name": "debian-vps-1"},
        secret_refs=(),
        local_side_effects=(),
        remote_side_effects=(),
        command_policy="read-only",
        steps=(
            CommandStep(
                id="step-1",
                command=command,
                command_policy_class="read-only",
                expected_remote_effect="none",
                allowed_exit_codes=(0,),
                timeout_seconds=20,
                output_policy="internal-only",
            ),
        ),
        consistency_policy="read-only",
        audit_summary="Run read-only server health check",
        rollback_note="No rollback is needed for read-only health checks.",
        confirmation_required=False,
    )


def test_runner_builds_plan_without_executing_ssh():
    ssh = RecordingSshClient()
    runner = RemoteOperationRunner(ssh)

    plan = runner.plan(_read_only_operation())

    assert plan.operation_id == "server.health.check"
    assert plan.risk_class == "read-only-remote"
    assert plan.commands == ("cat /etc/os-release",)
    assert ssh.calls == []


def test_runner_plan_includes_state_changing_metadata_without_executing_ssh():
    ssh = RecordingSshClient()
    runner = RemoteOperationRunner(ssh)

    plan = runner.plan(_state_changing_operation())

    assert plan.operation_id == "server.peer.apply"
    assert plan.risk_class == "remote-state-write"
    assert plan.consistency_status == "pending-remote"
    assert plan.local_side_effects == ("device-create", "admin-audit")
    assert plan.remote_side_effects == ("awg-peer-add", "service-reload")
    assert plan.idempotency_key == "server.peer.apply:1:7"
    assert ssh.calls == []


def test_runner_executes_read_only_operation():
    ssh = RecordingSshClient(
        results={
            "cat /etc/os-release": CommandResult(
                exit_code=0,
                stdout="ID=debian\n",
                stderr="",
            )
        }
    )
    runner = RemoteOperationRunner(ssh)

    result = runner.apply(_read_only_operation())

    assert result.status == "completed"
    assert result.consistency_status == "read-only"
    assert result.steps[0].stdout == "ID=debian\n"
    assert ssh.calls == [("cat /etc/os-release", None)]


def test_runner_continues_read_only_operation_after_failed_step():
    operation = RemoteOperation(
        id="server.health.check",
        risk_class="read-only-remote",
        server_id="debian-vps-1",
        actor_id="cli",
        actor_auth_method="cli",
        inputs={"server_name": "debian-vps-1"},
        secret_refs=(),
        local_side_effects=(),
        remote_side_effects=(),
        command_policy="read-only",
        steps=(
            CommandStep(
                id="missing-awg",
                command="command -v awg",
                command_policy_class="read-only",
                expected_remote_effect="none",
                allowed_exit_codes=(0,),
                timeout_seconds=20,
                output_policy="internal-only",
            ),
            CommandStep(
                id="udp-sockets",
                command="ss -lun",
                command_policy_class="read-only",
                expected_remote_effect="none",
                allowed_exit_codes=(0,),
                timeout_seconds=20,
                output_policy="internal-only",
            ),
        ),
        consistency_policy="read-only",
        audit_summary="Run read-only server health check",
        rollback_note="No rollback is needed for read-only health checks.",
        confirmation_required=False,
    )
    ssh = RecordingSshClient(
        results={
            "command -v awg": CommandResult(exit_code=1, stdout="", stderr="not found"),
            "ss -lun": CommandResult(exit_code=0, stdout="udp sockets\n", stderr=""),
        }
    )

    result = RemoteOperationRunner(ssh).apply(operation)

    assert result.status == "failed"
    assert [step.step_id for step in result.steps] == ["missing-awg", "udp-sockets"]
    assert ssh.calls == [("command -v awg", None), ("ss -lun", None)]


def test_runner_blocks_mutating_command_before_ssh():
    ssh = RecordingSshClient()
    runner = RemoteOperationRunner(ssh)

    result = runner.apply(_read_only_operation("systemctl restart awg-quick@awg0"))

    assert result.status == "blocked"
    assert (
        "not in the read-only allowlist" in result.recovery_note
        or "Mutating command" in result.recovery_note
    )
    assert ssh.calls == []
