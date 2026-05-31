from __future__ import annotations

from app.security.redaction import redact
from app.server.checks import CommandPolicyError, ensure_read_only_command
from app.server.operations import (
    OperationPlan,
    OperationResult,
    RemoteOperation,
    StepExecutionResult,
    is_state_changing_risk_class,
    validate_operation,
)
from app.server.ssh import SshClient


class RemoteOperationRunner:
    def __init__(self, ssh_client: SshClient) -> None:
        self._ssh_client = ssh_client

    def plan(self, operation: RemoteOperation) -> OperationPlan:
        validate_operation(operation)
        consistency_status = (
            "dry-run"
            if is_state_changing_risk_class(operation.risk_class)
            else operation.consistency_status
        )
        return OperationPlan(
            operation_id=operation.id,
            risk_class=operation.risk_class,
            consistency_status=consistency_status,
            commands=tuple(step.command for step in operation.steps),
            audit_summary=operation.audit_summary,
            rollback_note=operation.rollback_note,
            local_side_effects=operation.local_side_effects,
            remote_side_effects=operation.remote_side_effects,
            idempotency_key=operation.idempotency_key,
        )

    def apply(self, operation: RemoteOperation) -> OperationResult:
        try:
            validate_operation(operation)
            if operation.risk_class != "read-only-remote":
                return _blocked(operation, "First runner slice only supports read-only-remote operations.")
            step_results: list[StepExecutionResult] = []
            for step in operation.steps:
                try:
                    ensure_read_only_command(step.command)
                except CommandPolicyError as exc:
                    return _blocked(operation, str(exc))
                result = self._ssh_client.run(step.command)
                status = "succeeded" if result.exit_code in step.allowed_exit_codes else "failed"
                step_results.append(
                    StepExecutionResult(
                        step_id=step.id,
                        command=step.command,
                        exit_code=result.exit_code,
                        stdout=result.stdout,
                        stderr=result.stderr,
                        status=status,
                    )
                )
            operation_status = (
                "failed" if any(step.status == "failed" for step in step_results) else "completed"
            )
            return OperationResult(
                operation_id=operation.id,
                risk_class=operation.risk_class,
                status=operation_status,
                consistency_status="read-only",
                steps=tuple(step_results),
                redacted_stdout_summary=_combined_summary(step.stdout for step in step_results),
                redacted_stderr_summary=_combined_summary(step.stderr for step in step_results),
                recovery_note=operation.rollback_note,
            )
        except Exception as exc:
            return OperationResult(
                operation_id=operation.id,
                risk_class=operation.risk_class,
                status="failed",
                consistency_status="unknown",
                steps=(),
                redacted_stdout_summary="empty",
                redacted_stderr_summary="empty",
                recovery_note=redact(
                    f"Remote operation failed before completion: {type(exc).__name__}: {exc}"
                ),
            )


def _blocked(operation: RemoteOperation, reason: str) -> OperationResult:
    return OperationResult(
        operation_id=operation.id,
        risk_class=operation.risk_class,
        status="blocked",
        consistency_status="read-only",
        steps=(),
        redacted_stdout_summary="empty",
        redacted_stderr_summary="empty",
        recovery_note=redact(reason),
    )


def _combined_summary(values) -> str:
    return "present" if any(values) else "empty"
