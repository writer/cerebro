from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


ROLE_ARN_RE = re.compile(r"^arn:(aws|aws-us-gov|aws-cn):iam::(?P<account>[0-9]{12}):role/(?P<name>[A-Za-z0-9+=,.@_/-]+)$")


@dataclass(frozen=True)
class CerebroTaskRoleArns:
    task_role_arn: str
    worker_task_role_arn: str | None = None

    def as_principals(self) -> list[str]:
        principals = [self.task_role_arn]
        if self.worker_task_role_arn:
            principals.append(self.worker_task_role_arn)
        return principals


def environment_name_for_stack(stack: str, config: dict[str, Any]) -> str:
    """Return the Pulumi environment name used in ECS task-role names.

    Existing deployed stacks may not yet expose task-role outputs. The fallback
    intentionally mirrors infra/aws/__main__.py naming so consumers can derive
    the exact role ARNs until those outputs are present in the stack state.
    """
    configured = str(config.get("environment") or "").strip()
    if configured:
        return configured
    if stack == "go-prod":
        return "go-production"
    if stack.startswith("go-"):
        return stack.replace("-prod", "-production")
    return "production"


def derive_task_role_arns(stack: str, config: dict[str, Any], account_id: str) -> CerebroTaskRoleArns:
    account_id = str(account_id).strip()
    if not re.fullmatch(r"[0-9]{12}", account_id):
        raise ValueError(f"account_id must be a 12-digit AWS account id for stack {stack!r}")
    environment = environment_name_for_stack(stack, config)
    if not environment:
        raise ValueError(f"cannot derive Cerebro task role names for stack {stack!r}: environment is empty")
    role_prefix = f"cerebro-{environment}"
    worker_role_arn = None
    if config.get("orchestratorEnabled", True):
        worker_role_arn = f"arn:aws:iam::{account_id}:role/{role_prefix}-worker-task-role"
    return CerebroTaskRoleArns(
        task_role_arn=f"arn:aws:iam::{account_id}:role/{role_prefix}-task-role",
        worker_task_role_arn=worker_role_arn,
    )


def resolve_task_role_arns(
    stack: str,
    config: dict[str, Any],
    account_id: str,
    outputs: dict[str, Any] | None = None,
) -> CerebroTaskRoleArns:
    """Resolve Cerebro ECS task-role ARNs from Pulumi outputs or fallback names.

    If Pulumi outputs are provided, any present task-role output must match the
    deterministic fallback. Missing outputs are allowed for existing stacks and
    fall back to the derived names; blank or mismatched outputs fail closed.
    """
    derived = derive_task_role_arns(stack, config, account_id)
    if outputs is None:
        return derived

    task_role_arn = _validated_output_or_fallback(
        outputs,
        "task_role_arn",
        derived.task_role_arn,
        stack,
    )
    worker_task_role_arn = derived.worker_task_role_arn
    if "worker_task_role_arn" in outputs:
        if worker_task_role_arn is None:
            raise ValueError(f"Pulumi output worker_task_role_arn is set for stack {stack!r}, but orchestrator worker role is disabled")
        worker_task_role_arn = _validated_output_or_fallback(
            outputs,
            "worker_task_role_arn",
            worker_task_role_arn,
            stack,
        )
    return CerebroTaskRoleArns(task_role_arn=task_role_arn, worker_task_role_arn=worker_task_role_arn)


def _validated_output_or_fallback(outputs: dict[str, Any], key: str, fallback: str, stack: str) -> str:
    if key not in outputs:
        return fallback
    value = str(outputs.get(key) or "").strip()
    if not value:
        raise ValueError(f"Pulumi output {key} is unresolved for stack {stack!r}")
    if not ROLE_ARN_RE.fullmatch(value):
        raise ValueError(f"Pulumi output {key} for stack {stack!r} must be an IAM role ARN")
    if value != fallback:
        raise ValueError(
            f"Pulumi output {key} for stack {stack!r} disagrees with derived fallback: "
            f"{value!r} != {fallback!r}"
        )
    return value
