#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

import yaml

try:
    from scripts.cerebro_task_roles import resolve_task_role_arns
except ImportError:  # pragma: no cover - used when executed from infra/scripts directly
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from cerebro_task_roles import resolve_task_role_arns


BEDROCK_ACTIONS = ("bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream")
SIMULATION_QUERY = (
    "EvaluationResults[].{"
    "Action:EvalActionName,"
    "Decision:EvalDecision,"
    "Resource:EvalResourceName,"
    "ResourceSpecificResults:ResourceSpecificResults[].{"
    "Decision:EvalResourceDecision,"
    "Resource:EvalResourceName"
    "}"
    "}"
)


def load_stack(path: Path) -> dict[str, Any]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    config = raw.get("config") or {}
    return {str(key).removeprefix("cerebro:"): value for key, value in config.items()}


def bedrock_model_ids(config: dict[str, Any]) -> list[str]:
    if str(config.get("graphAgentLlmProvider") or "").strip().lower() != "bedrock":
        return []
    values = [
        config.get("graphAgentLlmModel"),
        config.get("graphAgentLlmModelSonnet"),
        config.get("graphAgentLlmModelOpus"),
        config.get("graphAgentLlmModelHaiku"),
    ]
    return sorted({str(value).strip() for value in values if str(value or "").strip()})


def bedrock_resource_arns(model_ids: list[str], account_id: str) -> list[str]:
    resources: set[str] = set()
    for model_id in sorted({str(model_id).strip() for model_id in model_ids if str(model_id).strip()}):
        if model_id.startswith("arn:aws:bedrock:"):
            resources.add(model_id)
        elif is_inference_profile_id(model_id):
            resources.add(f"arn:aws:bedrock:*:{account_id}:inference-profile/{model_id}")
            foundation_model_id = foundation_model_id_from_profile(model_id)
            if foundation_model_id:
                resources.add(f"arn:aws:bedrock:*::foundation-model/{foundation_model_id}")
        else:
            resources.add(f"arn:aws:bedrock:*::foundation-model/{model_id}")
    return sorted(resources)


def is_inference_profile_id(model_id: str) -> bool:
    return model_id.startswith(("us.", "global.", "eu.", "apac."))


def foundation_model_id_from_profile(profile_id: str) -> str:
    for prefix in ("us.", "global.", "eu.", "apac."):
        if profile_id.startswith(prefix):
            return profile_id[len(prefix):]
    return ""


def aws_json(args: list[str]) -> Any:
    output = subprocess.check_output(["aws", *args, "--output", "json"], text=True)
    return json.loads(output)


def caller_account_id(profile: str | None) -> str:
    args = ["sts", "get-caller-identity", "--query", "Account"]
    if profile:
        args.extend(["--profile", profile])
    return str(aws_json(args)).strip()


def simulate_role(profile: str | None, role_arn: str, resources: list[str]) -> list[dict[str, Any]]:
    args = [
        "iam",
        "simulate-principal-policy",
        "--policy-source-arn",
        role_arn,
        "--action-names",
        *BEDROCK_ACTIONS,
        "--resource-arns",
        *resources,
        "--query",
        SIMULATION_QUERY,
    ]
    if profile:
        args.extend(["--profile", profile])
    return aws_json(args)


def simulate_custom_policies(profile: str | None, policy_documents: list[dict[str, Any]], resources: list[str]) -> list[dict[str, Any]]:
    if not policy_documents:
        return []
    args = [
        "iam",
        "simulate-custom-policy",
        "--policy-input-list",
        *[json.dumps(document, separators=(",", ":")) for document in policy_documents],
        "--action-names",
        *BEDROCK_ACTIONS,
        "--resource-arns",
        *resources,
        "--query",
        SIMULATION_QUERY,
    ]
    if profile:
        args.extend(["--profile", profile])
    return aws_json(args)


def role_name_from_arn(role_arn: str) -> str:
    return role_arn.rsplit("/", 1)[-1]


def inline_policy_names(profile: str | None, role_name: str) -> list[str]:
    args = ["iam", "list-role-policies", "--role-name", role_name, "--query", "PolicyNames"]
    if profile:
        args.extend(["--profile", profile])
    values = aws_json(args)
    if not isinstance(values, list):
        return []
    return sorted(str(value) for value in values if str(value or "").strip())


def role_policy_document(profile: str | None, role_name: str, policy_name: str) -> dict[str, Any]:
    args = ["iam", "get-role-policy", "--role-name", role_name, "--policy-name", policy_name, "--query", "PolicyDocument"]
    if profile:
        args.extend(["--profile", profile])
    document = aws_json(args)
    if isinstance(document, str):
        document = json.loads(document)
    if not isinstance(document, dict):
        raise RuntimeError(f"inline policy {policy_name} on {role_name} did not return a JSON policy document")
    return document


def policy_mentions_bedrock(value: Any) -> bool:
    if isinstance(value, str):
        return value.lower().startswith("bedrock:")
    if isinstance(value, list):
        return any(policy_mentions_bedrock(item) for item in value)
    if isinstance(value, dict):
        return any(policy_mentions_bedrock(item) for item in value.values())
    return False


def bedrock_inline_policy_documents(profile: str | None, role_arn: str) -> list[dict[str, Any]]:
    role_name = role_name_from_arn(role_arn)
    documents: list[dict[str, Any]] = []
    for policy_name in inline_policy_names(profile, role_name):
        document = role_policy_document(profile, role_name, policy_name)
        if policy_mentions_bedrock(document):
            documents.append(document)
    return documents


def denied_simulation_decisions(result: dict[str, Any]) -> list[tuple[str, Any]]:
    action = str(result.get("Action") or "")
    resource_results = result.get("ResourceSpecificResults")
    if isinstance(resource_results, list) and resource_results:
        return [
            (action, resource_result.get("Resource"))
            for resource_result in resource_results
            if isinstance(resource_result, dict) and resource_result.get("Decision") != "allowed"
        ]
    if result.get("Decision") != "allowed":
        return [(action, result.get("Resource"))]
    return []


def verify_bedrock_permissions(stack_path: Path, profile: str | None = None) -> None:
    stack = stack_path.stem.removeprefix("Pulumi.")
    config = load_stack(stack_path)
    models = bedrock_model_ids(config)
    if not models:
        print(f"{stack} Bedrock task-role preflight skipped.")
        return
    account_id = caller_account_id(profile)
    resources = bedrock_resource_arns(models, account_id)
    roles = resolve_task_role_arns(stack, config, account_id).as_principals()
    denied: list[str] = []
    for role_arn in roles:
        role_name = role_name_from_arn(role_arn)
        role_denied = [
            f"{role_name}:{action}:{resource}"
            for result in simulate_role(profile, role_arn, resources)
            for action, resource in denied_simulation_decisions(result)
        ]
        if not role_denied:
            continue

        policy_documents = bedrock_inline_policy_documents(profile, role_arn)
        inline_denied = [
            f"{role_name}:{action}:{resource}"
            for result in simulate_custom_policies(profile, policy_documents, resources)
            for action, resource in denied_simulation_decisions(result)
        ]
        if policy_documents and not inline_denied:
            print(
                f"{role_name} principal-policy simulation returned {len(role_denied)} denied Bedrock decision(s); "
                "inline Bedrock policy simulation allowed all checked resources."
            )
            continue
        denied.extend(inline_denied or role_denied)
    if denied:
        raise RuntimeError(f"{stack} Bedrock task-role preflight failed for {len(denied)} decision(s)")
    print(f"{stack} Bedrock task-role preflight passed for {len(roles)} role(s) and {len(resources)} resource(s).")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify Cerebro ECS task roles can invoke configured Bedrock models.")
    parser.add_argument("--stack-file", type=Path, required=True)
    parser.add_argument("--profile")
    args = parser.parse_args(argv)

    verify_bedrock_permissions(args.stack_file, args.profile)
    return 0


if __name__ == "__main__":
    sys.exit(main())
