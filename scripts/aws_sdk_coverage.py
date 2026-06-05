#!/usr/bin/env python3
"""Dump and check AWS SDK service coverage for the AWS source."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "docs" / "AWS_SDK_COVERAGE.json"
AWS_SERVICE_PREFIX = "github.com/aws/aws-sdk-go-v2/service/"

EXPLICIT_SERVICE_FAMILIES = {
    "apigateway": ["public_endpoint"],
    "apigatewayv2": ["public_endpoint"],
    "cloudfront": ["public_endpoint"],
    "cloudtrail": ["cloudtrail"],
    "ec2": ["asset_metadata", "ec2_instance", "public_endpoint", "resource_exposure"],
    "ecr": ["asset_metadata", "ecr_repository"],
    "ecs": ["asset_metadata", "ecs_service", "ecs_task", "ecs_task_definition"],
    "eks": ["asset_metadata", "eks_cluster", "eks_nodegroup", "eks_fargate_profile", "eks_pod_identity_association"],
    "elasticloadbalancingv2": ["public_endpoint"],
    "iam": ["access_key", "effective_permission", "iam_group", "iam_group_membership", "iam_role", "iam_role_assignment", "iam_role_trust", "iam_user"],
    "kms": ["asset_metadata", "kms_key"],
    "lambda": ["asset_metadata", "lambda_function"],
    "rds": ["asset_metadata", "rds_instance"],
    "resourcegroupstaggingapi": ["asset_metadata"],
    "route53": ["public_endpoint"],
    "s3": ["asset_metadata", "s3_bucket"],
    "secretsmanager": ["asset_metadata", "secret"],
    "sns": ["asset_metadata", "sns_topic"],
    "sqs": ["asset_metadata", "sqs_queue"],
}

NON_INVENTORY_SERVICES = {
    "bedrockruntime": "runtime invocation client; not an AWS asset inventory API",
    "signin": "AWS auth helper; not an AWS asset inventory API",
    "sso": "AWS auth helper; not an AWS asset inventory API",
    "ssooidc": "AWS auth helper; not an AWS asset inventory API",
    "sts": "AWS identity/session API used to validate and assume source credentials",
}


def parse_go_list_json(stream: str) -> list[dict[str, Any]]:
    decoder = json.JSONDecoder()
    modules: list[dict[str, Any]] = []
    index = 0
    while index < len(stream):
        while index < len(stream) and stream[index].isspace():
            index += 1
        if index >= len(stream):
            break
        module, end = decoder.raw_decode(stream, index)
        if isinstance(module, dict):
            modules.append(module)
        index = end
    return modules


def go_modules() -> list[dict[str, Any]]:
    completed = subprocess.run(
        ["go", "list", "-m", "-json", "all"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "go list failed")
    return parse_go_list_json(completed.stdout)


def service_name(module_path: str) -> str:
    if not module_path.startswith(AWS_SERVICE_PREFIX):
        return ""
    service = module_path.removeprefix(AWS_SERVICE_PREFIX).split("/", 1)[0]
    if service == "internal":
        return ""
    return service


def build_dump(modules: list[dict[str, Any]]) -> dict[str, Any]:
    services: dict[str, dict[str, Any]] = {}
    for module in modules:
        path = str(module.get("Path", ""))
        service = service_name(path)
        if service == "":
            continue
        services[service] = {
            "service": service,
            "module": path,
            "version": module.get("Version", ""),
        }

    rows = []
    uncovered = []
    for service in sorted(services):
        families = EXPLICIT_SERVICE_FAMILIES.get(service, [])
        non_inventory_reason = NON_INVENTORY_SERVICES.get(service, "")
        generic_asset_metadata = service not in NON_INVENTORY_SERVICES
        status = "explicit" if families else "non_inventory" if non_inventory_reason else "generic_asset_metadata"
        row = {
            **services[service],
            "coverage_status": status,
            "explicit_families": families,
            "generic_asset_metadata": generic_asset_metadata,
        }
        if non_inventory_reason:
            row["note"] = non_inventory_reason
        if not families and not generic_asset_metadata and not non_inventory_reason:
            uncovered.append(service)
        rows.append(row)

    return {
        "description": "AWS SDK service modules used by Cerebro and how the AWS source covers their inventory surface.",
        "generic_asset_metadata_backstop": "The aws asset_metadata family calls Resource Groups Tagging API GetResources without ResourceTypeFilters, so taggable resources from SDK services are projected as typed cloud resources even when no service-specific family exists.",
        "services": rows,
        "uncovered_services": uncovered,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="write the checked-in JSON dump")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    args = parser.parse_args()

    dump = build_dump(go_modules())
    payload = json.dumps(dump, indent=2, sort_keys=True) + "\n"
    output = Path(args.output)
    if args.write:
        output.write_text(payload, encoding="utf-8")
    elif output.exists() and output.read_text(encoding="utf-8") != payload:
        print(f"{output.relative_to(ROOT)} is stale; run scripts/aws_sdk_coverage.py --write", file=sys.stderr)
        return 1
    if dump["uncovered_services"]:
        print("AWS SDK services without coverage:", file=sys.stderr)
        for service in dump["uncovered_services"]:
            print(f"- {service}", file=sys.stderr)
        return 1
    print(f"aws sdk coverage: {len(dump['services'])} service modules covered")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
