#!/usr/bin/env python3
"""Generate and check GitHub-backed AWS resource coverage inventory."""

from __future__ import annotations

import argparse
import base64
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

try:
    from scripts import aws_sdk_coverage
except ModuleNotFoundError:  # pragma: no cover - direct script execution path
    import aws_sdk_coverage


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "docs" / "AWS_RESOURCE_COVERAGE.json"

AWS_API_MODELS_REPO = "aws/api-models-aws"
AWS_API_MODELS_PATH = "models"
AWS_SDK_GO_V2_REPO = "aws/aws-sdk-go-v2"
AWS_SDK_GO_V2_MODELS_PATH = "codegen/sdk-codegen/aws-models"
TAGGABILITY_REPO = "olu-folarin/can-i-tag-aws"
TAGGABILITY_PATH = "output/api_taggable_resources.json"

DEEP_COVERAGE_BATCHES = {
    "security_posture": [
        "accessanalyzer",
        "config",
        "guardduty",
        "inspector2",
        "macie2",
        "network-firewall",
        "securityhub",
        "wafv2",
    ],
    "data_stores": [
        "docdb",
        "dynamodb",
        "elasticache",
        "efs",
        "fsx",
        "neptune",
        "opensearch",
        "opensearchserverless",
        "redshift",
    ],
    "network_edge": [
        "acm",
        "apigatewayv2",
        "elasticloadbalancingv2",
        "globalaccelerator",
        "route53resolver",
        "vpclattice",
    ],
    "runtime_platform": [
        "apprunner",
        "batch",
        "cloudwatch",
        "eventbridge",
        "pipes",
        "scheduler",
        "ssm",
        "sfn",
    ],
}

SDK_MODEL_ALIASES = {
    "config": "config-service",
    "elasticloadbalancingv2": "elastic-load-balancing-v2",
    "globalaccelerator": "global-accelerator",
    "vpclattice": "vpc-lattice",
}


def slug(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    aliases = {
        "amazon-dynamodb": "dynamodb",
        "amazon-elastic-container-registry-amazon-ecr": "ecr",
        "amazon-elastic-container-service-amazon-ecs": "ecs",
        "amazon-elastic-kubernetes-service-amazon-eks": "eks",
        "amazon-elastic-file-system-amazon-efs": "efs",
        "amazon-simple-storage-service-amazon-s3-buckets-only": "s3",
        "amazon-simple-notification-service-amazon-sns": "sns",
        "amazon-simple-queue-service-amazon-sqs": "sqs",
        "amazon-relational-database-service-amazon-rds": "rds",
        "aws-key-management-service-aws-kms": "kms",
        "aws-secrets-manager": "secretsmanager",
        "aws-security-hub-cspm": "securityhub",
        "amazon-opensearch-service": "opensearch",
        "amazon-opensearch-serverless": "opensearchserverless",
    }
    return aliases.get(normalized, normalized)


def run_gh_api(path: str, *args: str) -> str:
    completed = subprocess.run(
        ["gh", "api", path, *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or f"gh api {path} failed")
    return completed.stdout


def github_directory_names(repo: str, path: str) -> list[str]:
    output = run_gh_api(f"repos/{repo}/contents/{path}", "--jq", ".[].name")
    return sorted(line.strip() for line in output.splitlines() if line.strip())


def github_json_file(repo: str, path: str) -> dict[str, Any]:
    content = run_gh_api(f"repos/{repo}/contents/{path}", "--jq", ".content")
    body = base64.b64decode("".join(content.split())).decode("utf-8")
    parsed = json.loads(body)
    if not isinstance(parsed, dict):
        raise RuntimeError(f"{repo}/{path} did not contain a JSON object")
    return parsed


def sdk_model_services(model_files: list[str]) -> list[str]:
    services: list[str] = []
    for name in model_files:
        if name.endswith(".json"):
            services.append(name.removesuffix(".json"))
    return sorted(services)


def taggability_resources(data: dict[str, Any]) -> list[dict[str, str]]:
    resources: list[dict[str, str]] = []
    for service in data.get("mixed_services_detail") or []:
        service_name = str(service.get("name", "")).strip()
        if service_name == "":
            continue
        for key, status in (
            ("taggable", "taggable"),
            ("conditionally_taggable", "conditionally_taggable"),
            ("untaggable", "untaggable"),
        ):
            for resource in service.get(key) or []:
                resources.append(
                    {
                        "service": service_name,
                        "service_slug": slug(service_name),
                        "resource": str(resource),
                        "taggability": status,
                    }
                )
    for resource in data.get("untaggable_resources") or []:
        service_name = str(resource.get("service", "")).strip()
        resources.append(
            {
                "service": service_name,
                "service_slug": slug(service_name),
                "resource": str(resource.get("resource", "")),
                "taggability": "untaggable",
                "reason": str(resource.get("reason", "")),
            }
        )
    resources.sort(key=lambda item: (item["service_slug"], item["resource"], item["taggability"]))
    return resources


def build_dump() -> dict[str, Any]:
    api_model_services = github_directory_names(AWS_API_MODELS_REPO, AWS_API_MODELS_PATH)
    sdk_models = sdk_model_services(github_directory_names(AWS_SDK_GO_V2_REPO, AWS_SDK_GO_V2_MODELS_PATH))
    taggability = github_json_file(TAGGABILITY_REPO, TAGGABILITY_PATH)
    explicit_families = {
        service: families
        for service, families in sorted(aws_sdk_coverage.EXPLICIT_SERVICE_FAMILIES.items())
    }
    non_inventory = {
        service: reason
        for service, reason in sorted(aws_sdk_coverage.NON_INVENTORY_SERVICES.items())
    }
    explicit_services = set(explicit_families)
    candidate_deep_services = sorted({service for services in DEEP_COVERAGE_BATCHES.values() for service in services})
    sdk_model_set = set(sdk_models)
    missing_from_sdk_models = [
        service
        for service in candidate_deep_services
        if service not in sdk_model_set and SDK_MODEL_ALIASES.get(service, "") not in sdk_model_set
    ]
    return {
        "description": "GitHub-backed AWS resource and service coverage inventory used to drive Cerebro AWS source depth.",
        "sources": {
            "aws_api_models": {
                "repo": AWS_API_MODELS_REPO,
                "path": AWS_API_MODELS_PATH,
                "service_count": len(api_model_services),
            },
            "aws_sdk_go_v2_models": {
                "repo": AWS_SDK_GO_V2_REPO,
                "path": AWS_SDK_GO_V2_MODELS_PATH,
                "service_count": len(sdk_models),
            },
            "taggability": {
                "repo": TAGGABILITY_REPO,
                "path": TAGGABILITY_PATH,
                "summary": taggability.get("summary", {}),
            },
        },
        "aws_api_model_services": api_model_services,
        "aws_sdk_go_v2_model_services": sdk_models,
        "taggability_resources": taggability_resources(taggability),
        "services_without_tagging_api": sorted(taggability.get("services_without_tagging_api") or []),
        "conditionally_taggable_resources": taggability.get("conditionally_taggable_resources") or [],
        "explicit_service_families": explicit_families,
        "non_inventory_services": non_inventory,
        "deep_coverage_batches": DEEP_COVERAGE_BATCHES,
        "sdk_model_aliases": SDK_MODEL_ALIASES,
        "deep_coverage_services_missing_from_sdk_models": missing_from_sdk_models,
        "explicit_services_missing_from_sdk_models": sorted(explicit_services - set(sdk_models)),
    }


def validate_dump(data: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    for key in (
        "sources",
        "aws_api_model_services",
        "aws_sdk_go_v2_model_services",
        "taggability_resources",
        "deep_coverage_batches",
    ):
        if key not in data:
            failures.append(f"missing top-level key {key!r}")
    if len(data.get("aws_sdk_go_v2_model_services") or []) < 400:
        failures.append("aws_sdk_go_v2_model_services unexpectedly small")
    if len(data.get("taggability_resources") or []) < 500:
        failures.append("taggability_resources unexpectedly small")
    if data.get("deep_coverage_services_missing_from_sdk_models"):
        failures.append("deep coverage services missing from SDK model list")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="fetch GitHub sources and write the checked-in JSON dump")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    args = parser.parse_args()

    output = Path(args.output)
    if args.write:
        dump = build_dump()
        output.write_text(json.dumps(dump, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        failures = validate_dump(dump)
    else:
        if not output.exists():
            print(f"{output.relative_to(ROOT)} is missing; run scripts/aws_resource_coverage.py --write", file=sys.stderr)
            return 1
        dump = json.loads(output.read_text(encoding="utf-8"))
        failures = validate_dump(dump)

    if failures:
        print("aws resource coverage check failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(
        "aws resource coverage: "
        f"{len(dump['aws_sdk_go_v2_model_services'])} SDK model services, "
        f"{len(dump['taggability_resources'])} taggability resource rows"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
