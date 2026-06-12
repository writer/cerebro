#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

try:
    from scripts import verify_aws_secret_imports, verify_runtime_contract
except ImportError:  # pragma: no cover - used when executed from infra/scripts directly
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import verify_aws_secret_imports
    import verify_runtime_contract


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def _check(name: str, errors: list[str] | None = None, details: dict[str, Any] | None = None) -> dict[str, Any]:
    errors = errors or []
    check: dict[str, Any] = {"name": name, "status": "fail" if errors else "pass"}
    if errors:
        check["errors"] = errors
    if details:
        check["details"] = details
    return check


def build_receipt(contract_path: Path, stack_path: Path, require_manifest_runtimes: bool = False) -> dict[str, Any]:
    stack = verify_runtime_contract._load_stack(stack_path)
    contract = verify_runtime_contract._load_contract(contract_path)
    checks: list[dict[str, Any]] = []

    contract_errors = verify_runtime_contract.verify_contract(contract, stack, require_manifest_runtimes=require_manifest_runtimes)
    checks.append(_check("runtime_contract", contract_errors))

    imports = verify_aws_secret_imports.expected_secret_imports(stack, stack_path.stem.removeprefix("Pulumi."))
    missing_refs = verify_aws_secret_imports.missing_env_ref_findings(stack, imports)
    checks.append(
        _check(
            "secret_import_plan",
            [f"undeclared runtime env reference fingerprint={finding.fingerprint}" for finding in missing_refs],
            {
                "import_count": len(imports),
                "import_fingerprints": sorted(_fingerprint(item.env_name) for item in imports),
            },
        )
    )

    provider = str(stack.get("graphAgentLlmProvider") or "").strip().lower()
    model = str(stack.get("graphAgentLlmModel") or "").strip()
    bedrock_region = str(stack.get("bedrockRegion") or "").strip()
    openrouter_secret = str(stack.get("openrouterApiKeySecret") or "").strip()
    llm_errors: list[str] = []
    if provider == "openrouter":
        if not openrouter_secret:
            llm_errors.append("OpenRouter provider is missing its secret import")
        if not any(item.env_name == "CEREBRO_OPENROUTER_API_KEY" for item in imports):
            llm_errors.append("OpenRouter API key is absent from the secret import plan")
    if provider == "bedrock":
        if not model:
            llm_errors.append("Bedrock provider is missing its model or inference profile id")
        if not bedrock_region:
            llm_errors.append("Bedrock provider is missing its runtime region")
    checks.append(
        _check(
            "graph_agent_llm",
            llm_errors,
            {
                "provider": provider or "unconfigured",
                "openrouter_secret_configured": bool(openrouter_secret),
                "bedrock_model_configured": bool(model) if provider == "bedrock" else False,
                "bedrock_region_configured": bool(bedrock_region) if provider == "bedrock" else False,
            },
        )
    )

    status = "pass" if all(check["status"] == "pass" for check in checks) else "fail"
    return {
        "kind": "cerebro.deploy_preflight",
        "status": status,
        "stack": stack_path.stem.removeprefix("Pulumi."),
        "image_tag": str(stack.get("imageTag") or ""),
        "checks": checks,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build a redacted Cerebro deploy preflight receipt.")
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--stack-file", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-manifest-runtimes", action="store_true")
    args = parser.parse_args(argv)

    receipt = build_receipt(
        args.contract,
        args.stack_file,
        require_manifest_runtimes=args.require_manifest_runtimes,
    )
    data = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(data, encoding="utf-8")
    else:
        print(data, end="")
    return 0 if receipt["status"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
