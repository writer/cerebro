#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import sys
from tempfile import TemporaryDirectory
from typing import Any
from urllib.request import Request, urlopen

try:
    from scripts import build_deploy_preflight_receipt, set_image_tag, verify_runtime_contract
except ImportError:  # pragma: no cover - used when executed from infra/scripts directly
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import build_deploy_preflight_receipt
    import set_image_tag
    import verify_runtime_contract


DEFAULT_REPO = "writer/cerebro"
DEFAULT_STACKS = {
    "sec-dev": Path("aws/Pulumi.sec-dev.yaml"),
    "go-prod": Path("aws/Pulumi.go-prod.yaml"),
}


def _parse_mapping(value: str) -> tuple[str, Path]:
    if "=" not in value:
        raise argparse.ArgumentTypeError(f"{value!r} must be formatted as environment=path")
    environment, raw_path = value.split("=", 1)
    environment = environment.strip()
    if not environment:
        raise argparse.ArgumentTypeError(f"{value!r} must declare a non-empty environment")
    return environment, Path(raw_path)


def _request_json(url: str, token: str = "") -> Any:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(url, headers=headers)
    with urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def _download_latest_contracts(repo: str, environments: set[str], destination: Path, token: str = "") -> dict[str, Path]:
    release = _request_json(f"https://api.github.com/repos/{repo}/releases/latest", token)
    assets = release.get("assets") or []
    if not isinstance(assets, list):
        raise ValueError(f"latest {repo} release returned malformed assets")

    by_name = {
        str(asset.get("name") or ""): str(asset.get("browser_download_url") or "")
        for asset in assets
        if isinstance(asset, dict)
    }
    contracts: dict[str, Path] = {}
    for environment in sorted(environments):
        asset_name = f"cerebro-runtime-contract-{environment}.json"
        asset_url = by_name.get(asset_name)
        if not asset_url:
            raise ValueError(f"latest {repo} release is missing {asset_name}")
        contract_path = destination / asset_name
        contract_path.write_text(json.dumps(_request_json(asset_url, token), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        contracts[environment] = contract_path
    return contracts


def verify_environment(environment: str, contract_path: Path, stack_path: Path) -> list[str]:
    contract = verify_runtime_contract._load_contract(contract_path)
    image_tag = str(contract.get("image_tag") or "").strip()
    if not image_tag:
        return [f"{environment}: contract {contract_path} does not declare image_tag"]

    with TemporaryDirectory() as raw_tmp:
        tmp = Path(raw_tmp)
        simulated_stack = tmp / f"Pulumi.{environment}.yaml"
        shutil.copyfile(stack_path, simulated_stack)
        set_image_tag.set_image_tag(simulated_stack, image_tag)

        stack = verify_runtime_contract._load_stack(simulated_stack)
        errors = [
            f"{environment}: {error}"
            for error in verify_runtime_contract.verify_contract(contract, stack, require_manifest_runtimes=False)
        ]

        receipt = build_deploy_preflight_receipt.build_receipt(contract_path, simulated_stack)
        if receipt["status"] != "pass":
            for check in receipt["checks"]:
                if check["status"] == "pass":
                    continue
                for error in check.get("errors") or []:
                    errors.append(f"{environment}: deploy preflight {check['name']}: {error}")
        return errors


def verify_contracts(contract_paths: dict[str, Path], stack_paths: dict[str, Path]) -> list[str]:
    errors: list[str] = []
    for environment, stack_path in sorted(stack_paths.items()):
        contract_path = contract_paths.get(environment)
        if contract_path is None:
            errors.append(f"{environment}: missing runtime contract")
            continue
        errors.extend(verify_environment(environment, contract_path, stack_path))
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify latest Cerebro release contracts can be promoted to internal stacks.")
    parser.add_argument("--repo", default=DEFAULT_REPO, help="GitHub repository that publishes Cerebro release contracts.")
    parser.add_argument(
        "--stack",
        action="append",
        type=_parse_mapping,
        help="Environment stack mapping, formatted as environment=path.",
    )
    parser.add_argument(
        "--contract",
        action="append",
        type=_parse_mapping,
        help="Optional local runtime contract mapping, formatted as environment=path.",
    )
    args = parser.parse_args(argv)

    stack_paths = dict(args.stack or DEFAULT_STACKS.items())
    contract_paths = dict(args.contract or [])

    with TemporaryDirectory() as raw_tmp:
        if not contract_paths:
            token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
            contract_paths = _download_latest_contracts(args.repo, set(stack_paths), Path(raw_tmp), token)

        errors = verify_contracts(contract_paths, stack_paths)

    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    if errors:
        return 1
    print(f"Verified {len(stack_paths)} Cerebro promotion contract(s) against {args.repo}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
