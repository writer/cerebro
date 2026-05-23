#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

import yaml


SCHEMA_VERSION = "cerebro.runtime-deploy-contract/v1"


def _load_stack(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle) or {}
    config = loaded.get("config")
    if not isinstance(config, dict):
        raise ValueError(f"{path} must contain a top-level config mapping")
    return {
        key.removeprefix("cerebro:"): value
        for key, value in config.items()
        if isinstance(key, str) and key.startswith("cerebro:")
    }


def _load_contract(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        loaded = json.load(handle)
    if not isinstance(loaded, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return loaded


def _runtime_env_refs(runtime: dict[str, Any]) -> set[str]:
    config = runtime.get("config") or {}
    if not isinstance(config, dict):
        return set()
    refs: set[str] = set()
    for value in config.values():
        if isinstance(value, str) and value.strip().startswith("env:"):
            refs.add(value.strip().removeprefix("env:").strip())
    return refs


def _runtime_family(runtime: dict[str, Any]) -> str:
    config = runtime.get("config") or {}
    if not isinstance(config, dict):
        return ""
    return str(config.get("family") or "").strip()


def _contract_sources(contract: dict[str, Any]) -> dict[str, dict[str, Any]]:
    sources = contract.get("sources") or []
    if not isinstance(sources, list):
        raise ValueError("contract sources must be a list")
    by_id: dict[str, dict[str, Any]] = {}
    for source in sources:
        if not isinstance(source, dict):
            raise ValueError("contract source entries must be objects")
        source_id = str(source.get("source_id") or "").strip()
        if not source_id:
            raise ValueError("contract source entries must declare source_id")
        by_id[source_id] = source
    return by_id


def _contract_runtimes(contract: dict[str, Any]) -> dict[str, dict[str, Any]]:
    runtimes: dict[str, dict[str, Any]] = {}
    for source in _contract_sources(contract).values():
        for runtime in source.get("runtimes") or []:
            if not isinstance(runtime, dict):
                raise ValueError("contract runtime entries must be objects")
            runtime_id = str(runtime.get("id") or "").strip()
            if runtime_id:
                runtimes[runtime_id] = runtime
    return runtimes


def verify_contract(contract: dict[str, Any], stack: dict[str, Any], require_manifest_runtimes: bool = False) -> list[str]:
    errors: list[str] = []
    if contract.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"contract schema_version must be {SCHEMA_VERSION!r}")

    contract_tag = str(contract.get("image_tag") or "").strip()
    stack_tag = str(stack.get("imageTag") or "").strip()
    if contract_tag and stack_tag and contract_tag != stack_tag:
        errors.append(f"contract image_tag {contract_tag!r} does not match stack imageTag {stack_tag!r}")

    source_secret_keys = {
        str(value).strip()
        for value in (stack.get("sourceSecretKeys") or [])
        if str(value).strip()
    }
    if require_manifest_runtimes:
        contract_required_secrets = {
            str(value).strip()
            for value in (contract.get("required_secrets") or [])
            if str(value).strip()
        }
        missing_contract_secrets = sorted(contract_required_secrets - source_secret_keys)
        if missing_contract_secrets:
            errors.append(f"stack is missing contract-required sourceSecretKeys: {', '.join(missing_contract_secrets)}")

    sources = _contract_sources(contract)
    stack_runtimes = stack.get("sourceRuntimes") or []
    if not isinstance(stack_runtimes, list):
        errors.append("stack sourceRuntimes must be a list")
        stack_runtimes = []

    by_runtime_id: dict[str, dict[str, Any]] = {}
    for runtime in stack_runtimes:
        if not isinstance(runtime, dict):
            errors.append("stack sourceRuntimes entries must be objects")
            continue
        runtime_id = str(runtime.get("id") or "").strip()
        source_id = str(runtime.get("sourceId") or runtime.get("source_id") or "").strip()
        if runtime_id:
            by_runtime_id[runtime_id] = runtime
        source = sources.get(source_id)
        if source is None:
            errors.append(f"runtime {runtime_id or '<unknown>'} uses sourceId {source_id!r} not present in contract")
            continue
        family = _runtime_family(runtime)
        supported_families = {
            str(value).strip()
            for value in (source.get("supported_families") or [])
            if str(value).strip()
        }
        if family and supported_families and family not in supported_families:
            errors.append(f"runtime {runtime_id} uses unsupported {source_id} family {family!r}")
        missing_env_refs = sorted(_runtime_env_refs(runtime) - source_secret_keys)
        if missing_env_refs:
            errors.append(f"runtime {runtime_id} references undeclared sourceSecretKeys: {', '.join(missing_env_refs)}")

    if require_manifest_runtimes:
        for runtime_id, runtime in sorted(_contract_runtimes(contract).items()):
            stack_runtime = by_runtime_id.get(runtime_id)
            if stack_runtime is None:
                errors.append(f"contract runtime {runtime_id!r} is missing from stack sourceRuntimes")
                continue
            stack_config = stack_runtime.get("config") or {}
            contract_config = runtime.get("config") or {}
            if not isinstance(stack_config, dict) or not isinstance(contract_config, dict):
                errors.append(f"runtime {runtime_id!r} config must be an object")
                continue
            for key, expected in sorted(contract_config.items()):
                actual = stack_config.get(key)
                if str(expected).startswith("env:") or key == "family":
                    if str(actual) != str(expected):
                        errors.append(f"runtime {runtime_id!r} config {key!r} is {actual!r}, expected {expected!r}")
                elif key not in stack_config:
                    errors.append(f"runtime {runtime_id!r} is missing contract config key {key!r}")

    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify a signed runtime deploy contract against a Cerebro stack file.")
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--stack-file", type=Path, required=True)
    parser.add_argument("--require-manifest-runtimes", action="store_true")
    args = parser.parse_args(argv)

    errors = verify_contract(_load_contract(args.contract), _load_stack(args.stack_file), args.require_manifest_runtimes)
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
