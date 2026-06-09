#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

import yaml

try:
    from aws.source_rollouts import apply_source_runtime_rollouts
except ModuleNotFoundError:  # pragma: no cover - used when executed as scripts/verify_runtime_contract.py
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from aws.source_rollouts import apply_source_runtime_rollouts


SCHEMA_VERSION = "cerebro.runtime-deploy-contract/v1"


def _load_stack(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle) or {}
    config = loaded.get("config")
    if not isinstance(config, dict):
        raise ValueError(f"{path} must contain a top-level config mapping")
    config = {
        key.removeprefix("cerebro:"): value
        for key, value in config.items()
        if isinstance(key, str) and key.startswith("cerebro:")
    }
    return apply_source_runtime_rollouts(config)


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


def _runtime_value(runtime: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = runtime.get(key)
        if value is not None:
            return str(value).strip()
    return ""


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


def _contract_source_health_receipts(contract: dict[str, Any]) -> list[dict[str, Any]]:
    receipts: list[dict[str, Any]] = []

    def append_receipt(raw: Any, source_id: str = "") -> None:
        if raw is None:
            return
        if not isinstance(raw, dict):
            raise ValueError("contract source_health_receipt entries must be objects")
        receipt = dict(raw)
        if source_id and not str(receipt.get("source_id") or "").strip():
            receipt["source_id"] = source_id
        receipts.append(receipt)

    top_level = contract.get("source_health_receipts") or []
    if not isinstance(top_level, list):
        raise ValueError("contract source_health_receipts must be a list")
    for receipt in top_level:
        append_receipt(receipt)

    for source in _contract_sources(contract).values():
        source_id = str(source.get("source_id") or "").strip()
        append_receipt(source.get("source_health_receipt"), source_id)
        source_receipts = source.get("source_health_receipts") or []
        if not isinstance(source_receipts, list):
            raise ValueError("contract source source_health_receipts must be a list")
        for receipt in source_receipts:
            append_receipt(receipt, source_id)

    return receipts


def _positive_int(value: Any) -> int | None:
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    if parsed <= 0:
        return None
    return parsed


def _stack_runtimes_by_source(stack: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    by_source: dict[str, list[dict[str, Any]]] = {}
    runtimes = stack.get("sourceRuntimes") or []
    if not isinstance(runtimes, list):
        return by_source
    for runtime in runtimes:
        if not isinstance(runtime, dict):
            continue
        source_id = _runtime_value(runtime, "sourceId", "source_id")
        if source_id:
            by_source.setdefault(source_id, []).append(runtime)
    return by_source


def _verify_source_health_receipts(
    contract: dict[str, Any],
    sources: dict[str, dict[str, Any]],
    stack: dict[str, Any],
) -> list[str]:
    errors: list[str] = []
    runtimes_by_source = _stack_runtimes_by_source(stack)
    for receipt in _contract_source_health_receipts(contract):
        receipt_kind = str(receipt.get("receipt_kind") or "").strip()
        source_id = str(receipt.get("source_id") or "").strip()
        if receipt_kind != "source_health.receipt":
            errors.append(f"source_health_receipt for {source_id or '<unknown>'} must declare receipt_kind 'source_health.receipt'")
            continue
        if source_id not in sources:
            errors.append(f"source_health_receipt source_id {source_id!r} is not present in contract sources")
            continue
        health_path = str(receipt.get("adapter_health_path") or "").strip()
        if health_path and not health_path.startswith("/"):
            errors.append(f"source_health_receipt for {source_id} adapter_health_path must start with /")
        if str(receipt.get("evidence_cas_reference_kind") or "").strip() not in ("", f"{source_id}.evidence_cas_reference"):
            errors.append(f"source_health_receipt for {source_id} evidence_cas_reference_kind must match the source id")
        expected_cadence = _positive_int(receipt.get("expected_cadence_seconds"))
        if expected_cadence is None:
            errors.append(f"source_health_receipt for {source_id} expected_cadence_seconds must be a positive integer")
        stale_after = _positive_int(receipt.get("stale_after_seconds"))
        if stale_after is None:
            errors.append(f"source_health_receipt for {source_id} stale_after_seconds must be a positive integer")
        if expected_cadence is None or stale_after is None:
            continue
        for runtime in runtimes_by_source.get(source_id, []):
            runtime_id = _runtime_value(runtime, "id") or "<unknown>"
            config = runtime.get("config") or {}
            if not isinstance(config, dict):
                errors.append(f"runtime {runtime_id!r} config must be an object")
                continue
            for key, expected in {
                "expected_cadence_seconds": expected_cadence,
                "stale_after_seconds": stale_after,
            }.items():
                actual = str(config.get(key) or "").strip()
                if actual != str(expected):
                    errors.append(f"runtime {runtime_id!r} config {key!r} is {actual!r}, expected source health receipt value")
            if health_path and str(config.get("health_path") or "").strip() != health_path:
                errors.append(f"runtime {runtime_id!r} config 'health_path' does not match source health receipt")
    return errors


def _verify_matching_runtime_deploy_metadata(
    contract_runtimes: dict[str, dict[str, Any]],
    stack_runtimes: dict[str, dict[str, Any]],
) -> list[str]:
    errors: list[str] = []
    generated_keys = ("health_path", "expected_cadence_seconds", "stale_after_seconds")
    for runtime_id, stack_runtime in sorted(stack_runtimes.items()):
        contract_runtime = contract_runtimes.get(runtime_id)
        if contract_runtime is None:
            continue
        stack_config = stack_runtime.get("config") or {}
        contract_config = contract_runtime.get("config") or {}
        if not isinstance(stack_config, dict) or not isinstance(contract_config, dict):
            continue
        for key in generated_keys:
            if key not in contract_config:
                continue
            actual = str(stack_config.get(key) or "").strip()
            expected = str(contract_config.get(key) or "").strip()
            if actual != expected:
                errors.append(f"runtime {runtime_id!r} config {key!r} is {actual!r}, expected runtime deploy contract value")
    return errors


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
            errors.append(f"stack is missing {len(missing_contract_secrets)} contract-required sourceSecretKeys")

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
            errors.append(f"runtime {runtime_id} references {len(missing_env_refs)} undeclared sourceSecretKeys")

    contract_runtimes = _contract_runtimes(contract)
    if not require_manifest_runtimes:
        errors.extend(_verify_matching_runtime_deploy_metadata(contract_runtimes, by_runtime_id))

    if require_manifest_runtimes:
        for runtime_id, runtime in sorted(contract_runtimes.items()):
            stack_runtime = by_runtime_id.get(runtime_id)
            if stack_runtime is None:
                errors.append(f"contract runtime {runtime_id!r} is missing from stack sourceRuntimes")
                continue
            contract_source_id = _runtime_value(runtime, "source_id", "sourceId")
            stack_source_id = _runtime_value(stack_runtime, "sourceId", "source_id")
            if contract_source_id and stack_source_id != contract_source_id:
                errors.append(f"runtime {runtime_id!r} sourceId is {stack_source_id!r}, expected {contract_source_id!r}")
            contract_tenant_id = _runtime_value(runtime, "tenant_id", "tenantId")
            stack_tenant_id = _runtime_value(stack_runtime, "tenantId", "tenant_id")
            if contract_tenant_id and stack_tenant_id != contract_tenant_id:
                errors.append(f"runtime {runtime_id!r} tenantId is {stack_tenant_id!r}, expected {contract_tenant_id!r}")
            stack_config = stack_runtime.get("config") or {}
            contract_config = runtime.get("config") or {}
            if not isinstance(stack_config, dict) or not isinstance(contract_config, dict):
                errors.append(f"runtime {runtime_id!r} config must be an object")
                continue
            for key, expected in sorted(contract_config.items()):
                actual = stack_config.get(key)
                if str(expected).startswith("env:") or key == "family":
                    if str(actual) != str(expected):
                        if str(expected).startswith("env:"):
                            errors.append(f"runtime {runtime_id!r} config {key!r} does not match contract env reference")
                        else:
                            errors.append(f"runtime {runtime_id!r} config {key!r} is {actual!r}, expected {expected!r}")
                elif key not in stack_config:
                    errors.append(f"runtime {runtime_id!r} is missing contract config key {key!r}")

    errors.extend(_verify_source_health_receipts(contract, sources, stack))

    return errors


def contract_drift(contract: dict[str, Any], stack: dict[str, Any]) -> list[str]:
    """Non-blocking drift signals between the signed contract and the stack.

    Restores the visibility the removed manifest-parity gate used to provide
    without failing the deploy. Secret names are never emitted.
    """
    warnings: list[str] = []

    contract_required_secrets = {
        str(value).strip()
        for value in (contract.get("required_secrets") or [])
        if str(value).strip()
    }
    source_secret_keys = {
        str(value).strip()
        for value in (stack.get("sourceSecretKeys") or [])
        if str(value).strip()
    }
    missing_secrets = contract_required_secrets - source_secret_keys
    if missing_secrets:
        warnings.append(f"stack is missing {len(missing_secrets)} contract-required sourceSecretKeys")

    stack_runtime_ids = {
        str(runtime.get("id") or "").strip()
        for runtime in (stack.get("sourceRuntimes") or [])
        if isinstance(runtime, dict) and str(runtime.get("id") or "").strip()
    }
    for runtime_id in sorted(_contract_runtimes(contract)):
        if runtime_id not in stack_runtime_ids:
            warnings.append(f"contract runtime {runtime_id!r} is not configured on the stack")

    stack_sources = set(_stack_runtimes_by_source(stack))
    for receipt in _contract_source_health_receipts(contract):
        source_id = str(receipt.get("source_id") or "").strip()
        if source_id and source_id not in stack_sources:
            warnings.append(f"source health receipt source_id {source_id!r} is not configured on the stack")

    return warnings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify a signed runtime deploy contract against a Cerebro stack file.")
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--stack-file", type=Path, required=True)
    parser.add_argument("--require-manifest-runtimes", action="store_true")
    args = parser.parse_args(argv)

    contract = _load_contract(args.contract)
    stack = _load_stack(args.stack_file)
    errors = verify_contract(contract, stack, args.require_manifest_runtimes)
    for warning in contract_drift(contract, stack):
        print(f"::warning::{warning}")
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
