#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any


PLAN_SCHEMA_VERSION = 2
STATE_SCHEMA_VERSION = 1
SUPPORTED_MODES = {"plan", "dry-run", "run"}
SUPPORTED_STACK_FILES = {
    "sec-dev": "aws/Pulumi.sec-dev.yaml",
    "go-prod": "aws/Pulumi.go-prod.yaml",
}
EXECUTABLE_TARGET_STATES = {"backfillable"}
RUNTIME_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
SOURCE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,126}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")

PLAN_HASH_FIELDS = (
    "schema_version",
    "control_plane_ref",
    "stack_file",
    "stack_name",
    "stack_config_sha256",
    "requested_runtime_ids",
    "policy",
    "targets",
    "source_groups",
)

POLICY_BOUNDS = {
    "max_targets": (1, 100),
    "max_targets_per_source": (1, 20),
    "source_parallelism": (1, 10),
    "source_cooldown_seconds": (0, 3600),
    "max_attempts": (1, 5),
    "retry_backoff_seconds": (0, 3600),
    "run_page_limit": (1, 1000),
    "run_graph_page_limit": (1, 1000),
    "run_event_limit": (1, 100000),
    "wait_timeout_seconds": (60, 21600),
    "run_attempt_timeout_seconds": (60, 21600),
}
MAX_SOURCE_LANE_SECONDS = 19800


class BackfillPlanError(ValueError):
    pass


def canonical_sha256(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def plan_hash_payload(plan: dict[str, Any]) -> dict[str, Any]:
    missing = [field for field in PLAN_HASH_FIELDS if field not in plan]
    if missing:
        raise BackfillPlanError(
            f"backfill plan missing hash field(s): {', '.join(missing)}"
        )
    return {field: plan[field] for field in PLAN_HASH_FIELDS}


def compute_plan_hash(plan: dict[str, Any]) -> str:
    return canonical_sha256(plan_hash_payload(plan))


def _require_int(policy: dict[str, Any], name: str) -> int:
    value = policy.get(name)
    if isinstance(value, bool) or not isinstance(value, int):
        raise BackfillPlanError(f"backfill policy {name} must be an integer")
    lower, upper = POLICY_BOUNDS[name]
    if value < lower or value > upper:
        raise BackfillPlanError(
            f"backfill policy {name} must be between {lower} and {upper}"
        )
    return value


def _validate_target(target: Any, index: int) -> tuple[str, str, str]:
    if not isinstance(target, dict):
        raise BackfillPlanError(f"backfill target {index} must be an object")
    runtime_id = str(target.get("runtime_id") or "")
    source_id = str(target.get("source_id") or "")
    state = str(target.get("state") or "")
    if not RUNTIME_ID_PATTERN.fullmatch(runtime_id):
        raise BackfillPlanError(f"backfill target {index} has invalid runtime_id")
    if source_id and not SOURCE_ID_PATTERN.fullmatch(source_id):
        raise BackfillPlanError(f"backfill target {index} has invalid source_id")
    if not state:
        raise BackfillPlanError(f"backfill target {index} is missing state")
    return runtime_id, source_id, state


def validate_plan(plan: dict[str, Any], expected_plan_hash: str = "") -> None:
    if not isinstance(plan, dict):
        raise BackfillPlanError("backfill plan must be a JSON object")
    if plan.get("schema_version") != PLAN_SCHEMA_VERSION:
        raise BackfillPlanError(
            f"unsupported backfill plan schema_version; expected {PLAN_SCHEMA_VERSION}"
        )

    mode = str(plan.get("mode") or "")
    if mode not in SUPPORTED_MODES:
        raise BackfillPlanError(f"unsupported backfill mode {mode!r}")
    stack_name = str(plan.get("stack_name") or "")
    stack_file = str(plan.get("stack_file") or "")
    if SUPPORTED_STACK_FILES.get(stack_name) != stack_file:
        raise BackfillPlanError(
            "backfill plan stack name and stack file do not match an approved deployment stack"
        )
    if not SHA256_PATTERN.fullmatch(str(plan.get("stack_config_sha256") or "")):
        raise BackfillPlanError(
            "backfill plan stack_config_sha256 must be a lowercase SHA-256 digest"
        )
    if not str(plan.get("control_plane_ref") or "").strip():
        raise BackfillPlanError("backfill plan control_plane_ref is required")

    policy = plan.get("policy")
    if not isinstance(policy, dict):
        raise BackfillPlanError("backfill plan policy must be an object")
    for name in POLICY_BOUNDS:
        _require_int(policy, name)
    if not isinstance(policy.get("stop_running_before_run"), bool):
        raise BackfillPlanError(
            "backfill policy stop_running_before_run must be a boolean"
        )
    if policy["run_attempt_timeout_seconds"] > policy["wait_timeout_seconds"]:
        raise BackfillPlanError(
            "run_attempt_timeout_seconds cannot exceed wait_timeout_seconds"
        )
    retry_backoff_per_target = policy["retry_backoff_seconds"] * (
        (2 ** max(0, policy["max_attempts"] - 1)) - 1
    )
    attempt_time_per_target = (
        policy["max_attempts"] * policy["run_attempt_timeout_seconds"]
    )
    worst_case_lane_seconds = (
        policy["max_targets_per_source"]
        * (attempt_time_per_target + retry_backoff_per_target)
        + max(0, policy["max_targets_per_source"] - 1)
        * policy["source_cooldown_seconds"]
    )
    if worst_case_lane_seconds > MAX_SOURCE_LANE_SECONDS:
        raise BackfillPlanError(
            f"backfill policy can exceed the {MAX_SOURCE_LANE_SECONDS}-second source lane budget; reduce targets, attempts, or attempt timeout"
        )

    targets = plan.get("targets")
    if not isinstance(targets, list):
        raise BackfillPlanError("backfill plan targets must be an array")
    if not targets and mode != "plan":
        raise BackfillPlanError(
            "executable backfill plans must contain at least one target"
        )
    if len(targets) > policy["max_targets"]:
        raise BackfillPlanError("backfill plan exceeds its max_targets policy")
    target_rows = [
        _validate_target(target, index) for index, target in enumerate(targets)
    ]
    runtime_ids = [row[0] for row in target_rows]
    if len(runtime_ids) != len(set(runtime_ids)):
        raise BackfillPlanError("backfill plan contains duplicate runtime targets")
    requested_runtime_ids = plan.get("requested_runtime_ids")
    if requested_runtime_ids != sorted(runtime_ids):
        raise BackfillPlanError(
            "requested_runtime_ids must be the sorted target runtime IDs"
        )

    expected_groups: dict[str, list[str]] = {}
    for runtime_id, source_id, state in target_rows:
        if state not in EXECUTABLE_TARGET_STATES:
            continue
        if not source_id:
            raise BackfillPlanError(
                f"executable runtime {runtime_id!r} is missing source_id"
            )
        expected_groups.setdefault(source_id, []).append(runtime_id)
    for runtime_ids_for_source in expected_groups.values():
        runtime_ids_for_source.sort()

    groups = plan.get("source_groups")
    if not isinstance(groups, list):
        raise BackfillPlanError("backfill plan source_groups must be an array")
    actual_groups: dict[str, list[str]] = {}
    source_keys: set[str] = set()
    for index, group in enumerate(groups):
        if not isinstance(group, dict):
            raise BackfillPlanError(f"backfill source group {index} must be an object")
        source_id = str(group.get("source_id") or "")
        source_key = str(group.get("source_key") or "")
        group_runtime_ids = group.get("runtime_ids")
        if not SOURCE_ID_PATTERN.fullmatch(source_id):
            raise BackfillPlanError(
                f"backfill source group {index} has invalid source_id"
            )
        if not SOURCE_ID_PATTERN.fullmatch(source_key) or source_key in source_keys:
            raise BackfillPlanError(
                f"backfill source group {index} has invalid or duplicate source_key"
            )
        if source_id in actual_groups:
            raise BackfillPlanError(
                f"backfill source group {index} has duplicate source_id"
            )
        if not isinstance(group_runtime_ids, list) or group_runtime_ids != sorted(
            group_runtime_ids
        ):
            raise BackfillPlanError(
                f"backfill source group {index} runtime_ids must be a sorted array"
            )
        if len(group_runtime_ids) > policy["max_targets_per_source"]:
            raise BackfillPlanError(
                f"backfill source group {index} exceeds max_targets_per_source"
            )
        source_keys.add(source_key)
        actual_groups[source_id] = group_runtime_ids
    if actual_groups != dict(sorted(expected_groups.items())):
        raise BackfillPlanError(
            "backfill source groups do not match executable targets"
        )

    stored_hash = str(plan.get("plan_hash") or "")
    computed_hash = compute_plan_hash(plan)
    if not SHA256_PATTERN.fullmatch(stored_hash) or stored_hash != computed_hash:
        raise BackfillPlanError("backfill plan content does not match plan_hash")
    if expected_plan_hash and stored_hash != expected_plan_hash.strip():
        raise BackfillPlanError(
            f"plan hash mismatch: expected {expected_plan_hash.strip()}, got {stored_hash}"
        )


def validate_execution_context(plan: dict[str, Any], working_directory: Path) -> None:
    stack_path = working_directory / str(plan["stack_file"])
    if not stack_path.is_file():
        raise BackfillPlanError(f"planned stack file is missing: {plan['stack_file']}")
    if file_sha256(stack_path) != plan["stack_config_sha256"]:
        raise BackfillPlanError(
            "stack configuration changed after approval; create a new backfill plan"
        )
    current_ref = os.environ.get("GITHUB_SHA", "").strip()
    if current_ref and current_ref != str(plan["control_plane_ref"]):
        raise BackfillPlanError(
            "control-plane commit changed after approval; create a new backfill plan"
        )


def source_group(plan: dict[str, Any], source_id: str) -> dict[str, Any]:
    matches = [
        group for group in plan["source_groups"] if group["source_id"] == source_id
    ]
    if len(matches) != 1:
        raise BackfillPlanError(
            f"backfill plan must contain exactly one source group for {source_id!r}"
        )
    return matches[0]
