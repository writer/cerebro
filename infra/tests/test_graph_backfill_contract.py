from __future__ import annotations

import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.graph_backfill_contract import (
    BackfillPlanError,
    compute_plan_hash,
    validate_execution_context,
    validate_plan,
)


def _valid_plan() -> dict:
    plan = {
        "schema_version": 2,
        "control_plane_ref": "commit-a",
        "stack_file": "aws/Pulumi.sec-dev.yaml",
        "stack_name": "sec-dev",
        "stack_config_sha256": hashlib.sha256(b"config: {}\n").hexdigest(),
        "mode": "run",
        "requested_runtime_ids": ["runtime-a"],
        "policy": {
            "max_targets": 20,
            "max_targets_per_source": 5,
            "source_parallelism": 2,
            "source_cooldown_seconds": 60,
            "max_attempts": 2,
            "retry_backoff_seconds": 60,
            "run_page_limit": 25,
            "run_graph_page_limit": 25,
            "run_event_limit": 250,
            "wait_timeout_seconds": 1800,
            "run_attempt_timeout_seconds": 900,
            "stop_running_before_run": False,
        },
        "targets": [
            {
                "runtime_id": "runtime-a",
                "source_id": "gcp",
                "family": "asset",
                "schedule_name": "runtime-a",
                "schedule_expression": "rate(6 hours)",
                "state": "backfillable",
                "reason": "runtime is declared and scheduled",
            }
        ],
        "source_groups": [
            {
                "source_id": "gcp",
                "source_key": "gcp-abcd123456",
                "runtime_ids": ["runtime-a"],
            }
        ],
    }
    plan["plan_hash"] = compute_plan_hash(plan)
    return plan


class GraphBackfillContractTest(unittest.TestCase):
    def test_validates_exact_plan_content(self) -> None:
        plan = _valid_plan()

        validate_plan(plan, plan["plan_hash"])

    def test_rejects_source_groups_that_omit_executable_target(self) -> None:
        plan = _valid_plan()
        plan["source_groups"] = []
        plan["plan_hash"] = compute_plan_hash(plan)

        with self.assertRaisesRegex(BackfillPlanError, "source groups do not match"):
            validate_plan(plan, plan["plan_hash"])

    def test_rejects_duplicate_source_lane(self) -> None:
        plan = _valid_plan()
        duplicate = dict(plan["source_groups"][0])
        duplicate["source_key"] = "gcp-duplicate1"
        plan["source_groups"].append(duplicate)
        plan["plan_hash"] = compute_plan_hash(plan)

        with self.assertRaisesRegex(BackfillPlanError, "duplicate source_id"):
            validate_plan(plan, plan["plan_hash"])

    def test_allows_empty_plan_but_not_empty_execution(self) -> None:
        plan = _valid_plan()
        plan["mode"] = "plan"
        plan["requested_runtime_ids"] = []
        plan["targets"] = []
        plan["source_groups"] = []
        plan["plan_hash"] = compute_plan_hash(plan)
        validate_plan(plan, plan["plan_hash"])

        plan["mode"] = "run"
        with self.assertRaisesRegex(BackfillPlanError, "at least one target"):
            validate_plan(plan, plan["plan_hash"])

    def test_rejects_unbounded_policy(self) -> None:
        plan = _valid_plan()
        plan["policy"]["run_event_limit"] = 100001
        plan["plan_hash"] = compute_plan_hash(plan)

        with self.assertRaisesRegex(BackfillPlanError, "run_event_limit"):
            validate_plan(plan, plan["plan_hash"])

    def test_rejects_policy_that_can_outlive_source_job(self) -> None:
        plan = _valid_plan()
        plan["policy"]["max_targets_per_source"] = 20
        plan["policy"]["max_attempts"] = 5
        plan["policy"]["run_attempt_timeout_seconds"] = 1800
        plan["plan_hash"] = compute_plan_hash(plan)

        with self.assertRaisesRegex(BackfillPlanError, "source lane budget"):
            validate_plan(plan, plan["plan_hash"])

    def test_retry_backoff_counts_toward_source_lane_budget(self) -> None:
        plan = _valid_plan()
        plan["policy"].update(
            {
                "max_targets_per_source": 1,
                "max_attempts": 5,
                "retry_backoff_seconds": 1300,
                "run_attempt_timeout_seconds": 300,
            }
        )
        plan["plan_hash"] = compute_plan_hash(plan)

        with self.assertRaisesRegex(BackfillPlanError, "source lane budget"):
            validate_plan(plan, plan["plan_hash"])

    def test_execution_context_binds_stack_file_and_commit(self) -> None:
        plan = _valid_plan()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stack_file = root / "aws" / "Pulumi.sec-dev.yaml"
            stack_file.parent.mkdir()
            stack_file.write_bytes(b"config: {}\n")
            with mock.patch.dict(os.environ, {"GITHUB_SHA": "commit-a"}):
                validate_execution_context(plan, root)

            stack_file.write_bytes(b"config:\n  changed: true\n")
            with self.assertRaisesRegex(
                BackfillPlanError, "stack configuration changed"
            ):
                validate_execution_context(plan, root)

    def test_execution_context_rejects_new_commit(self) -> None:
        plan = _valid_plan()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stack_file = root / "aws" / "Pulumi.sec-dev.yaml"
            stack_file.parent.mkdir()
            stack_file.write_bytes(b"config: {}\n")
            with mock.patch.dict(os.environ, {"GITHUB_SHA": "commit-b"}):
                with self.assertRaisesRegex(
                    BackfillPlanError, "control-plane commit changed"
                ):
                    validate_execution_context(plan, root)


if __name__ == "__main__":
    unittest.main()
