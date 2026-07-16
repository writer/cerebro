from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.execute_graph_backfill_plan import (
    _failure_decision,
    _run_streaming,
    execute_plan,
)
from scripts.graph_backfill_contract import (
    BackfillPlanError,
    STATE_SCHEMA_VERSION,
    compute_plan_hash,
)


def _plan(*, mode: str = "run", runtime_ids: list[str] | None = None) -> dict:
    runtime_ids = runtime_ids or ["runtime-a", "runtime-b"]
    stack_bytes = b"config: {}\n"
    plan = {
        "schema_version": 2,
        "control_plane_ref": "commit-a",
        "stack_file": "aws/Pulumi.sec-dev.yaml",
        "stack_name": "sec-dev",
        "stack_config_sha256": hashlib.sha256(stack_bytes).hexdigest(),
        "mode": mode,
        "requested_runtime_ids": sorted(runtime_ids),
        "policy": {
            "max_targets": 20,
            "max_targets_per_source": 5,
            "source_parallelism": 2,
            "source_cooldown_seconds": 0,
            "max_attempts": 2,
            "retry_backoff_seconds": 5,
            "run_page_limit": 25,
            "run_graph_page_limit": 25,
            "run_event_limit": 250,
            "wait_timeout_seconds": 1800,
            "run_attempt_timeout_seconds": 900,
            "stop_running_before_run": False,
        },
        "targets": [
            {
                "runtime_id": runtime_id,
                "source_id": "gcp",
                "family": "asset",
                "schedule_name": runtime_id,
                "schedule_expression": "rate(6 hours)",
                "state": "backfillable",
                "reason": "runtime is declared and scheduled",
            }
            for runtime_id in sorted(runtime_ids)
        ],
        "source_groups": [
            {
                "source_id": "gcp",
                "source_key": "gcp-abcd123456",
                "runtime_ids": sorted(runtime_ids),
            }
        ],
    }
    plan["plan_hash"] = compute_plan_hash(plan)
    return plan


class ExecuteGraphBackfillPlanTest(unittest.TestCase):
    def test_failure_classification_identifies_shared_source_failures(self) -> None:
        cases = {
            "authentication failed": ("authentication", False, True),
            "permission denied": ("authorization", False, True),
            "too many requests": ("rate_limited", True, True),
            "request timed out": ("transient", True, False),
            "lease_not_acquired": ("transient", True, False),
        }
        for output, expected in cases.items():
            with self.subTest(output=output):
                decision = _failure_decision(output)
                self.assertEqual(
                    (
                        decision.failure_class,
                        decision.retryable,
                        decision.blocks_source,
                    ),
                    expected,
                )

    def test_streaming_runner_preserves_bounded_output_for_classification(self) -> None:
        result = _run_streaming(
            [
                sys.executable,
                "-c",
                "import sys; print('complete'); print('Invalid token', file=sys.stderr)",
            ],
            Path.cwd(),
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn("complete", result.stdout)
        self.assertIn("Invalid token", result.stderr)

    def test_execute_plan_requires_expected_hash(self) -> None:
        plan = _plan()
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(
                BackfillPlanError, "expected plan hash is required"
            ):
                execute_plan(
                    plan,
                    "",
                    "gcp",
                    Path(directory) / "state.json",
                    verify_context=False,
                )

    def test_execute_plan_rejects_hash_mismatch(self) -> None:
        plan = _plan()
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(BackfillPlanError, "plan hash mismatch"):
                execute_plan(
                    plan,
                    "0" * 64,
                    "gcp",
                    Path(directory) / "state.json",
                    verify_context=False,
                )

    def test_execute_plan_rehashes_content_before_running(self) -> None:
        plan = _plan()
        expected = plan["plan_hash"]
        plan["policy"]["run_event_limit"] = 100000
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(BackfillPlanError, "content does not match"):
                execute_plan(
                    plan,
                    expected,
                    "gcp",
                    Path(directory) / "state.json",
                    verify_context=False,
                )

    def test_execute_plan_builds_allowlisted_bounded_commands(self) -> None:
        plan = _plan(runtime_ids=["runtime-a"])
        seen: list[list[str]] = []

        def run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
            seen.append(command)
            return subprocess.CompletedProcess(command, 0, "ok\n", "")

        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "state.json"
            status = execute_plan(
                plan,
                plan["plan_hash"],
                "gcp",
                state_path,
                verify_context=False,
                run_command=run,
            )
            state = json.loads(state_path.read_text(encoding="utf-8"))

        self.assertEqual(status, 0)
        self.assertEqual(
            seen[0][0:4],
            ["uv", "run", "python", "scripts/verify_source_runtime_ecs.py"],
        )
        self.assertIn("--run", seen[0])
        self.assertNotIn("--allow-lease-contention-skip", seen[0])
        self.assertEqual(seen[0][seen[0].index("--runtime-id") + 1], "runtime-a")
        self.assertEqual(seen[0][seen[0].index("--target-concurrency") + 1], "1")
        self.assertEqual(state["status"], "completed")

    def test_transient_failure_retries_with_backoff(self) -> None:
        plan = _plan(runtime_ids=["runtime-a"])
        results = [
            subprocess.CompletedProcess([], 1, "", "request timed out"),
            subprocess.CompletedProcess([], 0, "ok", ""),
        ]
        sleeps: list[float] = []

        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "state.json"
            status = execute_plan(
                plan,
                plan["plan_hash"],
                "gcp",
                state_path,
                verify_context=False,
                run_command=lambda *_args, **_kwargs: results.pop(0),
                sleep=sleeps.append,
            )
            state = json.loads(state_path.read_text(encoding="utf-8"))

        self.assertEqual(status, 0)
        self.assertEqual(sleeps, [5])
        self.assertEqual(state["targets"][0]["attempts"], 2)
        self.assertEqual(state["targets"][0]["status"], "completed")

    def test_authentication_failure_opens_source_circuit(self) -> None:
        plan = _plan()
        run = mock.Mock(
            return_value=subprocess.CompletedProcess(
                [], 1, "", "HTTP 401 Invalid token"
            )
        )

        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "state.json"
            status = execute_plan(
                plan,
                plan["plan_hash"],
                "gcp",
                state_path,
                verify_context=False,
                run_command=run,
            )
            state = json.loads(state_path.read_text(encoding="utf-8"))

        self.assertEqual(status, 1)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(
            [target["status"] for target in state["targets"]], ["failed", "blocked"]
        )
        self.assertEqual(
            [target["failure_class"] for target in state["targets"]],
            ["authentication", "authentication"],
        )

    def test_resume_skips_completed_runtime_and_retries_incomplete_runtime(
        self,
    ) -> None:
        plan = _plan()
        completed_at = "2026-07-15T00:00:00Z"
        resume = {
            "schema_version": STATE_SCHEMA_VERSION,
            "plan_hash": plan["plan_hash"],
            "mode": "run",
            "source_id": "gcp",
            "targets": [
                {
                    "runtime_id": "runtime-a",
                    "status": "completed",
                    "attempts": 1,
                    "started_at": completed_at,
                    "completed_at": completed_at,
                },
                {
                    "runtime_id": "runtime-b",
                    "status": "failed",
                    "attempts": 2,
                    "failure_class": "transient",
                },
            ],
        }
        seen_runtime_ids: list[str] = []

        def run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
            seen_runtime_ids.append(command[command.index("--runtime-id") + 1])
            return subprocess.CompletedProcess(command, 0, "ok", "")

        with tempfile.TemporaryDirectory() as directory:
            resume_path = Path(directory) / "resume.json"
            state_path = Path(directory) / "state.json"
            resume_path.write_text(json.dumps(resume), encoding="utf-8")
            status = execute_plan(
                plan,
                plan["plan_hash"],
                "gcp",
                state_path,
                resume_state_path=resume_path,
                verify_context=False,
                run_command=run,
            )
            state = json.loads(state_path.read_text(encoding="utf-8"))

        self.assertEqual(status, 0)
        self.assertEqual(seen_runtime_ids, ["runtime-b"])
        self.assertTrue(state["targets"][0]["resumed"])
        self.assertEqual(state["targets"][1]["attempts"], 3)

    def test_resume_rejects_checkpoint_with_different_target_set(self) -> None:
        plan = _plan()
        resume = {
            "schema_version": STATE_SCHEMA_VERSION,
            "plan_hash": plan["plan_hash"],
            "mode": "run",
            "source_id": "gcp",
            "targets": [
                {"runtime_id": "runtime-a", "status": "completed", "attempts": 1}
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            resume_path = Path(directory) / "resume.json"
            resume_path.write_text(json.dumps(resume), encoding="utf-8")
            with self.assertRaisesRegex(BackfillPlanError, "targets do not match"):
                execute_plan(
                    plan,
                    plan["plan_hash"],
                    "gcp",
                    Path(directory) / "state.json",
                    resume_state_path=resume_path,
                    verify_context=False,
                )

    def test_plan_mode_cannot_execute(self) -> None:
        plan = _plan(mode="plan", runtime_ids=["runtime-a"])
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(BackfillPlanError, "plan mode"):
                execute_plan(
                    plan,
                    plan["plan_hash"],
                    "gcp",
                    Path(directory) / "state.json",
                    verify_context=False,
                )


if __name__ == "__main__":
    unittest.main()
