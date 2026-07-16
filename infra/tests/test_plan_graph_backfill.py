from __future__ import annotations

from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.plan_graph_backfill import (
    BackfillTarget,
    _missing_runtime_ids_from_diagnostics,
    _verify_command,
    backfill_run,
    plan_backfill,
)


def _args(
    stack_file: Path,
    *,
    mode: str = "plan",
    control_plane_ref: str = "commit-a",
    max_targets: int = 20,
) -> SimpleNamespace:
    return SimpleNamespace(
        stack_file=stack_file,
        mode=mode,
        control_plane_ref=control_plane_ref,
        max_targets=max_targets,
        max_targets_per_source=5,
        source_parallelism=2,
        source_cooldown_seconds=60,
        max_attempts=2,
        retry_backoff_seconds=30,
        run_page_limit=25,
        run_graph_page_limit=25,
        run_event_limit=250,
        wait_timeout_seconds=1800,
        run_attempt_timeout_seconds=900,
        stop_running_before_run=False,
    )


class PlanGraphBackfillTest(unittest.TestCase):
    def test_plan_backfill_classifies_declared_scheduled_runtime(self) -> None:
        config = {
            "sourceRuntimes": [
                {
                    "id": "runtime-a",
                    "sourceId": "gcp",
                    "config": {"family": "asset_metadata"},
                },
            ],
            "orchestratorSchedules": [
                {
                    "name": "runtime-a-schedule",
                    "scheduleExpression": "rate(6 hours)",
                    "command": ["orchestrator", "run", "runtime_id=runtime-a"],
                }
            ],
        }

        targets = plan_backfill(config, ["runtime-missing", "runtime-a"])

        self.assertEqual(
            [target.runtime_id for target in targets], ["runtime-a", "runtime-missing"]
        )
        self.assertEqual(targets[0].state, "backfillable")
        self.assertEqual(targets[0].source_id, "gcp")
        self.assertEqual(targets[1].state, "not_declared")

    def test_extract_missing_runtime_ids_from_diagnostics(self) -> None:
        diagnostics = "ERROR: missing graph ingest run history for 2 declared runtime(s): runtime-a, runtime-b; latest graph ingest run failed"

        self.assertEqual(
            _missing_runtime_ids_from_diagnostics(diagnostics),
            ["runtime-a", "runtime-b"],
        )

    def test_extract_missing_runtime_ids_stops_before_integrity_failure(self) -> None:
        diagnostics = (
            "ERROR: missing graph ingest run history for 1 declared runtime(s): runtime-a; "
            "graph integrity failed 1 checks: entities_missing_typed_properties=620650"
        )

        self.assertEqual(
            _missing_runtime_ids_from_diagnostics(diagnostics), ["runtime-a"]
        )

    def test_plan_groups_targets_by_source_with_stable_keys(self) -> None:
        targets = [
            BackfillTarget("runtime-b", "gcp", "service", "", "", "backfillable", ""),
            BackfillTarget("runtime-a", "gcp", "secret", "", "", "backfillable", ""),
            BackfillTarget("runtime-c", "okta", "audit", "", "", "backfillable", ""),
        ]
        with tempfile.TemporaryDirectory() as directory:
            stack_file = Path(directory) / "Pulumi.sec-dev.yaml"
            stack_file.write_text("config: {}\n", encoding="utf-8")

            plan = backfill_run(
                _args(stack_file), [target.runtime_id for target in targets], targets
            )

        self.assertEqual(
            [group.source_id for group in plan.source_groups], ["gcp", "okta"]
        )
        self.assertEqual(plan.source_groups[0].runtime_ids, ["runtime-a", "runtime-b"])
        self.assertRegex(plan.source_groups[0].source_key, r"^gcp-[0-9a-f]{10}$")

    def test_plan_marks_unlaunchable_schedule_states_non_executable(self) -> None:
        config = {
            "sourceRuntimes": [
                {
                    "id": "runtime-ambiguous",
                    "sourceId": "gcp",
                    "config": {"family": "a"},
                },
                {
                    "id": "runtime-disabled",
                    "sourceId": "gcp",
                    "config": {"family": "b"},
                },
                {
                    "id": "runtime-unscheduled",
                    "sourceId": "gcp",
                    "config": {"family": "c"},
                },
            ],
            "orchestratorSchedules": [
                {
                    "name": "a-1",
                    "command": [
                        "orchestrator",
                        "run",
                        "runtime_id=runtime-ambiguous",
                    ],
                },
                {
                    "name": "a-2",
                    "command": [
                        "orchestrator",
                        "run",
                        "runtime_id=runtime-ambiguous",
                    ],
                },
                {
                    "name": "b",
                    "state": "DISABLED",
                    "command": [
                        "orchestrator",
                        "run",
                        "runtime_id=runtime-disabled",
                    ],
                },
            ],
        }

        targets = plan_backfill(
            config,
            ["runtime-unscheduled", "runtime-disabled", "runtime-ambiguous"],
        )

        self.assertEqual(
            {target.runtime_id: target.state for target in targets},
            {
                "runtime-ambiguous": "ambiguous_schedule",
                "runtime-disabled": "schedule_disabled",
                "runtime-unscheduled": "missing_schedule",
            },
        )

    def test_plan_hash_binds_stack_contents_and_control_plane_commit(self) -> None:
        targets = [
            BackfillTarget("runtime-a", "gcp", "asset", "", "", "backfillable", "")
        ]
        with tempfile.TemporaryDirectory() as directory:
            stack_file = Path(directory) / "Pulumi.sec-dev.yaml"
            stack_file.write_text("config:\n  value: one\n", encoding="utf-8")
            first = backfill_run(_args(stack_file), ["runtime-a"], targets)
            same = backfill_run(_args(stack_file), ["runtime-a"], targets)
            other_ref = backfill_run(
                _args(stack_file, control_plane_ref="commit-b"), ["runtime-a"], targets
            )
            stack_file.write_text("config:\n  value: two\n", encoding="utf-8")
            other_config = backfill_run(_args(stack_file), ["runtime-a"], targets)

        self.assertEqual(first.plan_hash, same.plan_hash)
        self.assertNotEqual(first.plan_hash, other_ref.plan_hash)
        self.assertNotEqual(first.plan_hash, other_config.plan_hash)

    def test_plan_hash_is_reusable_across_explicit_execution_mode(self) -> None:
        targets = [
            BackfillTarget("runtime-a", "gcp", "asset", "", "", "backfillable", "")
        ]
        with tempfile.TemporaryDirectory() as directory:
            stack_file = Path(directory) / "Pulumi.sec-dev.yaml"
            stack_file.write_text("config: {}\n", encoding="utf-8")
            planned = backfill_run(_args(stack_file), ["runtime-a"], targets)
            run = backfill_run(_args(stack_file, mode="run"), ["runtime-a"], targets)

        self.assertEqual(planned.plan_hash, run.plan_hash)

    def test_run_rejects_non_executable_target(self) -> None:
        targets = [
            BackfillTarget("runtime-a", "", "", "", "", "quarantined", "credentials")
        ]
        with tempfile.TemporaryDirectory() as directory:
            stack_file = Path(directory) / "Pulumi.sec-dev.yaml"
            stack_file.write_text("config: {}\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "non-executable"):
                backfill_run(_args(stack_file, mode="run"), ["runtime-a"], targets)

    def test_plan_enforces_maximum_target_count(self) -> None:
        targets = [
            BackfillTarget("runtime-a", "gcp", "asset", "", "", "backfillable", ""),
            BackfillTarget("runtime-b", "gcp", "asset", "", "", "backfillable", ""),
        ]
        with tempfile.TemporaryDirectory() as directory:
            stack_file = Path(directory) / "Pulumi.sec-dev.yaml"
            stack_file.write_text("config: {}\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "max_targets"):
                backfill_run(
                    _args(stack_file, max_targets=1),
                    ["runtime-a", "runtime-b"],
                    targets,
                )

    def test_verifier_command_is_typed_bounded_and_single_runtime(self) -> None:
        target = BackfillTarget("runtime-a", "gcp", "asset", "", "", "backfillable", "")
        with tempfile.TemporaryDirectory() as directory:
            stack_file = Path(directory) / "Pulumi.sec-dev.yaml"
            stack_file.write_text("config: {}\n", encoding="utf-8")
            run = backfill_run(_args(stack_file, mode="run"), ["runtime-a"], [target])

        command = _verify_command(run, "gcp", "runtime-a")

        self.assertEqual(
            command[0:4],
            ["uv", "run", "python", "scripts/verify_source_runtime_ecs.py"],
        )
        self.assertIn("--run", command)
        self.assertIn("--run-page-limit", command)
        self.assertIn("--run-event-limit", command)
        self.assertNotIn("--allow-lease-contention-skip", command)
        self.assertEqual(command.count("--runtime-id"), 1)
        self.assertEqual(command[command.index("--target-concurrency") + 1], "1")

    def test_plan_backfill_marks_temporarily_disabled_runtime_quarantined(self) -> None:
        config = {
            "sourceRuntimes": [],
            "temporarilyDisabledSourceRuntimes": [
                {
                    "runtimeId": "runtime-disabled",
                    "reason": "invalid_credentials",
                    "reviewDeadline": "2026-07-10",
                }
            ],
        }

        targets = plan_backfill(config, ["runtime-disabled"])

        self.assertEqual(targets[0].state, "quarantined")
        self.assertIn("invalid_credentials", targets[0].reason)
        self.assertIn("review_deadline=2026-07-10", targets[0].reason)


if __name__ == "__main__":
    unittest.main()
