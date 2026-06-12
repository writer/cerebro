import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.execute_graph_backfill_plan import execute_plan


class ExecuteGraphBackfillPlanTest(unittest.TestCase):
    def test_execute_plan_requires_expected_hash(self) -> None:
        with self.assertRaisesRegex(ValueError, "expected plan hash is required"):
            execute_plan({"mode": "dry-run", "plan_hash": "abc", "commands": []}, "")

    def test_execute_plan_rejects_hash_mismatch(self) -> None:
        with self.assertRaisesRegex(ValueError, "plan hash mismatch"):
            execute_plan({"mode": "dry-run", "plan_hash": "abc", "commands": []}, "def")

    def test_execute_plan_runs_json_commands_without_shell(self) -> None:
        plan = {
            "mode": "dry-run",
            "plan_hash": "abc",
            "commands": [["python", "-c", "print('ok')"]],
        }

        with mock.patch("scripts.execute_graph_backfill_plan.subprocess.run") as run:
            self.assertEqual(execute_plan(plan, "abc"), 0)

        run.assert_called_once_with(["python", "-c", "print('ok')"], check=True)

    def test_execute_plan_rejects_plan_mode(self) -> None:
        with self.assertRaisesRegex(ValueError, "plan mode"):
            execute_plan({"mode": "plan", "plan_hash": "abc", "commands": []}, "abc")

    def test_execute_plan_surfaces_command_failure(self) -> None:
        plan = {
            "mode": "run",
            "plan_hash": "abc",
            "commands": [["false"]],
        }

        with mock.patch(
            "scripts.execute_graph_backfill_plan.subprocess.run",
            side_effect=subprocess.CalledProcessError(1, ["false"]),
        ):
            with self.assertRaises(subprocess.CalledProcessError):
                execute_plan(plan, "abc")


if __name__ == "__main__":
    unittest.main()
