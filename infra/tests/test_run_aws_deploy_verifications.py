from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import run_aws_deploy_verifications


class FakeProcess:
    def __init__(self, status: int) -> None:
        self.status = status

    def wait(self) -> int:
        return self.status


class RunAwsDeployVerificationsTest(unittest.TestCase):
    def test_source_runtime_command_includes_parallelism_and_stop_flag(self) -> None:
        args = argparse.Namespace(
            stack_file=Path("aws/Pulumi.sec-dev.yaml"),
            source_target_concurrency=2,
            stop_running_source_before_run=True,
        )

        command = run_aws_deploy_verifications._source_runtime_command(args)

        self.assertIn("scripts/verify_source_runtime_ecs.py", command)
        self.assertIn("--target-concurrency", command)
        self.assertEqual(command[command.index("--target-concurrency") + 1], "2")
        self.assertIn("--stop-running-before-run", command)

    def test_source_failure_reports_warning_but_does_not_fail_without_graph_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            summary_path = Path(temp_dir) / "summary.md"
            with (
                patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(summary_path)}),
                patch("scripts.run_aws_deploy_verifications._start_process", return_value=FakeProcess(1)),
                patch("scripts.run_aws_deploy_verifications._stream_graph_health", return_value=0),
            ):
                status = run_aws_deploy_verifications.main(
                    [
                        "--stack-file",
                        "aws/Pulumi.sec-dev.yaml",
                        "--source-runtime-verify",
                        "--graph-health",
                        "--graph-health-output",
                        str(Path(temp_dir) / "graph.tsv"),
                    ]
                )
                summary = summary_path.read_text(encoding="utf-8")

        self.assertEqual(status, 0)
        self.assertIn("Source runtime verification degraded (sec-dev)", summary)

    def test_graph_failure_remains_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with (
                patch("scripts.run_aws_deploy_verifications._start_process", return_value=FakeProcess(0)),
                patch("scripts.run_aws_deploy_verifications._stream_graph_health", return_value=23),
            ):
                status = run_aws_deploy_verifications.main(
                    [
                        "--stack-file",
                        "aws/Pulumi.go-prod.yaml",
                        "--source-runtime-verify",
                        "--graph-health",
                        "--graph-health-output",
                        str(Path(temp_dir) / "graph.tsv"),
                    ]
                )

        self.assertEqual(status, 23)


if __name__ == "__main__":
    unittest.main()
