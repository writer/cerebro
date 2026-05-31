from __future__ import annotations

import argparse
import contextlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import run_aws_deploy_verifications


class FakeProcess:
    def __init__(self, status: int, *, timeout_once: bool = False) -> None:
        self.status = status
        self.timeout_once = timeout_once
        self.terminated = False
        self.killed = False
        self.wait_timeouts: list[int | None] = []

    def wait(self, timeout: int | None = None) -> int:
        self.wait_timeouts.append(timeout)
        if timeout is not None and self.timeout_once:
            self.timeout_once = False
            raise subprocess.TimeoutExpired("fake", timeout)
        return self.status

    def terminate(self) -> None:
        self.terminated = True

    def kill(self) -> None:
        self.killed = True


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
        self.assertEqual(command[command.index("--failed-run-retry-seconds") + 1], "0")
        self.assertEqual(command[command.index("--run-attempt-timeout-seconds") + 1], "300")
        self.assertEqual(command[command.index("--wait-timeout-seconds") + 1], "300")
        self.assertIn("--stop-running-before-run", command)

    def test_source_failure_reports_warning_but_does_not_fail_without_graph_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            summary_path = Path(temp_dir) / "summary.md"
            with (
                patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(summary_path)}),
                patch("scripts.run_aws_deploy_verifications._start_process", return_value=FakeProcess(1)),
                patch("scripts.run_aws_deploy_verifications._stream_graph_health", return_value=0),
            ):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
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

    def test_source_runtime_default_grace_after_graph_health_is_short(self) -> None:
        fake_source = FakeProcess(0)
        with (
            patch("scripts.run_aws_deploy_verifications._start_process", return_value=fake_source),
            patch("scripts.run_aws_deploy_verifications._stream_graph_health", return_value=0),
        ):
            status = run_aws_deploy_verifications.main(
                [
                    "--stack-file",
                    "aws/Pulumi.go-prod.yaml",
                    "--source-runtime-verify",
                    "--graph-health",
                ]
            )

        self.assertEqual(status, 0)
        self.assertEqual(fake_source.wait_timeouts, [10])

    def test_source_runtime_timeout_after_graph_health_is_degraded(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            summary_path = Path(temp_dir) / "summary.md"
            fake_source = FakeProcess(0, timeout_once=True)
            with (
                patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(summary_path)}),
                patch("scripts.run_aws_deploy_verifications._start_process", return_value=fake_source),
                patch("scripts.run_aws_deploy_verifications._stream_graph_health", return_value=0),
            ):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    status = run_aws_deploy_verifications.main(
                        [
                            "--stack-file",
                            "aws/Pulumi.go-prod.yaml",
                            "--source-runtime-verify",
                            "--graph-health",
                            "--graph-health-output",
                            str(Path(temp_dir) / "graph.tsv"),
                            "--source-runtime-grace-seconds",
                            "1",
                        ]
                    )
                summary = summary_path.read_text(encoding="utf-8")

        self.assertEqual(status, 0)
        self.assertTrue(fake_source.terminated)
        self.assertFalse(fake_source.killed)
        self.assertIn("Source runtime verification degraded (go-prod)", summary)

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
