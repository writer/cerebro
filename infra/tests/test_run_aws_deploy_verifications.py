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

    def test_graph_failure_degrades_when_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            summary_path = Path(temp_dir) / "summary.md"
            output_path = Path(temp_dir) / "outputs.txt"
            with (
                patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(summary_path)}),
                patch(
                    "scripts.run_aws_deploy_verifications._stream_graph_health",
                    return_value=run_aws_deploy_verifications.GraphHealthResult(
                        23,
                        "ERROR: latest graph ingest run failed for 1 runtime(s): writer-runtime:graph-ingest:writer-runtime:20260601T000000Z:status=failed",
                    ),
                ),
            ):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    status = run_aws_deploy_verifications.main(
                        [
                            "--stack-file",
                            "aws/Pulumi.go-prod.yaml",
                            "--graph-health",
                            "--graph-health-output",
                            str(Path(temp_dir) / "graph.tsv"),
                            "--allow-graph-health-degradation",
                            "--github-output",
                            str(output_path),
                        ]
                    )
                summary = summary_path.read_text(encoding="utf-8")
                outputs = output_path.read_text(encoding="utf-8")

        self.assertEqual(status, 0)
        self.assertIn("Graph health verification degraded (go-prod)", summary)
        self.assertIn("graph_health_degraded=true", outputs)
        self.assertIn("graph_health_degradation_category=stale_or_transient_ingest_run", outputs)

    def test_graph_integrity_failure_remains_blocking_when_degradation_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch(
                "scripts.run_aws_deploy_verifications._stream_graph_health",
                return_value=run_aws_deploy_verifications.GraphHealthResult(
                    23,
                    "ERROR: graph integrity failed 1 checks: open_findings_missing_primary_has_finding_edge=1",
                ),
            ):
                status = run_aws_deploy_verifications.main(
                    [
                        "--stack-file",
                        "aws/Pulumi.go-prod.yaml",
                        "--graph-health",
                        "--graph-health-output",
                        str(Path(temp_dir) / "graph.tsv"),
                        "--allow-graph-health-degradation",
                    ]
                )

        self.assertEqual(status, 23)

    def test_blocking_graph_failure_can_create_followup_issue(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with (
                patch(
                    "scripts.run_aws_deploy_verifications._stream_graph_health",
                    return_value=run_aws_deploy_verifications.GraphHealthResult(
                        23,
                        "ERROR: graph integrity failed 1 checks: open_findings_missing_primary_has_finding_edge=1",
                    ),
                ),
                patch("scripts.run_aws_deploy_verifications._create_graph_health_issue") as create_issue,
            ):
                status = run_aws_deploy_verifications.main(
                    [
                        "--stack-file",
                        "aws/Pulumi.sec-dev.yaml",
                        "--graph-health",
                        "--graph-health-output",
                        str(Path(temp_dir) / "graph.tsv"),
                        "--allow-graph-health-degradation",
                        "--graph-health-issue",
                        "--graph-health-artifact-name",
                        "graph-health-sec-dev",
                    ]
                )

        self.assertEqual(status, 23)
        create_issue.assert_called_once_with(
            "sec-dev",
            23,
            "blocking_graph_health_failure",
            "graph-health-sec-dev",
            degraded=False,
        )

    def test_graph_failure_heals_then_reruns_health(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            results = iter(
                [
                    run_aws_deploy_verifications.GraphHealthResult(
                        23,
                        "ERROR: latest graph ingest run failed for 1 runtime(s): writer-runtime:graph-ingest:writer-runtime:20260601T000000Z:status=failed",
                    ),
                    run_aws_deploy_verifications.GraphHealthResult(0, ""),
                ]
            )
            with (
                patch("scripts.run_aws_deploy_verifications._stream_graph_health", side_effect=lambda *_args: next(results)) as stream,
                patch("scripts.run_aws_deploy_verifications._attempt_graph_health_heal", return_value=True) as heal,
            ):
                status = run_aws_deploy_verifications.main(
                    [
                        "--stack-file",
                        "aws/Pulumi.go-prod.yaml",
                        "--graph-health",
                        "--graph-health-output",
                        str(Path(temp_dir) / "graph.tsv"),
                        "--allow-graph-health-degradation",
                        "--graph-health-heal",
                    ]
                )

        self.assertEqual(status, 0)
        self.assertEqual(stream.call_count, 2)
        heal.assert_called_once()

    def test_graph_degradation_can_create_followup_issue(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with (
                patch(
                    "scripts.run_aws_deploy_verifications._stream_graph_health",
                    return_value=run_aws_deploy_verifications.GraphHealthResult(
                        23,
                        "ERROR: latest graph ingest run is stale-running for 1 runtime(s): writer-runtime:graph-ingest:writer-runtime:20260601T000000Z:status=running",
                    ),
                ),
                patch("scripts.run_aws_deploy_verifications._create_graph_health_issue") as create_issue,
            ):
                status = run_aws_deploy_verifications.main(
                    [
                        "--stack-file",
                        "aws/Pulumi.go-prod.yaml",
                        "--graph-health",
                        "--graph-health-output",
                        str(Path(temp_dir) / "graph.tsv"),
                        "--allow-graph-health-degradation",
                        "--graph-health-issue",
                        "--graph-health-artifact-name",
                        "graph-health-go-prod",
                    ]
                )

        self.assertEqual(status, 0)
        create_issue.assert_called_once_with("go-prod", 23, "stale_ingest_run", "graph-health-go-prod")

    def test_graph_health_runtime_ids_parse_ingest_summaries(self) -> None:
        diagnostics = (
            "latest graph ingest run failed for 1 runtime(s): "
            "writer-vulnview-asset:graph-ingest:writer-vulnview-asset:20260601T172200Z:status=failed"
        )

        self.assertEqual(run_aws_deploy_verifications._graph_health_runtime_ids(diagnostics), ["writer-vulnview-asset"])


if __name__ == "__main__":
    unittest.main()
