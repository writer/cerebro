from __future__ import annotations

import argparse
import contextlib
from datetime import UTC, datetime, timedelta
import io
import json
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


class FakeHTTPResponse:
    def __init__(self, payload: object) -> None:
        self.payload = payload

    def __enter__(self) -> FakeHTTPResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps(self.payload).encode("utf-8")


class RunAwsDeployVerificationsTest(unittest.TestCase):
    def test_source_runtime_command_includes_parallelism_and_stop_flag(self) -> None:
        args = argparse.Namespace(
            stack_file=Path("aws/Pulumi.sec-dev.yaml"),
            source_id="aws",
            runtime_id=["writer-aws-sec-dev-us1-public-endpoint"],
            family=["public_endpoint"],
            source_target_concurrency=2,
            stop_running_source_before_run=True,
            source_runtime_dry_run=False,
            source_runtime_observability_targets=False,
            source_runtime_allow_missing_targets=False,
        )

        command = run_aws_deploy_verifications._source_runtime_command(args)

        self.assertIn("scripts/verify_source_runtime_ecs.py", command)
        self.assertIn("--target-concurrency", command)
        self.assertEqual(command[command.index("--target-concurrency") + 1], "2")
        self.assertEqual(command[command.index("--source-id") + 1], "aws")
        self.assertIn("--runtime-id", command)
        self.assertIn("writer-aws-sec-dev-us1-public-endpoint", command)
        self.assertIn("--family", command)
        self.assertIn("public_endpoint", command)
        self.assertEqual(command[command.index("--failed-run-retry-seconds") + 1], "0")
        self.assertEqual(command[command.index("--run-attempt-timeout-seconds") + 1], "300")
        self.assertEqual(command[command.index("--wait-timeout-seconds") + 1], "300")
        self.assertIn("--stop-running-before-run", command)

    def test_source_runtime_command_supports_go_prod_panopticon_readiness_only(self) -> None:
        args = argparse.Namespace(
            stack_file=Path("aws/Pulumi.go-prod.yaml"),
            source_id="panopticon",
            runtime_id=[],
            family=[],
            source_target_concurrency=2,
            stop_running_source_before_run=False,
            source_runtime_dry_run=True,
            source_runtime_observability_targets=True,
            source_runtime_allow_missing_targets=True,
        )

        command = run_aws_deploy_verifications._source_runtime_command(args)

        self.assertIn("--dry-run", command)
        self.assertIn("--observability-targets", command)
        self.assertIn("--allow-missing-targets", command)
        self.assertNotIn("--run", command)
        self.assertEqual(command[command.index("--source-id") + 1], "panopticon")
        self.assertEqual(command[command.index("--target-concurrency") + 1], "2")

    def test_source_runtime_command_uses_selected_source_from_repeated_args(self) -> None:
        args = argparse.Namespace(
            stack_file=Path("aws/Pulumi.go-prod.yaml"),
            source_ids=["panopticon", "okta"],
            runtime_id=[],
            family=[],
            source_target_concurrency=2,
            stop_running_source_before_run=False,
            source_runtime_dry_run=False,
            source_runtime_observability_targets=True,
            source_runtime_allow_missing_targets=False,
        )

        command = run_aws_deploy_verifications._source_runtime_command(args, "okta")

        self.assertEqual(command[command.index("--source-id") + 1], "okta")
        self.assertIn("--observability-targets", command)

    def test_source_runtime_verify_starts_each_requested_source(self) -> None:
        started_commands: list[list[str]] = []

        def fake_start(command: list[str]) -> FakeProcess:
            started_commands.append(command)
            return FakeProcess(0)

        with patch("scripts.run_aws_deploy_verifications._start_process", side_effect=fake_start):
            status = run_aws_deploy_verifications.main(
                [
                    "--stack-file",
                    "aws/Pulumi.go-prod.yaml",
                    "--source-runtime-verify",
                    "--source-id",
                    "panopticon",
                    "--source-id",
                    "okta",
                ]
            )

        self.assertEqual(status, 0)
        self.assertEqual([command[command.index("--source-id") + 1] for command in started_commands], ["panopticon", "okta"])

    def test_graph_health_command_uses_fast_deploy_retry_defaults(self) -> None:
        args = argparse.Namespace(
            stack_file=Path("aws/Pulumi.go-prod.yaml"),
            graph_health_command_retry_seconds=run_aws_deploy_verifications.DEFAULT_GRAPH_HEALTH_COMMAND_RETRY_SECONDS,
            graph_health_ingest_retry_seconds=run_aws_deploy_verifications.DEFAULT_GRAPH_HEALTH_INGEST_RETRY_SECONDS,
        )

        command = run_aws_deploy_verifications._graph_health_command(args)

        self.assertEqual(command[command.index("--graph-command-retry-seconds") + 1], "300")
        self.assertEqual(command[command.index("--ingest-health-retry-seconds") + 1], "0")
        self.assertIn("--require-bundled-health", command)

    def test_graph_health_command_allows_retry_overrides(self) -> None:
        args = argparse.Namespace(
            stack_file=Path("aws/Pulumi.sec-dev.yaml"),
            graph_health_command_retry_seconds=42,
            graph_health_ingest_retry_seconds=17,
        )

        command = run_aws_deploy_verifications._graph_health_command(args)

        self.assertEqual(command[command.index("--graph-command-retry-seconds") + 1], "42")
        self.assertEqual(command[command.index("--ingest-health-retry-seconds") + 1], "17")

    def test_fresh_graph_health_cache_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            cache = Path(temp_dir) / "graph.tsv"
            checked_at = datetime.now(UTC) - timedelta(minutes=5)
            cache.write_text(
                "checked_at\tstack\tnodes\trelations\tintegrity_passed\tintegrity_failed\tgraph_relations\tcurrent_ingest_runtimes\tdeclared_runtimes\tmissing_ingest_runtimes\tcounts_task\tintegrity_task\tpaths_task\tingest_runs_task\n"
                f"{checked_at.isoformat()}\tgo-prod\t10\t20\t3\t0\tbelongs_to,represents\t4\t4\t\ttask\ttask\ttask\ttask\n",
                encoding="utf-8",
            )

            fresh, reason = run_aws_deploy_verifications._fresh_graph_health_cache(cache, "go-prod", 3600)

        self.assertTrue(fresh, reason)

    def test_stale_graph_health_cache_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            cache = Path(temp_dir) / "graph.tsv"
            checked_at = datetime.now(UTC) - timedelta(hours=2)
            cache.write_text(
                "checked_at\tstack\tnodes\trelations\tintegrity_passed\tintegrity_failed\tgraph_relations\tcurrent_ingest_runtimes\tdeclared_runtimes\tmissing_ingest_runtimes\tcounts_task\tintegrity_task\tpaths_task\tingest_runs_task\n"
                f"{checked_at.isoformat()}\tgo-prod\t10\t20\t3\t0\tbelongs_to,represents\t4\t4\t\ttask\ttask\ttask\ttask\n",
                encoding="utf-8",
            )

            fresh, reason = run_aws_deploy_verifications._fresh_graph_health_cache(cache, "go-prod", 3600)

        self.assertFalse(fresh)
        self.assertIn("exceeds", reason)

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

    def test_graph_command_missing_log_stream_degrades_when_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "outputs.txt"
            diagnostics = (
                "ERROR: aws logs get-log-events --log-group-name /ecs/cerebro-go-production "
                "--log-stream-name ecs/cerebro/task --limit 10000 --start-from-head --region us-east-1 --output json "
                "failed with exit code 254: aws: [ERROR]: An error occurred (ResourceNotFoundException) "
                "when calling the GetLogEvents operation: The specified log stream does not exist."
            )
            with patch(
                "scripts.run_aws_deploy_verifications._stream_graph_health",
                return_value=run_aws_deploy_verifications.GraphHealthResult(23, diagnostics),
            ):
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
                outputs = output_path.read_text(encoding="utf-8")

        self.assertEqual(status, 0)
        self.assertIn("graph_health_degraded=true", outputs)
        self.assertIn("graph_health_degradation_category=graph_command_no_logs", outputs)

    def test_missing_ingest_run_history_degrades_when_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "outputs.txt"
            diagnostics = "ERROR: missing graph ingest run history for 2 declared runtime(s): runtime-a, runtime-b"
            with patch(
                "scripts.run_aws_deploy_verifications._stream_graph_health",
                return_value=run_aws_deploy_verifications.GraphHealthResult(23, diagnostics),
            ):
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
                outputs = output_path.read_text(encoding="utf-8")

        self.assertEqual(status, 0)
        self.assertIn("graph_health_degraded=true", outputs)
        self.assertIn("graph_health_degradation_category=missing_ingest_run_history", outputs)

    def test_resource_initialization_secret_failure_uses_specific_category(self) -> None:
        diagnostics = (
            "stoppedReason=ResourceInitializationError: unable to pull secrets or registry auth: "
            "execution resource retrieval failed: unable to retrieve secret from asm: "
            "ResourceNotFoundException: Secrets Manager can't find the specified secret. "
            "GetLogEvents operation: The specified log stream does not exist."
        )

        category = run_aws_deploy_verifications._graph_health_degradation_category(1, diagnostics)

        self.assertEqual(category, "ecs_secret_initialization_failed")

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

    def test_graph_integrity_failure_repairs_then_reruns_health(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            results = iter(
                [
                    run_aws_deploy_verifications.GraphHealthResult(
                        23,
                        "ERROR: graph integrity failed 1 checks: open_findings_missing_primary_has_finding_edge=1",
                    ),
                    run_aws_deploy_verifications.GraphHealthResult(0, ""),
                ]
            )
            with (
                patch("scripts.run_aws_deploy_verifications._stream_graph_health", side_effect=lambda *_args: next(results)) as stream,
                patch(
                    "scripts.run_aws_deploy_verifications.subprocess.run",
                    return_value=subprocess.CompletedProcess(["repair"], 0),
                ) as run,
            ):
                status = run_aws_deploy_verifications.main(
                    [
                        "--stack-file",
                        "aws/Pulumi.sec-dev.yaml",
                        "--graph-health",
                        "--graph-health-output",
                        str(Path(temp_dir) / "graph.tsv"),
                        "--allow-graph-health-degradation",
                        "--graph-health-heal",
                    ]
                )

        self.assertEqual(status, 0)
        self.assertEqual(stream.call_count, 2)
        command = run.call_args.args[0]
        self.assertIn("scripts/verify_graph_health_ecs.py", command)
        self.assertIn("--graph-command", command)
        self.assertIn("repair-open-finding-primary-links", command)
        self.assertIn("apply=true", command)

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

    def test_graph_failure_heals_runtime_ids_in_parallel(self) -> None:
        args = argparse.Namespace(
            stack_file=Path("aws/Pulumi.go-prod.yaml"),
            graph_health_heal_concurrency=2,
        )
        diagnostics = (
            "ERROR: latest graph ingest run failed for 2 runtime(s): "
            "runtime-a:graph-ingest:runtime-a:20260601T000000Z:status=failed, "
            "runtime-b:graph-ingest:runtime-b:20260601T000000Z:status=failed"
        )
        with (
            patch("scripts.run_aws_deploy_verifications._source_id_for_runtime", return_value="aws"),
            patch(
                "scripts.run_aws_deploy_verifications.subprocess.run",
                return_value=subprocess.CompletedProcess(["heal"], 0),
            ) as run,
        ):
            healed = run_aws_deploy_verifications._attempt_graph_health_heal(args, diagnostics)

        self.assertTrue(healed)
        self.assertEqual(run.call_count, 2)

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
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
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
        self.assertIn("::warning::Graph health verification degraded after deployment", stdout.getvalue())
        create_issue.assert_called_once_with("go-prod", 23, "stale_ingest_run", "graph-health-go-prod")

    def test_graph_degradation_updates_existing_followup_issue(self) -> None:
        requests = []

        def fake_urlopen(request, timeout: int):  # noqa: ANN001
            requests.append(request)
            if request.get_method() == "GET":
                return FakeHTTPResponse(
                    [
                        {
                            "number": 956,
                            "title": "Graph health degraded for go-prod",
                            "html_url": "https://github.com/WriterInternal/cerebro/issues/956",
                        }
                    ]
                )
            return FakeHTTPResponse({"html_url": "https://github.com/WriterInternal/cerebro/issues/956#issuecomment-1"})

        with (
            patch.dict(
                os.environ,
                {
                    "GITHUB_TOKEN": "token",
                    "GITHUB_REPOSITORY": "WriterInternal/cerebro",
                    "GITHUB_RUN_ID": "27053505182",
                },
            ),
            patch("scripts.run_aws_deploy_verifications.urllib.request.urlopen", side_effect=fake_urlopen),
        ):
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                run_aws_deploy_verifications._create_graph_health_issue(
                    "go-prod",
                    1,
                    "ecs_secret_initialization_failed",
                    "graph-health-go-prod",
                )

        self.assertEqual(len(requests), 2)
        self.assertIn("/issues/956/comments", requests[1].full_url)
        payload = json.loads(requests[1].data.decode("utf-8"))
        self.assertIn("ecs_secret_initialization_failed", payload["body"])

    def test_passing_graph_health_closes_existing_degraded_issue(self) -> None:
        requests = []

        def fake_urlopen(request, timeout: int):  # noqa: ANN001
            requests.append(request)
            if request.get_method() == "GET":
                if "page=1" in request.full_url:
                    return FakeHTTPResponse(
                        [
                            {
                                "number": 956,
                                "title": "Graph health degraded for go-prod",
                                "html_url": "https://github.com/WriterInternal/cerebro/issues/956",
                            }
                        ]
                    )
                return FakeHTTPResponse([])
            return FakeHTTPResponse({"html_url": "https://github.com/WriterInternal/cerebro/issues/956#issuecomment-2"})

        with tempfile.TemporaryDirectory() as temp_dir:
            with (
                patch.dict(
                    os.environ,
                    {
                        "GITHUB_TOKEN": "token",
                        "GITHUB_REPOSITORY": "WriterInternal/cerebro",
                        "GITHUB_RUN_ID": "27284692112",
                    },
                ),
                patch("scripts.run_aws_deploy_verifications._stream_graph_health", return_value=run_aws_deploy_verifications.GraphHealthResult(0, "")),
                patch("scripts.run_aws_deploy_verifications.urllib.request.urlopen", side_effect=fake_urlopen),
            ):
                status = run_aws_deploy_verifications.main(
                    [
                        "--stack-file",
                        "aws/Pulumi.go-prod.yaml",
                        "--graph-health",
                        "--graph-health-output",
                        str(Path(temp_dir) / "graph.tsv"),
                        "--graph-health-issue",
                        "--graph-health-artifact-name",
                        "graph-health-go-prod",
                    ]
                )

        self.assertEqual(status, 0)
        methods = [request.get_method() for request in requests]
        self.assertIn("POST", methods)
        self.assertIn("PATCH", methods)
        patch_payload = json.loads(next(request.data.decode("utf-8") for request in requests if request.get_method() == "PATCH"))
        self.assertEqual(patch_payload["state"], "closed")

    def test_healed_graph_health_closes_existing_issue(self) -> None:
        requests = []
        results = iter(
            [
                run_aws_deploy_verifications.GraphHealthResult(
                    23,
                    "ERROR: latest graph ingest run failed for 1 runtime(s): writer-runtime:graph-ingest:writer-runtime:20260601T000000Z:status=failed",
                ),
                run_aws_deploy_verifications.GraphHealthResult(0, ""),
            ]
        )

        def fake_urlopen(request, timeout: int):  # noqa: ANN001
            requests.append(request)
            if request.get_method() == "GET":
                return FakeHTTPResponse(
                    [
                        {
                            "number": 956,
                            "title": "Graph health degraded for go-prod",
                            "html_url": "https://github.com/WriterInternal/cerebro/issues/956",
                        }
                    ]
                )
            return FakeHTTPResponse({"html_url": "https://github.com/WriterInternal/cerebro/issues/956#issuecomment-3"})

        with tempfile.TemporaryDirectory() as temp_dir:
            with (
                patch.dict(
                    os.environ,
                    {
                        "GITHUB_TOKEN": "token",
                        "GITHUB_REPOSITORY": "WriterInternal/cerebro",
                        "GITHUB_RUN_ID": "27284692112",
                    },
                ),
                patch("scripts.run_aws_deploy_verifications._stream_graph_health", side_effect=lambda *_args: next(results)),
                patch("scripts.run_aws_deploy_verifications._attempt_graph_health_heal", return_value=True),
                patch("scripts.run_aws_deploy_verifications.urllib.request.urlopen", side_effect=fake_urlopen),
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
                        "--graph-health-issue",
                    ]
                )

        self.assertEqual(status, 0)
        self.assertTrue(any(request.get_method() == "PATCH" for request in requests))

    def test_recovered_issue_close_is_noop_without_github_env(self) -> None:
        stderr = io.StringIO()
        with patch.dict(os.environ, {}, clear=True), contextlib.redirect_stderr(stderr):
            run_aws_deploy_verifications._close_recovered_graph_health_issues("go-prod", "graph-health-go-prod")

        self.assertIn("cannot close recovered graph-health issue", stderr.getvalue())

    def test_graph_health_runtime_ids_parse_ingest_summaries(self) -> None:
        diagnostics = (
            "latest graph ingest run failed for 1 runtime(s): "
            "writer-vulnview-asset:graph-ingest:writer-vulnview-asset:20260601T172200Z:status=failed"
        )

        self.assertEqual(run_aws_deploy_verifications._graph_health_runtime_ids(diagnostics), ["writer-vulnview-asset"])


if __name__ == "__main__":
    unittest.main()
