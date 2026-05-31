#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys
from typing import TextIO


def _stack_name(path: Path) -> str:
    name = path.name
    if name.startswith("Pulumi.") and name.endswith(".yaml"):
        return name.removeprefix("Pulumi.").removesuffix(".yaml")
    return path.stem


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return parsed


def _source_runtime_command(args: argparse.Namespace) -> list[str]:
    command = [
        sys.executable,
        "scripts/verify_source_runtime_ecs.py",
        "--stack-file",
        str(args.stack_file),
        "--source-id",
        "cosmo",
        "--run",
        "--run-page-limit",
        "1",
        "--run-graph-page-limit",
        "1",
        "--run-event-limit",
        "10",
        "--succeed-after-graph-ingest",
        "--allow-lease-contention-skip",
        "--stop-timeout-seconds",
        "600",
        "--failed-run-retry-seconds",
        "300",
        "--run-attempt-timeout-seconds",
        "900",
        "--max-age-minutes",
        "60",
        "--wait-timeout-seconds",
        "1200",
        "--poll-seconds",
        "5",
        "--target-concurrency",
        str(args.source_target_concurrency),
    ]
    if args.stop_running_source_before_run:
        command.append("--stop-running-before-run")
    return command


def _graph_health_command(args: argparse.Namespace) -> list[str]:
    return [
        sys.executable,
        "scripts/verify_graph_health_ecs.py",
        "--stack-file",
        str(args.stack_file),
        "--wait-timeout-seconds",
        "3600",
        "--graph-command-retry-seconds",
        "1800",
        "--poll-seconds",
        "5",
        "--allow-transient-source-failures",
    ]


def _start_process(command: list[str]) -> subprocess.Popen[str]:
    print(f"Running: {' '.join(command)}", file=sys.stderr, flush=True)
    return subprocess.Popen(command, text=True)


def _stream_graph_health(command: list[str], output_path: Path) -> int:
    print(f"Running: {' '.join(command)}", file=sys.stderr, flush=True)
    with output_path.open("w", encoding="utf-8") as output:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, text=True)
        assert process.stdout is not None
        for line in process.stdout:
            output.write(line)
            output.flush()
            print(line, end="", flush=True)
        return process.wait()


def _report_source_degradation(stack: str, summary: TextIO | None = None) -> None:
    print(
        "::warning::Cosmo source runtime verification failed after deployment; rollout will continue and graph-health integrity checks remain blocking."
    )
    summary_path = Path(summary.name) if summary is not None else None
    if summary_path is None:
        from os import environ

        raw_summary_path = environ.get("GITHUB_STEP_SUMMARY")
        summary_path = Path(raw_summary_path) if raw_summary_path else None
    if summary_path is None:
        return
    with summary_path.open("a", encoding="utf-8") as handle:
        handle.write(f"### Source runtime verification degraded ({stack})\n\n")
        handle.write(
            "Cosmo source runtime verification failed after deployment. This is reported as degraded source-provider health instead of blocking the service rollout.\n"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run AWS deployment verifications, overlapping non-blocking source checks with graph health.")
    parser.add_argument("--stack-file", type=Path, required=True)
    parser.add_argument("--source-runtime-verify", action="store_true")
    parser.add_argument("--graph-health", action="store_true")
    parser.add_argument("--graph-health-output", type=Path, default=Path("graph-health.tsv"))
    parser.add_argument("--source-target-concurrency", type=_positive_int, default=2)
    parser.add_argument("--stop-running-source-before-run", action="store_true")
    args = parser.parse_args(argv)

    source_process: subprocess.Popen[str] | None = None
    source_status = 0
    graph_status = 0
    stack = _stack_name(args.stack_file)
    try:
        if args.source_runtime_verify:
            source_process = _start_process(_source_runtime_command(args))
        if args.graph_health:
            graph_status = _stream_graph_health(_graph_health_command(args), args.graph_health_output)
    finally:
        if source_process is not None:
            source_status = source_process.wait()

    if source_status != 0:
        _report_source_degradation(stack)
    if graph_status != 0:
        return graph_status
    return 0


if __name__ == "__main__":
    sys.exit(main())
