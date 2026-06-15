#!/usr/bin/env python3
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
from dataclasses import dataclass
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import time
from typing import TextIO
import urllib.error
import urllib.parse
import urllib.request

import yaml

try:
    from aws.source_rollouts import apply_source_runtime_rollouts
except ModuleNotFoundError:  # pragma: no cover - used when executed as scripts/run_aws_deploy_verifications.py
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from aws.source_rollouts import apply_source_runtime_rollouts


@dataclass(frozen=True)
class GraphHealthResult:
    status: int
    diagnostics: str = ""


DEFAULT_GRAPH_HEALTH_COMMAND_RETRY_SECONDS = 300
DEFAULT_GRAPH_HEALTH_INGEST_RETRY_SECONDS = 0
DEFAULT_GRAPH_HEALTH_CACHE_MAX_AGE_SECONDS = 3600


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


def _non_negative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return parsed


def _source_ids(args: argparse.Namespace) -> list[str]:
    raw_source_ids = getattr(args, "source_ids", None)
    if raw_source_ids:
        return list(raw_source_ids)
    raw_source_id = getattr(args, "source_id", None)
    return [raw_source_id or "cosmo"]


def _source_runtime_command(args: argparse.Namespace, source_id: str | None = None) -> list[str]:
    source_id = source_id or _source_ids(args)[0]
    command = [
        sys.executable,
        "scripts/verify_source_runtime_ecs.py",
        "--stack-file",
        str(args.stack_file),
        "--source-id",
        source_id,
        "--stop-timeout-seconds",
        "600",
        "--failed-run-retry-seconds",
        "0",
        "--run-attempt-timeout-seconds",
        "300",
        "--max-age-minutes",
        "60",
        "--wait-timeout-seconds",
        "300",
        "--poll-seconds",
        "5",
        "--target-concurrency",
        str(args.source_target_concurrency),
    ]
    if args.source_runtime_dry_run:
        command.append("--dry-run")
    else:
        command.extend(
            [
                "--run",
                "--run-page-limit",
                "1",
                "--run-graph-page-limit",
                "1",
                "--run-event-limit",
                "10",
                "--succeed-after-graph-ingest",
                "--allow-lease-contention-skip",
            ]
        )
    if args.source_runtime_observability_targets:
        command.append("--observability-targets")
    if args.source_runtime_allow_missing_targets:
        command.append("--allow-missing-targets")
    for runtime_id in args.runtime_id:
        command.extend(["--runtime-id", runtime_id])
    for family in args.family:
        command.extend(["--family", family])
    if args.stop_running_source_before_run:
        command.append("--stop-running-before-run")
    return command


def _graph_health_command(args: argparse.Namespace) -> list[str]:
    command = [
        sys.executable,
        "scripts/verify_graph_health_ecs.py",
        "--stack-file",
        str(args.stack_file),
        "--wait-timeout-seconds",
        "3600",
        "--graph-command-retry-seconds",
        str(args.graph_health_command_retry_seconds),
        "--ingest-health-retry-seconds",
        str(args.graph_health_ingest_retry_seconds),
        "--poll-seconds",
        "5",
        "--allow-transient-source-failures",
        "--require-bundled-health",
    ]
    return command


def _start_process(command: list[str]) -> subprocess.Popen[str]:
    print(f"Running: {' '.join(command)}", file=sys.stderr, flush=True)
    return subprocess.Popen(command, text=True)


def _stream_graph_health(command: list[str], output_path: Path) -> GraphHealthResult:
    print(f"Running: {' '.join(command)}", file=sys.stderr, flush=True)
    with output_path.open("w", encoding="utf-8") as output:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        assert process.stdout is not None
        assert process.stderr is not None
        stderr_lines: list[str] = []

        def stream_stdout() -> None:
            for line in process.stdout:
                output.write(line)
                output.flush()
                print(line, end="", flush=True)

        def stream_stderr() -> None:
            for line in process.stderr:
                stderr_lines.append(line)
                print(line, end="", file=sys.stderr, flush=True)

        stdout_thread = threading.Thread(target=stream_stdout, daemon=True)
        stderr_thread = threading.Thread(target=stream_stderr, daemon=True)
        stdout_thread.start()
        stderr_thread.start()
        status = process.wait()
        stdout_thread.join()
        stderr_thread.join()
        return GraphHealthResult(status=status, diagnostics="".join(stderr_lines))


def _parse_graph_health_checked_at(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _positive_field(row: dict[str, str], key: str) -> bool:
    try:
        return int(row.get(key, "") or "0") > 0
    except ValueError:
        return False


def _fresh_graph_health_cache(
    cache_path: Path,
    stack: str,
    max_age_seconds: int,
    *,
    now: datetime | None = None,
) -> tuple[bool, str]:
    if max_age_seconds <= 0:
        return False, "cache disabled"
    if not cache_path.exists():
        return False, "cache missing"
    rows: list[dict[str, str]]
    with cache_path.open("r", encoding="utf-8") as handle:
        rows = [row for row in csv.DictReader(handle, delimiter="\t") if row]
    if not rows:
        return False, "cache is empty"
    row = rows[-1]
    if row.get("stack") != stack:
        return False, f"cache stack mismatch: {row.get('stack')}"
    try:
        checked_at = _parse_graph_health_checked_at(row.get("checked_at", ""))
    except ValueError:
        return False, "cache checked_at is invalid"
    now = (now or datetime.now(UTC)).astimezone(UTC)
    age_seconds = (now - checked_at).total_seconds()
    if age_seconds < 0 or age_seconds > max_age_seconds:
        return False, f"cache age {age_seconds:.0f}s exceeds {max_age_seconds}s"
    if not _positive_field(row, "nodes") or not _positive_field(row, "relations"):
        return False, "cache has non-positive graph size"
    if str(row.get("integrity_failed") or "") != "0":
        return False, "cache has failed integrity checks"
    if str(row.get("missing_ingest_runtimes") or "").strip():
        return False, "cache has missing ingest runtimes"
    if not str(row.get("graph_relations") or "").strip():
        return False, "cache has no graph relations"
    return True, f"cache is fresh ({age_seconds:.0f}s old)"


def _maybe_use_graph_health_cache(args: argparse.Namespace, stack: str) -> GraphHealthResult | None:
    if not args.allow_graph_health_cache or args.graph_health_cache_path is None:
        return None
    fresh, reason = _fresh_graph_health_cache(
        args.graph_health_cache_path,
        stack,
        args.graph_health_cache_max_age_seconds,
    )
    if not fresh:
        print(f"Graph health cache miss for {stack}: {reason}", file=sys.stderr, flush=True)
        return None
    print(f"Using recent graph health cache for {stack}: {reason}", file=sys.stderr, flush=True)
    if args.graph_health_cache_path.resolve() != args.graph_health_output.resolve():
        args.graph_health_output.write_text(args.graph_health_cache_path.read_text(encoding="utf-8"), encoding="utf-8")
    return GraphHealthResult(status=0, diagnostics="")


def _finish_source_process(process: subprocess.Popen[str], grace_seconds: float | None) -> int:
    if grace_seconds is None:
        return process.wait()
    try:
        return process.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        print(
            f"Source runtime verification did not finish within {grace_seconds}s after graph health; marking it degraded.",
            file=sys.stderr,
            flush=True,
        )
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        return 124


def _finish_source_processes(processes: list[subprocess.Popen[str]], grace_seconds: int | None) -> int:
    if len(processes) == 1:
        return _finish_source_process(processes[0], grace_seconds)
    status = 0
    deadline = time.monotonic() + grace_seconds if grace_seconds is not None else None
    for process in processes:
        process_grace = None if deadline is None else max(0, deadline - time.monotonic())
        process_status = _finish_source_process(process, process_grace)
        if process_status != 0 and status == 0:
            status = process_status
    return status


def _report_source_degradation(stack: str, summary: TextIO | None = None) -> None:
    print(
        "::warning::Source runtime verification failed after deployment; rollout will continue and graph-health verification remains separately reported."
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
            "Source runtime verification failed after deployment. This is reported as degraded source-provider health instead of blocking the service rollout.\n"
        )


def _summary_path(summary: TextIO | None = None) -> Path | None:
    if summary is not None:
        return Path(summary.name)
    raw_summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    return Path(raw_summary_path) if raw_summary_path else None


def _report_graph_health_degradation(stack: str, status: int, category: str, summary: TextIO | None = None) -> None:
    print(
        f"::warning::Graph health verification degraded after deployment ({category}, exit code {status}); rollout will continue and graph-health artifacts remain available for follow-up."
    )
    summary_path = _summary_path(summary)
    if summary_path is None:
        return
    with summary_path.open("a", encoding="utf-8") as handle:
        handle.write(f"### Graph health verification degraded ({stack})\n\n")
        handle.write(
            f"Graph health verification failed after deployment with exit code `{status}` and category `{category}`. This is reported as degraded graph health instead of blocking the service rollout; inspect the uploaded graph-health artifact for details.\n"
        )


def _graph_health_status(result: int | GraphHealthResult) -> int:
    if isinstance(result, GraphHealthResult):
        return result.status
    return int(result)


def _graph_health_diagnostics(result: int | GraphHealthResult) -> str:
    if isinstance(result, GraphHealthResult):
        return result.diagnostics
    return ""


def _graph_health_degradation_category(status: int, diagnostics: str) -> str | None:
    if status == 0:
        return None
    text = diagnostics.lower()
    blocking_tokens = (
        "graph integrity",
        "graph relation counts missing",
        "graph paths missing",
        "missing required relation",
        "graph node count must be positive",
        "graph relation count must be positive",
    )
    if any(token in text for token in blocking_tokens):
        return None
    if "resourceinitializationerror" in text and (
        "unable to retrieve secret" in text
        or "unable to pull secrets" in text
        or "secrets manager can't find the specified secret" in text
    ):
        return "ecs_secret_initialization_failed"
    if "resourceinitializationerror" in text:
        return "ecs_task_initialization_failed"
    categories = (
        ("latest graph ingest run is stale-running", "stale_ingest_run"),
        ("latest graph ingest run failed", "stale_or_transient_ingest_run"),
        ("missing graph ingest run history", "missing_ingest_run_history"),
        ("latest graph ingest projected no graph records", "zero_projection_ingest_run"),
        ("did not emit valid json", "graph_command_no_json"),
        ("getlogevents operation: the specified log stream does not exist", "graph_command_no_logs"),
        ("graph health command exited with", "graph_command_failed"),
        ("context deadline exceeded", "graph_command_timeout"),
    )
    for token, category in categories:
        if token in text:
            return category
    return None


def _graph_health_runtime_ids(diagnostics: str) -> list[str]:
    runtime_ids = {
        match.group(1)
        for match in re.finditer(r"([A-Za-z0-9_.-]+):graph-ingest:\1(?::|$)", diagnostics)
    }
    return sorted(runtime_ids)


def _graph_health_needs_primary_link_repair(diagnostics: str) -> bool:
    return "open_findings_missing_primary_has_finding_edge" in diagnostics


def _source_id_for_runtime(stack_file: Path, runtime_id: str) -> str:
    with stack_file.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle) or {}
    raw_config = loaded.get("config") or {}
    config = apply_source_runtime_rollouts({
        key.removeprefix("cerebro:"): value
        for key, value in raw_config.items()
        if isinstance(key, str) and key.startswith("cerebro:")
    })
    runtimes = config.get("sourceRuntimes") or []
    if not isinstance(runtimes, list):
        return ""
    for runtime in runtimes:
        if not isinstance(runtime, dict) or str(runtime.get("id") or "").strip() != runtime_id:
            continue
        return str(runtime.get("sourceId") or runtime.get("source_id") or "").strip()
    return ""


def _graph_health_heal_command(args: argparse.Namespace, runtime_id: str, source_id: str) -> list[str]:
    return [
        sys.executable,
        "scripts/verify_source_runtime_ecs.py",
        "--stack-file",
        str(args.stack_file),
        "--source-id",
        source_id,
        "--runtime-id",
        runtime_id,
        "--run",
        "--run-page-limit",
        "1",
        "--run-graph-page-limit",
        "1",
        "--run-event-limit",
        "10",
        "--succeed-after-graph-ingest",
        "--allow-lease-contention-skip",
        "--failed-run-retry-seconds",
        "0",
        "--run-attempt-timeout-seconds",
        "300",
        "--max-age-minutes",
        "60",
        "--wait-timeout-seconds",
        "300",
        "--poll-seconds",
        "5",
    ]


def _graph_health_primary_link_repair_command(args: argparse.Namespace) -> list[str]:
    return [
        sys.executable,
        "scripts/verify_graph_health_ecs.py",
        "--stack-file",
        str(args.stack_file),
        "--wait-timeout-seconds",
        "900",
        "--poll-seconds",
        "5",
        "--graph-command-retry-seconds",
        "0",
        "--credential-safe-timeout-seconds",
        "900",
        "--graph-command",
        "graph",
        "repair-open-finding-primary-links",
        "apply=true",
        "limit=25",
    ]


def _attempt_graph_health_heal(args: argparse.Namespace, diagnostics: str) -> bool:
    runtime_ids = _graph_health_runtime_ids(diagnostics)
    healed_any = False
    if _graph_health_needs_primary_link_repair(diagnostics):
        command = _graph_health_primary_link_repair_command(args)
        print(f"Running graph-health primary-link repair command: {' '.join(command)}", file=sys.stderr, flush=True)
        completed = subprocess.run(command, text=True)
        if completed.returncode != 0:
            print(f"WARNING: graph-health primary-link repair command failed with exit code {completed.returncode}", file=sys.stderr)
        else:
            healed_any = True

    def heal_runtime(runtime_id: str) -> bool:
        source_id = _source_id_for_runtime(args.stack_file, runtime_id)
        if not source_id:
            print(f"WARNING: cannot heal graph health for {runtime_id}: source runtime is not declared", file=sys.stderr)
            return False
        command = _graph_health_heal_command(args, runtime_id, source_id)
        print(f"Running graph-health heal command: {' '.join(command)}", file=sys.stderr, flush=True)
        completed = subprocess.run(command, text=True)
        if completed.returncode != 0:
            print(f"WARNING: graph-health heal command failed for {runtime_id} with exit code {completed.returncode}", file=sys.stderr)
            return False
        return True

    with ThreadPoolExecutor(max_workers=min(args.graph_health_heal_concurrency, max(1, len(runtime_ids)))) as executor:
        futures = {executor.submit(heal_runtime, runtime_id): runtime_id for runtime_id in runtime_ids}
        for future in as_completed(futures):
            if future.result():
                healed_any = True
    return healed_any


def _write_github_output(path: Path | None, **values: str) -> None:
    output_path = path or (Path(os.environ["GITHUB_OUTPUT"]) if os.environ.get("GITHUB_OUTPUT") else None)
    if output_path is None:
        return
    with output_path.open("a", encoding="utf-8") as handle:
        for key, value in values.items():
            handle.write(f"{key}={value}\n")


def _github_api_json(repository: str, token: str, path: str, *, method: str = "GET", payload: dict | None = None) -> object:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repository}{path}",
        data=data,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        method=method,
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.loads(response.read().decode("utf-8"))


def _find_open_graph_health_issues(repository: str, token: str, title: str) -> list[dict]:
    matches: list[dict] = []
    for page in range(1, 6):
        query = urllib.parse.urlencode({"state": "open", "per_page": "100", "page": str(page)})
        issues = _github_api_json(repository, token, f"/issues?{query}")
        if not isinstance(issues, list):
            return matches
        for issue in issues:
            if not isinstance(issue, dict) or issue.get("pull_request"):
                continue
            if issue.get("title") == title:
                matches.append(issue)
        if len(issues) < 100:
            break
    return matches


def _find_open_graph_health_issue(repository: str, token: str, title: str) -> dict | None:
    matches = _find_open_graph_health_issues(repository, token, title)
    return matches[0] if matches else None


def _graph_health_missing_runtime_ids(diagnostics: str) -> list[str]:
    runtime_ids: list[str] = []
    for match in re.finditer(
        r"missing graph ingest run history for \d+ declared runtime\(s\): (.*?)(?:; latest graph ingest run failed|$)",
        diagnostics,
        flags=re.IGNORECASE | re.DOTALL,
    ):
        runtime_ids.extend(value.strip() for value in re.split(r"[\s,]+", match.group(1)) if value.strip())
    return sorted(set(runtime_ids))


def _graph_health_failed_runtime_ids(diagnostics: str) -> list[str]:
    runtime_ids = {
        match.group(1)
        for match in re.finditer(r"([A-Za-z0-9_.-]+):graph-ingest:\1(?::|$)", diagnostics)
    }
    return sorted(runtime_ids)


def _graph_health_issue_diagnostic_summary(diagnostics: str) -> list[str]:
    lines: list[str] = []
    missing = _graph_health_missing_runtime_ids(diagnostics)
    failed = _graph_health_failed_runtime_ids(diagnostics)
    if missing:
        sample = ", ".join(missing[:25])
        suffix = f" (showing 25 of {len(missing)})" if len(missing) > 25 else ""
        lines.extend(["", "### Missing ingest history", "", f"{sample}{suffix}"])
    if failed:
        lines.extend(["", "### Failed ingest runtimes", "", ", ".join(failed)])
    detail = diagnostics.strip()
    if detail:
        detail = detail[-2500:]
        lines.extend(["", "### Diagnostic tail", "", "```text", detail, "```"])
    return lines


def _graph_health_issue_body(
    stack: str,
    status: int,
    category: str,
    artifact_name: str,
    run_url: str,
    *,
    degraded: bool,
    diagnostics: str = "",
) -> str:
    outcome = "degraded" if degraded else "blocked deployment"
    lines = [
        f"Graph health verification {outcome} after an infrastructure deployment for `{stack}`.",
        "",
        f"- Category: `{category}`",
        f"- Exit code: `{status}`",
        f"- Workflow run: {run_url}",
        f"- Artifact: `{artifact_name}`",
        "",
        "Please inspect the graph-health artifact and follow up on the degraded runtime or graph command.",
    ]
    lines.extend(_graph_health_issue_diagnostic_summary(diagnostics))
    return "\n".join(lines)


def _create_graph_health_issue(
    stack: str,
    status: int,
    category: str,
    artifact_name: str,
    *,
    degraded: bool = True,
    diagnostics: str = "",
) -> None:
    token = os.environ.get("GITHUB_TOKEN")
    repository = os.environ.get("GITHUB_REPOSITORY")
    run_id = os.environ.get("GITHUB_RUN_ID")
    if not token or not repository or not run_id:
        print("WARNING: cannot create graph-health issue without GITHUB_TOKEN, GITHUB_REPOSITORY, and GITHUB_RUN_ID", file=sys.stderr)
        return
    run_url = f"https://github.com/{repository}/actions/runs/{run_id}"
    outcome = "degraded" if degraded else "blocked deployment"
    title = f"Graph health {outcome} for {stack}"
    body = _graph_health_issue_body(stack, status, category, artifact_name, run_url, degraded=degraded, diagnostics=diagnostics)
    try:
        existing_issues = _find_open_graph_health_issues(repository, token, title)
        if existing_issues:
            existing = existing_issues[0]
            issue_number = existing.get("number")
            if issue_number:
                updated = _github_api_json(
                    repository,
                    token,
                    f"/issues/{issue_number}/comments",
                    method="POST",
                    payload={"body": body},
                )
                if isinstance(updated, dict):
                    print(f"::notice::Updated existing graph-health follow-up issue: {updated.get('html_url')}")
                    for duplicate in existing_issues[1:]:
                        duplicate_number = duplicate.get("number")
                        if isinstance(duplicate_number, int):
                            _close_graph_health_issue(
                                repository,
                                token,
                                duplicate_number,
                                f"Closing duplicate graph-health issue; continuing follow-up in #{issue_number}.",
                                notice="Closed duplicate graph-health issue",
                            )
                    return
        created = _github_api_json(repository, token, "/issues", method="POST", payload={"title": title, "body": body})
    except urllib.error.URLError as exc:
        print(f"WARNING: failed to create graph-health issue: {exc}", file=sys.stderr)
        return
    print(f"::notice::Created graph-health follow-up issue: {created.get('html_url')}")


def _close_graph_health_issue(repository: str, token: str, issue_number: int, body: str, *, notice: str = "Closed recovered graph-health issue") -> None:
    updated = _github_api_json(
        repository,
        token,
        f"/issues/{issue_number}/comments",
        method="POST",
        payload={"body": body},
    )
    _github_api_json(repository, token, f"/issues/{issue_number}", method="PATCH", payload={"state": "closed"})
    if isinstance(updated, dict):
        print(f"::notice::{notice}: {updated.get('html_url')}")


def _close_recovered_graph_health_issues(stack: str, artifact_name: str) -> None:
    token = os.environ.get("GITHUB_TOKEN")
    repository = os.environ.get("GITHUB_REPOSITORY")
    run_id = os.environ.get("GITHUB_RUN_ID")
    if not token or not repository or not run_id:
        print("WARNING: cannot close recovered graph-health issue without GITHUB_TOKEN, GITHUB_REPOSITORY, and GITHUB_RUN_ID", file=sys.stderr)
        return
    run_url = f"https://github.com/{repository}/actions/runs/{run_id}"
    body = "\n".join(
        [
            f"Graph health recovered for `{stack}`.",
            "",
            f"- Workflow run: {run_url}",
            f"- Artifact: `{artifact_name}`",
            "",
            "Closing because the latest graph-health verification passed.",
        ]
    )
    try:
        for title in (f"Graph health degraded for {stack}", f"Graph health blocked deployment for {stack}"):
            for existing in _find_open_graph_health_issues(repository, token, title):
                issue_number = existing.get("number")
                if isinstance(issue_number, int):
                    _close_graph_health_issue(repository, token, issue_number, body)
    except urllib.error.URLError as exc:
        print(f"WARNING: failed to close recovered graph-health issue: {exc}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run AWS deployment verifications, overlapping non-blocking source checks with graph health.")
    parser.add_argument("--stack-file", type=Path, required=True)
    parser.add_argument("--source-runtime-verify", action="store_true")
    parser.add_argument(
        "--source-id",
        action="append",
        dest="source_ids",
        help="Source ID to verify when --source-runtime-verify runs. Repeat to verify multiple sources.",
    )
    parser.add_argument("--runtime-id", action="append", default=[], help="Restrict --source-runtime-verify to a declared runtime ID.")
    parser.add_argument("--family", action="append", default=[], help="Restrict --source-runtime-verify to a runtime config family.")
    parser.add_argument("--source-runtime-dry-run", action="store_true", help="Run source runtime verification in read-only dry-run/readiness mode.")
    parser.add_argument("--source-runtime-observability-targets", action="store_true", help="Select enabled sourceRuntimeObservability entries.")
    parser.add_argument("--source-runtime-allow-missing-targets", action="store_true", help="Allow not-yet-deployed EventBridge targets during source runtime readiness checks.")
    parser.add_argument("--graph-health", action="store_true")
    parser.add_argument("--graph-health-output", type=Path, default=Path("graph-health.tsv"))
    parser.add_argument(
        "--allow-graph-health-degradation",
        action="store_true",
        help="Report graph health failures as degraded post-deploy health instead of failing the rollout job.",
    )
    parser.add_argument("--graph-health-heal", action="store_true", help="Try to re-run failed source runtimes before degrading graph health.")
    parser.add_argument("--graph-health-heal-concurrency", type=_positive_int, default=4)
    parser.add_argument("--graph-health-issue", action="store_true", help="Create a GitHub issue when graph health is degraded.")
    parser.add_argument("--graph-health-artifact-name", default="graph-health", help="Artifact name to include in graph-health follow-up issues.")
    parser.add_argument("--allow-graph-health-cache", action="store_true", help="Reuse a recent passing graph-health TSV for deploy gating when available.")
    parser.add_argument("--graph-health-cache-path", type=Path, help="Path to a restored graph-health TSV cache.")
    parser.add_argument(
        "--graph-health-cache-max-age-seconds",
        type=_non_negative_int,
        default=DEFAULT_GRAPH_HEALTH_CACHE_MAX_AGE_SECONDS,
    )
    parser.add_argument(
        "--graph-health-command-retry-seconds",
        type=_non_negative_int,
        default=DEFAULT_GRAPH_HEALTH_COMMAND_RETRY_SECONDS,
        help="Retry transient graph command launch/output failures for this many seconds during deploy health checks.",
    )
    parser.add_argument(
        "--graph-health-ingest-retry-seconds",
        type=_non_negative_int,
        default=DEFAULT_GRAPH_HEALTH_INGEST_RETRY_SECONDS,
        help="Retry failed/stale graph ingest health for this many seconds before using the degradation/heal path.",
    )
    parser.add_argument("--github-output", type=Path, help="GitHub Actions output file for deployment health outputs.")
    parser.add_argument("--source-target-concurrency", type=_positive_int, default=4)
    parser.add_argument(
        "--source-runtime-grace-seconds",
        type=_non_negative_int,
        default=10,
        help="After graph health completes, wait this long for non-blocking source verification before degrading it.",
    )
    parser.add_argument("--stop-running-source-before-run", action="store_true")
    args = parser.parse_args(argv)

    source_processes: list[subprocess.Popen[str]] = []
    source_status = 0
    graph_result: int | GraphHealthResult = 0
    stack = _stack_name(args.stack_file)
    try:
        if args.source_runtime_verify:
            source_processes = [_start_process(_source_runtime_command(args, source_id)) for source_id in _source_ids(args)]
        if args.graph_health:
            graph_result = _maybe_use_graph_health_cache(args, stack) or _stream_graph_health(_graph_health_command(args), args.graph_health_output)
    finally:
        if source_processes:
            grace_seconds = args.source_runtime_grace_seconds if args.graph_health else None
            source_status = _finish_source_processes(source_processes, grace_seconds)

    if source_status != 0:
        _report_source_degradation(stack)
    graph_status = _graph_health_status(graph_result)
    graph_diagnostics = _graph_health_diagnostics(graph_result)
    if graph_status != 0:
        if args.graph_health_heal and _attempt_graph_health_heal(args, graph_diagnostics):
            graph_result = _stream_graph_health(_graph_health_command(args), args.graph_health_output)
            graph_status = _graph_health_status(graph_result)
            graph_diagnostics = _graph_health_diagnostics(graph_result)
        category = _graph_health_degradation_category(graph_status, graph_diagnostics)
        if graph_status == 0:
            _write_github_output(args.github_output, graph_health_degraded="false", graph_health_degradation_category="")
            if args.graph_health and args.graph_health_issue:
                _close_recovered_graph_health_issues(stack, args.graph_health_artifact_name)
            return 0
        if args.allow_graph_health_degradation and category:
            _write_github_output(args.github_output, graph_health_degraded="true", graph_health_degradation_category=category)
            _report_graph_health_degradation(stack, graph_status, category)
            if args.graph_health_issue:
                _create_graph_health_issue(stack, graph_status, category, args.graph_health_artifact_name, diagnostics=graph_diagnostics)
            return 0
        _write_github_output(args.github_output, graph_health_degraded="false", graph_health_degradation_category="", graph_health_blocked="true")
        if args.graph_health_issue:
            _create_graph_health_issue(
                stack,
                graph_status,
                category or "blocking_graph_health_failure",
                args.graph_health_artifact_name,
                degraded=False,
                diagnostics=graph_diagnostics,
            )
        return graph_status
    _write_github_output(args.github_output, graph_health_degraded="false", graph_health_degradation_category="")
    if args.graph_health and args.graph_health_issue:
        _close_recovered_graph_health_issues(stack, args.graph_health_artifact_name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
