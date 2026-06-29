#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
import json
import os
from pathlib import Path
import re
import sys
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen

import yaml

try:
    from aws.source_rollouts import apply_source_runtime_rollouts
except ModuleNotFoundError:  # pragma: no cover - used when executed as scripts/source_runtime_coverage_report.py
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from aws.source_rollouts import apply_source_runtime_rollouts

LIVE_RUNTIME_LIMIT = 500


@dataclass(frozen=True)
class CoverageFinding:
    severity: str
    runtime_id: str
    check: str
    message: str


@dataclass(frozen=True)
class CoverageRow:
    stack: str
    runtime_id: str
    source_id: str
    family: str
    tenant_id: str
    schedule_name: str
    schedule_expression: str
    schedule_cadence_seconds: int | None
    stale_after_seconds: int | None
    task_count: int | None
    backfill: bool
    remove_after: str
    live_present: bool | None
    live_status: str
    last_activity_at: str
    age_hours: float | None


@dataclass(frozen=True)
class CoverageReport:
    generated_at: str
    stack: str
    declared_runtime_count: int
    scheduled_runtime_count: int
    schedule_count: int
    live_runtime_count: int | None
    healthy_runtime_count: int | None
    stale_runtime_count: int
    backfill_schedule_count: int
    expired_backfill_count: int
    sources: dict[str, int]
    findings: list[CoverageFinding]
    rows: list[CoverageRow]


def _stack_name(path: Path) -> str:
    name = path.name
    if name.startswith("Pulumi.") and name.endswith(".yaml"):
        return name.removeprefix("Pulumi.").removesuffix(".yaml")
    return path.stem


def _load_stack_config(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle) or {}
    config = loaded.get("config") or {}
    if not isinstance(config, dict):
        raise ValueError(f"{path} must contain a top-level config mapping")
    config = {
        key.removeprefix("cerebro:"): value
        for key, value in config.items()
        if isinstance(key, str) and key.startswith("cerebro:")
    }
    return apply_source_runtime_rollouts(config)


def _stack_domain(path: Path) -> str:
    config = _load_stack_config(path)
    return str(config.get("domain") or "").strip()


def _is_elb_hostname(hostname: str) -> bool:
    normalized = hostname.rstrip(".").lower()
    return normalized.endswith(".elb.amazonaws.com")


def _normalize_api_url(api_url: str, stack_file: Path) -> str:
    domain = _stack_domain(stack_file)
    if not api_url:
        return f"https://{domain}" if domain else ""
    parsed = urlsplit(api_url)
    if not parsed.scheme:
        parsed = urlsplit(f"//{api_url}")
    if domain and parsed.hostname and _is_elb_hostname(parsed.hostname):
        return urlunsplit(("https", domain, "", "", ""))
    return api_url


def _runtime_field(runtime: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = runtime.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def _runtime_id_from_command(command: Any) -> str:
    if not isinstance(command, list):
        return ""
    for arg in command:
        text = str(arg).strip()
        if text.startswith("runtime_id="):
            return text.split("=", 1)[1].strip()
    return ""


def _family(runtime: dict[str, Any]) -> str:
    config = runtime.get("config") or {}
    if not isinstance(config, dict):
        return ""
    return str(config.get("family") or "").strip()


def _schedule_map(schedules: list[Any]) -> dict[str, list[dict[str, Any]]]:
    mapped: dict[str, list[dict[str, Any]]] = {}
    for schedule in schedules:
        if not isinstance(schedule, dict):
            continue
        runtime_id = _runtime_id_from_command(schedule.get("command"))
        if runtime_id:
            mapped.setdefault(runtime_id, []).append(schedule)
    return mapped


def _schedule_cadence_seconds(expression: Any) -> int | None:
    text = str(expression or "").strip().lower()
    match = re.fullmatch(r"rate\(\s*(\d+)\s+([a-z]+)\s*\)", text)
    if not match:
        return None
    amount = int(match.group(1))
    unit = match.group(2)
    if amount <= 0:
        return None
    if unit in {"minute", "minutes"}:
        return amount * 60
    if unit in {"hour", "hours"}:
        return amount * 3600
    if unit in {"day", "days"}:
        return amount * 86400
    return None


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _last_activity(runtime: dict[str, Any]) -> datetime | None:
    for key in ("last_synced_at", "lastSyncedAt", "last_sync_at", "lastSyncAt", "updated_at", "updatedAt", "last_run_at", "lastRunAt"):
        parsed = _parse_time(runtime.get(key))
        if parsed is not None:
            return parsed
    return None


def _load_actual(path: Path | None, api_url: str, api_key: str, tenant_id: str, timeout: int) -> list[dict[str, Any]] | None:
    if path is None and not api_url:
        return None
    if path is not None:
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    else:
        query = urlencode({"tenant_id": tenant_id, "limit": LIVE_RUNTIME_LIMIT})
        request = Request(f"{api_url.rstrip('/')}/source-runtimes?{query}", headers={"Accept": "application/json"})
        if api_key:
            request.add_header("Authorization", f"Bearer {api_key}")
        try:
            with urlopen(request, timeout=timeout) as response:
                payload = json.load(response)
        except HTTPError as err:
            body = err.read().decode("utf-8", errors="replace").strip()
            detail = f": {body[:500]}" if body else ""
            raise RuntimeError(f"source runtime API returned HTTP {err.code}{detail}") from err
        except URLError as err:
            raise RuntimeError(f"source runtime API request failed: {err.reason}") from err
    runtimes = payload.get("runtimes") if isinstance(payload, dict) else payload
    if not isinstance(runtimes, list):
        raise ValueError("actual runtime payload must be a list or an object with runtimes")
    return [runtime for runtime in runtimes if isinstance(runtime, dict)]


def build_report(
    stack_file: Path,
    *,
    actual: list[dict[str, Any]] | None = None,
    max_age_hours: int = 0,
    now: datetime | None = None,
) -> CoverageReport:
    now = (now or datetime.now(UTC)).astimezone(UTC)
    stack = _stack_name(stack_file)
    config = _load_stack_config(stack_file)
    runtimes = config.get("sourceRuntimes") or []
    schedules = config.get("orchestratorSchedules") or []
    if not isinstance(runtimes, list):
        raise ValueError(f"{stack_file} cerebro:sourceRuntimes must be a list")
    if not isinstance(schedules, list):
        raise ValueError(f"{stack_file} cerebro:orchestratorSchedules must be a list")

    declared: dict[str, dict[str, Any]] = {}
    findings: list[CoverageFinding] = []
    for runtime in runtimes:
        if not isinstance(runtime, dict):
            continue
        runtime_id = _runtime_field(runtime, "id")
        if not runtime_id:
            findings.append(CoverageFinding("error", "", "runtime_id", "declared runtime is missing id"))
            continue
        if runtime_id in declared:
            findings.append(CoverageFinding("error", runtime_id, "runtime_id", "runtime id is declared more than once"))
        declared[runtime_id] = runtime

    external_runtimes = config.get("externalSourceRuntimes") or []
    if not isinstance(external_runtimes, list):
        raise ValueError(f"{stack_file} cerebro:externalSourceRuntimes must be a list")
    external_declared: dict[str, dict[str, Any]] = {}
    for runtime in external_runtimes:
        if not isinstance(runtime, dict):
            continue
        runtime_id = _runtime_field(runtime, "id")
        if not runtime_id:
            findings.append(CoverageFinding("error", "", "external_runtime_id", "external runtime is missing id"))
            continue
        if runtime_id in declared:
            findings.append(CoverageFinding("error", runtime_id, "external_runtime_id", "external runtime is also declared as orchestrated"))
            continue
        if runtime_id in external_declared:
            findings.append(CoverageFinding("error", runtime_id, "external_runtime_id", "external runtime id is declared more than once"))
        external_declared[runtime_id] = runtime

    schedules_by_runtime = _schedule_map(schedules)
    actual_by_id: dict[str, dict[str, Any]] | None = None
    if actual is not None:
        actual_by_id = {_runtime_field(runtime, "id", "runtime_id"): runtime for runtime in actual if _runtime_field(runtime, "id", "runtime_id")}

    rows: list[CoverageRow] = []
    sources: dict[str, int] = {}
    stale_runtime_count = 0
    expired_backfill_count = 0
    scheduled_runtime_ids = set(schedules_by_runtime)

    for runtime_id, runtime in sorted(declared.items()):
        source_id = _runtime_field(runtime, "sourceId", "source_id")
        tenant_id = _runtime_field(runtime, "tenantId", "tenant_id")
        family = _family(runtime)
        sources[source_id or "unknown"] = sources.get(source_id or "unknown", 0) + 1

        runtime_schedules = schedules_by_runtime.get(runtime_id, [])
        if not runtime_schedules:
            findings.append(CoverageFinding("error", runtime_id, "schedule", "declared runtime has no orchestrator schedule"))
            runtime_schedules = [{}]
        elif len(runtime_schedules) > 1:
            findings.append(CoverageFinding("error", runtime_id, "schedule", "runtime has multiple orchestrator schedules"))

        live = actual_by_id.get(runtime_id) if actual_by_id is not None else None
        live_present = None if actual_by_id is None else live is not None
        live_status = ""
        last_activity_at = ""
        age_hours: float | None = None
        if actual_by_id is not None and live is None:
            findings.append(CoverageFinding("error", runtime_id, "live", "declared runtime is missing from the live API"))
        if live is not None:
            live_status = _runtime_field(live, "status", "state")
            last_activity = _last_activity(live)
            if last_activity is not None:
                last_activity_at = last_activity.isoformat().replace("+00:00", "Z")
                age_hours = max(0.0, (now - last_activity).total_seconds() / 3600)

        for schedule in runtime_schedules[:1]:
            schedule_expression = str(schedule.get("scheduleExpression") or "").strip() if schedule else ""
            cadence_seconds = _schedule_cadence_seconds(schedule_expression)
            stale_after_seconds = max_age_hours * 3600 if max_age_hours > 0 else cadence_seconds * 2 if cadence_seconds else None
            if live is not None and age_hours is not None and stale_after_seconds is not None:
                age_seconds = age_hours * 3600
                if age_seconds > stale_after_seconds:
                    stale_runtime_count += 1
                    findings.append(
                        CoverageFinding(
                            "warning",
                            runtime_id,
                            "freshness",
                            f"last activity is older than stale_after_seconds={stale_after_seconds}",
                        )
                    )
            remove_after = str(schedule.get("removeAfter") or "").strip() if schedule else ""
            remove_after_time = _parse_time(remove_after)
            backfill = bool(remove_after) or "backfill" in runtime_id.lower() or "backfill" in str(schedule.get("name", "")).lower()
            if remove_after_time is not None and remove_after_time < now:
                expired_backfill_count += 1
                findings.append(CoverageFinding("warning", runtime_id, "backfill", f"backfill schedule removeAfter {remove_after} has passed"))
            rows.append(
                CoverageRow(
                    stack=stack,
                    runtime_id=runtime_id,
                    source_id=source_id,
                    family=family,
                    tenant_id=tenant_id,
                    schedule_name=str(schedule.get("name") or "").strip() if schedule else "",
                    schedule_expression=schedule_expression,
                    schedule_cadence_seconds=cadence_seconds,
                    stale_after_seconds=stale_after_seconds,
                    task_count=_int_or_none(schedule.get("taskCount")) if schedule else None,
                    backfill=backfill,
                    remove_after=remove_after,
                    live_present=live_present,
                    live_status=live_status,
                    last_activity_at=last_activity_at,
                    age_hours=round(age_hours, 2) if age_hours is not None else None,
                )
            )

    for runtime_id, runtime in sorted(external_declared.items()):
        source_id = _runtime_field(runtime, "sourceId", "source_id")
        tenant_id = _runtime_field(runtime, "tenantId", "tenant_id")
        family = _family(runtime)
        sources[source_id or "unknown"] = sources.get(source_id or "unknown", 0) + 1

        live = actual_by_id.get(runtime_id) if actual_by_id is not None else None
        live_present = None if actual_by_id is None else live is not None
        live_status = ""
        last_activity_at = ""
        age_hours: float | None = None
        if actual_by_id is not None and live is None:
            findings.append(CoverageFinding("error", runtime_id, "live", "external runtime is missing from the live API"))
        if live is not None:
            live_status = _runtime_field(live, "status", "state")
            last_activity = _last_activity(live)
            if last_activity is not None:
                last_activity_at = last_activity.isoformat().replace("+00:00", "Z")
                age_hours = max(0.0, (now - last_activity).total_seconds() / 3600)
        rows.append(
            CoverageRow(
                stack=stack,
                runtime_id=runtime_id,
                source_id=source_id,
                family=family,
                tenant_id=tenant_id,
                schedule_name="external",
                schedule_expression="",
                schedule_cadence_seconds=None,
                stale_after_seconds=None,
                task_count=None,
                backfill=False,
                remove_after="",
                live_present=live_present,
                live_status=live_status,
                last_activity_at=last_activity_at,
                age_hours=round(age_hours, 2) if age_hours is not None else None,
            )
        )

    for runtime_id in sorted(scheduled_runtime_ids - set(declared)):
        findings.append(CoverageFinding("warning", runtime_id, "schedule", "orchestrator schedule targets an undeclared runtime"))

    if actual_by_id is not None:
        expected_runtime_ids = set(declared) | set(external_declared)
        for runtime_id in sorted(set(actual_by_id) - expected_runtime_ids):
            findings.append(CoverageFinding("warning", runtime_id, "live", "live runtime is not declared in stack config"))

    healthy_runtime_count = None
    if actual_by_id is not None:
        healthy_runtime_count = sum(
            1
            for row in rows
            if row.live_present
            and (
                row.age_hours is None
                or row.stale_after_seconds is None
                or row.age_hours * 3600 <= row.stale_after_seconds
            )
        )

    return CoverageReport(
        generated_at=now.isoformat().replace("+00:00", "Z"),
        stack=stack,
        declared_runtime_count=len(declared) + len(external_declared),
        scheduled_runtime_count=len(set(declared) & scheduled_runtime_ids),
        schedule_count=len([schedule for schedule in schedules if isinstance(schedule, dict)]),
        live_runtime_count=len(actual_by_id) if actual_by_id is not None else None,
        healthy_runtime_count=healthy_runtime_count,
        stale_runtime_count=stale_runtime_count,
        backfill_schedule_count=sum(1 for row in rows if row.backfill),
        expired_backfill_count=expired_backfill_count,
        sources=dict(sorted(sources.items())),
        findings=findings,
        rows=rows,
    )


def _int_or_none(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _markdown_escape(value: Any) -> str:
    return str(value if value is not None else "").replace("|", "\\|")


def format_markdown(report: CoverageReport) -> str:
    error_count = sum(1 for finding in report.findings if finding.severity == "error")
    warning_count = sum(1 for finding in report.findings if finding.severity == "warning")
    status = "failed" if error_count else "warning" if warning_count else "passed"
    live = "not loaded" if report.live_runtime_count is None else str(report.live_runtime_count)
    healthy = "not loaded" if report.healthy_runtime_count is None else str(report.healthy_runtime_count)
    lines = [
        f"## Source Runtime Coverage: `{report.stack}`",
        "",
        f"Status: **{status}**",
        f"Generated: `{report.generated_at}`",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| Declared runtimes | `{report.declared_runtime_count}` |",
        f"| Scheduled runtimes | `{report.scheduled_runtime_count}` |",
        f"| Schedules | `{report.schedule_count}` |",
        f"| Live runtimes | `{live}` |",
        f"| Healthy live runtimes | `{healthy}` |",
        f"| Stale live runtimes | `{report.stale_runtime_count}` |",
        f"| Backfill schedules | `{report.backfill_schedule_count}` |",
        f"| Expired backfills | `{report.expired_backfill_count}` |",
        f"| Errors | `{error_count}` |",
        f"| Warnings | `{warning_count}` |",
        "",
        "### Source families",
        "",
        "| Source | Runtimes |",
        "| --- | ---: |",
    ]
    for source, count in report.sources.items():
        lines.append(f"| `{_markdown_escape(source)}` | `{count}` |")
    lines.extend(["", "### Findings", ""])
    if report.findings:
        lines.extend(["| Severity | Runtime | Check | Message |", "| --- | --- | --- | --- |"])
        for finding in report.findings:
            lines.append(
                f"| `{_markdown_escape(finding.severity)}` | `{_markdown_escape(finding.runtime_id)}` | "
                f"`{_markdown_escape(finding.check)}` | {_markdown_escape(finding.message)} |"
            )
    else:
        lines.append("No source runtime coverage gaps detected.")
    lines.extend(["", "### Runtime coverage", ""])
    lines.extend([
        "| Runtime | Source | Family | Schedule | SLA | Backfill | Live | Last activity |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ])
    for row in report.rows:
        live = "unknown" if row.live_present is None else "yes" if row.live_present else "missing"
        schedule = row.schedule_name or "missing"
        sla = "unknown" if row.stale_after_seconds is None else f"{row.stale_after_seconds}s"
        last_activity = row.last_activity_at or "unknown"
        if row.age_hours is not None:
            last_activity = f"{last_activity} ({row.age_hours:.2f}h)"
        lines.append(
            f"| `{_markdown_escape(row.runtime_id)}` | `{_markdown_escape(row.source_id)}` | `{_markdown_escape(row.family)}` | "
            f"`{_markdown_escape(schedule)}` | `{sla}` | `{str(row.backfill).lower()}` | `{live}` | `{_markdown_escape(last_activity)}` |"
        )
    lines.append("")
    return "\n".join(lines)


def format_json(report: CoverageReport) -> str:
    return json.dumps(asdict(report), indent=2, sort_keys=True)


def format_tsv(report: CoverageReport) -> str:
    fieldnames = list(CoverageRow.__dataclass_fields__)
    from io import StringIO

    buffer = StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames, delimiter="\t", lineterminator="\n")
    writer.writeheader()
    for row in report.rows:
        writer.writerow(asdict(row))
    return buffer.getvalue()


def _write(path: Path | None, content: str) -> None:
    if path is None:
        return
    path.write_text(content, encoding="utf-8")


def _write_github_summary(content: str) -> None:
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    with open(summary_path, "a", encoding="utf-8") as handle:
        handle.write(content)


def _exit_code(report: CoverageReport, fail_on: str) -> int:
    if fail_on == "never":
        return 0
    severities = {finding.severity for finding in report.findings}
    if "error" in severities:
        return 1
    if fail_on == "warning" and "warning" in severities:
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Report source runtime coverage across stack config, schedules, and live runtime state.")
    parser.add_argument("--stack-file", type=Path, required=True)
    parser.add_argument("--actual-json", type=Path)
    parser.add_argument("--api-url", default=os.environ.get("CEREBRO_API_URL", ""))
    parser.add_argument("--api-key", default=os.environ.get("CEREBRO_API_KEY", ""))
    parser.add_argument("--tenant-id", default="writer")
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument("--max-age-hours", type=int, default=0)
    parser.add_argument("--format", choices=("markdown", "json", "tsv"), default="markdown")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--json-output", type=Path)
    parser.add_argument("--github-summary", action="store_true")
    parser.add_argument("--fail-on", choices=("error", "warning", "never"), default="error")
    args = parser.parse_args(argv)

    api_url = _normalize_api_url(args.api_url, args.stack_file) if args.api_url or args.actual_json is not None else ""
    actual = _load_actual(args.actual_json, api_url, args.api_key, args.tenant_id, args.timeout)
    report = build_report(args.stack_file, actual=actual, max_age_hours=args.max_age_hours)
    rendered = {
        "markdown": format_markdown,
        "json": format_json,
        "tsv": format_tsv,
    }[args.format](report)
    if args.output is None:
        print(rendered)
    else:
        _write(args.output, rendered)
    if args.json_output is not None:
        _write(args.json_output, format_json(report))
    if args.github_summary:
        _write_github_summary(format_markdown(report))
    return _exit_code(report, args.fail_on)


if __name__ == "__main__":
    raise SystemExit(main())
