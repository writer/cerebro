#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen

import yaml

try:
    from aws.source_rollouts import apply_source_runtime_rollouts
except ModuleNotFoundError:  # pragma: no cover - used when executed as scripts/check_source_runtime_drift.py
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from aws.source_rollouts import apply_source_runtime_rollouts


ALLOWED_UNDECLARED_SOURCE_RUNTIMES = {
    "sec-dev": {"trusted-endpoint"},
}


@dataclass(frozen=True)
class Drift:
    severity: str
    runtime_id: str
    message: str


def _load_stack_runtimes(path: Path) -> dict[str, dict[str, Any]]:
    config = _load_stack_config(path)
    runtimes = config.get("cerebro:sourceRuntimes") or []
    if not isinstance(runtimes, list):
        raise ValueError(f"{path} cerebro:sourceRuntimes must be a list")
    external_runtimes = config.get("cerebro:externalSourceRuntimes") or []
    if not isinstance(external_runtimes, list):
        raise ValueError(f"{path} cerebro:externalSourceRuntimes must be a list")
    result: dict[str, dict[str, Any]] = {}
    for runtime in [*runtimes, *external_runtimes]:
        if not isinstance(runtime, dict):
            continue
        runtime_id = str(runtime.get("id", "")).strip()
        if runtime_id:
            result[runtime_id] = runtime
    return result


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
    stripped = {
        key.removeprefix("cerebro:"): value
        for key, value in config.items()
        if isinstance(key, str) and key.startswith("cerebro:")
    }
    expanded = apply_source_runtime_rollouts(stripped)
    return {f"cerebro:{key}": value for key, value in expanded.items()}


def _stack_domain(path: Path) -> str:
    return str(_load_stack_config(path).get("cerebro:domain") or "").strip()


def _is_elb_hostname(hostname: str) -> bool:
    normalized = hostname.rstrip(".").lower()
    return normalized.endswith(".elb.amazonaws.com")


def _normalize_api_url(api_url: str, stack_file: Path) -> str:
    domain = _stack_domain(stack_file)
    if not domain:
        return api_url
    if not api_url:
        return f"https://{domain}"

    parsed = urlsplit(api_url)
    if not parsed.scheme:
        parsed = urlsplit(f"//{api_url}")
    if parsed.hostname and _is_elb_hostname(parsed.hostname):
        return urlunsplit(("https", domain, "", "", ""))
    return api_url


def _load_actual(path: Path | None, api_url: str, api_key: str, tenant_id: str, timeout: int) -> list[dict[str, Any]]:
    if path is not None:
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    else:
        query = urlencode({"tenant_id": tenant_id, "limit": 500})
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


def _runtime_field(runtime: dict[str, Any], snake: str, camel: str = "") -> str:
    value = runtime.get(snake)
    if value is None and camel:
        value = runtime.get(camel)
    return str(value or "").strip()


def _normalize_config(config: Any) -> dict[str, str]:
    if not isinstance(config, dict):
        return {}
    return {str(key): str(value) for key, value in config.items() if not str(value).startswith("env:")}


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
    return parsed


def _last_activity(runtime: dict[str, Any]) -> datetime | None:
    for key in ("last_synced_at", "lastSyncedAt", "last_sync_at", "lastSyncAt", "updated_at", "updatedAt", "last_run_at", "lastRunAt"):
        parsed = _parse_time(runtime.get(key))
        if parsed is not None:
            return parsed
    return None


def find_drift(
    expected: dict[str, dict[str, Any]],
    actual: list[dict[str, Any]],
    max_age_hours: int = 0,
    allowed_unexpected: set[str] | None = None,
) -> list[Drift]:
    drift: list[Drift] = []
    actual_by_id = {_runtime_field(runtime, "id"): runtime for runtime in actual if _runtime_field(runtime, "id")}
    allowed_unexpected = allowed_unexpected or set()

    for runtime_id, expected_runtime in expected.items():
        actual_runtime = actual_by_id.get(runtime_id)
        if actual_runtime is None:
            drift.append(Drift("error", runtime_id, "expected runtime is missing from the live API"))
            continue

        expected_source = str(expected_runtime.get("sourceId", "")).strip()
        actual_source = _runtime_field(actual_runtime, "source_id", "sourceId")
        if expected_source and actual_source and expected_source != actual_source:
            drift.append(Drift("error", runtime_id, f"source_id drift: expected {expected_source}, got {actual_source}"))

        expected_tenant = str(expected_runtime.get("tenantId", "")).strip()
        actual_tenant = _runtime_field(actual_runtime, "tenant_id", "tenantId")
        if expected_tenant and actual_tenant and expected_tenant != actual_tenant:
            drift.append(Drift("error", runtime_id, f"tenant_id drift: expected {expected_tenant}, got {actual_tenant}"))

        expected_config = _normalize_config(expected_runtime.get("config"))
        actual_config = _normalize_config(actual_runtime.get("config"))
        for key, expected_value in expected_config.items():
            actual_value = actual_config.get(key)
            if actual_value is not None and actual_value != expected_value:
                drift.append(Drift("error", runtime_id, f"config.{key} drift: expected {expected_value}, got {actual_value}"))

        if max_age_hours > 0:
            last_activity = _last_activity(actual_runtime)
            if last_activity is not None and last_activity < datetime.now(UTC) - timedelta(hours=max_age_hours):
                drift.append(Drift("warning", runtime_id, f"last activity is older than {max_age_hours} hours"))

    unexpected = sorted(set(actual_by_id) - set(expected) - allowed_unexpected)
    for runtime_id in unexpected:
        drift.append(Drift("warning", runtime_id, "live runtime is not declared in stack config"))

    return drift


def _markdown_escape(value: str) -> str:
    return value.replace("|", "\\|")


def _summary_markdown(stack: str, expected_count: int, actual_count: int, drift: list[Drift]) -> str:
    error_count = sum(1 for finding in drift if finding.severity == "error")
    warning_count = sum(1 for finding in drift if finding.severity == "warning")
    status = "failed" if error_count else "passed"
    lines = [
        f"## Source Runtime Drift: `{stack}`",
        "",
        f"Status: **{status}**",
        f"Declared runtimes: `{expected_count}`",
        f"Live runtimes: `{actual_count}`",
        f"Errors: `{error_count}`",
        f"Warnings: `{warning_count}`",
        "",
    ]
    if drift:
        lines.extend(
            [
                "| Severity | Runtime | Finding |",
                "| --- | --- | --- |",
            ]
        )
        for finding in drift:
            lines.append(
                f"| `{_markdown_escape(finding.severity)}` | `{_markdown_escape(finding.runtime_id)}` | {_markdown_escape(finding.message)} |"
            )
    else:
        lines.append("Live source runtimes match the stack declaration.")
    lines.append("")
    return "\n".join(lines)


def _write_github_summary(stack: str, expected_count: int, actual_count: int, drift: list[Drift]) -> None:
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    with open(summary_path, "a", encoding="utf-8") as handle:
        handle.write(_summary_markdown(stack, expected_count, actual_count, drift))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare declared source runtimes with the live Cerebro API.")
    parser.add_argument("--stack-file", type=Path, required=True)
    parser.add_argument("--actual-json", type=Path)
    parser.add_argument("--api-url", default=os.environ.get("CEREBRO_API_URL", ""))
    parser.add_argument("--api-key", default=os.environ.get("CEREBRO_API_KEY", ""))
    parser.add_argument("--tenant-id", default="writer")
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument("--max-age-hours", type=int, default=0)
    args = parser.parse_args(argv)

    api_url = _normalize_api_url(args.api_url, args.stack_file)
    if args.actual_json is None and not api_url:
        raise SystemExit("CEREBRO_API_URL, stack domain, or --actual-json is required")

    expected = _load_stack_runtimes(args.stack_file)
    actual = _load_actual(args.actual_json, api_url, args.api_key, args.tenant_id, args.timeout)
    stack = _stack_name(args.stack_file)
    drift = find_drift(expected, actual, args.max_age_hours, ALLOWED_UNDECLARED_SOURCE_RUNTIMES.get(stack, set()))
    _write_github_summary(stack, len(expected), len(actual), drift)

    for finding in drift:
        print(f"{finding.severity.upper()}: {finding.runtime_id}: {finding.message}")

    return 1 if any(finding.severity == "error" for finding in drift) else 0


if __name__ == "__main__":
    sys.exit(main())
