#!/usr/bin/env python3
"""Run a bounded load smoke against a Cerebro HTTP deployment."""

from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import json
import os
import pathlib
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from typing import Sequence


USER_AGENT = "cerebro-load-smoke/0"


@dataclasses.dataclass(frozen=True)
class RequestResult:
    path: str
    status_code: int | None
    latency_ms: float
    response_bytes: int
    error_kind: str


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        summary = execute(args)
        write_outputs(summary, args)
        print(render_console_summary(summary))
        return 0 if summary["healthy"] else 1
    except SmokeUsageError as exc:
        print(f"load_smoke: {exc}", file=sys.stderr)
        return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=first_env("CEREBRO_LOAD_SMOKE_BASE_URL", "CEREBRO_BASE_URL"), help="Cerebro origin, for example https://cerebro.example.com")
    parser.add_argument("--path", action="append", default=[], help="Path to exercise; repeatable. Defaults to /health")
    parser.add_argument("--duration", type=positive_float, default=float(os.environ.get("CEREBRO_LOAD_SMOKE_DURATION", "30")), help="Smoke duration in seconds")
    parser.add_argument("--rps", type=positive_float, default=float(os.environ.get("CEREBRO_LOAD_SMOKE_RPS", "2")), help="Target request rate per second")
    parser.add_argument("--concurrency", type=positive_int, default=int(os.environ.get("CEREBRO_LOAD_SMOKE_CONCURRENCY", "4")), help="Maximum in-flight requests")
    parser.add_argument("--timeout", type=positive_float, default=float(os.environ.get("CEREBRO_LOAD_SMOKE_TIMEOUT", "5")), help="Per-request timeout in seconds")
    parser.add_argument("--success-status-min", type=int, default=200, help="Minimum HTTP status counted as success")
    parser.add_argument("--success-status-max", type=int, default=399, help="Maximum HTTP status counted as success")
    parser.add_argument("--max-p95-ms", type=positive_float, default=float(os.environ.get("CEREBRO_LOAD_SMOKE_MAX_P95_MS", "750")), help="Fail when p95 latency exceeds this value")
    parser.add_argument("--max-error-rate", type=non_negative_float, default=float(os.environ.get("CEREBRO_LOAD_SMOKE_MAX_ERROR_RATE", "0.01")), help="Fail when non-success or transport errors exceed this fraction")
    parser.add_argument("--max-5xx-rate", type=non_negative_float, default=float(os.environ.get("CEREBRO_LOAD_SMOKE_MAX_5XX_RATE", "0")), help="Fail when 5xx responses exceed this fraction")
    parser.add_argument("--min-requests", type=positive_int, default=1, help="Fail when fewer requests completed")
    parser.add_argument("--header", action="append", default=[], help="Extra HTTP header as 'Name: value'; repeatable")
    parser.add_argument("--bearer-token", default=first_env("CEREBRO_LOAD_SMOKE_BEARER_TOKEN", "CEREBRO_MCP_BEARER_TOKEN"), help="Optional bearer/API token; never printed")
    parser.add_argument("--max-read-bytes", type=positive_int, default=65536, help="Maximum response bytes read per request")
    parser.add_argument("--json-out", default=os.environ.get("CEREBRO_LOAD_SMOKE_JSON_OUT", ""), help="Optional JSON summary path")
    parser.add_argument("--markdown-out", default=os.environ.get("CEREBRO_LOAD_SMOKE_MARKDOWN_OUT", ""), help="Optional Markdown summary path")
    return parser


def execute(args: argparse.Namespace) -> dict:
    base_url = normalize_base_url(args.base_url)
    paths = normalize_paths(args.path)
    headers = parse_headers(args.header)
    if args.bearer_token:
        headers["Authorization"] = f"Bearer {args.bearer_token}"

    started_at = time.time()
    results = run_schedule(
        base_url=base_url,
        paths=paths,
        headers=headers,
        duration_seconds=args.duration,
        rps=args.rps,
        concurrency=args.concurrency,
        timeout_seconds=args.timeout,
        max_read_bytes=args.max_read_bytes,
    )
    finished_at = time.time()
    summary = summarize(
        base_url=base_url,
        paths=paths,
        results=results,
        args=args,
        started_at=started_at,
        finished_at=finished_at,
    )
    return summary


def run_schedule(
    *,
    base_url: str,
    paths: list[str],
    headers: dict[str, str],
    duration_seconds: float,
    rps: float,
    concurrency: int,
    timeout_seconds: float,
    max_read_bytes: int,
) -> list[RequestResult]:
    interval = 1.0 / rps
    started = time.monotonic()
    deadline = started + duration_seconds
    next_request_at = started
    request_index = 0
    results: list[RequestResult] = []
    pending: set[concurrent.futures.Future[RequestResult]] = set()

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        while time.monotonic() < deadline:
            now = time.monotonic()
            if now < next_request_at:
                drain_ready(pending, results, timeout=next_request_at - now)
                continue
            if len(pending) >= concurrency:
                drain_ready(pending, results, timeout=0.05)
                continue
            path = paths[request_index % len(paths)]
            pending.add(pool.submit(fetch_once, base_url, path, dict(headers), timeout_seconds, max_read_bytes))
            request_index += 1
            next_request_at += interval

        while pending:
            drain_ready(pending, results, timeout=0.1)
    return results


def drain_ready(pending: set[concurrent.futures.Future[RequestResult]], results: list[RequestResult], *, timeout: float) -> None:
    if not pending:
        if timeout > 0:
            time.sleep(timeout)
        return
    done, still_pending = concurrent.futures.wait(pending, timeout=max(0.0, timeout), return_when=concurrent.futures.FIRST_COMPLETED)
    pending.clear()
    pending.update(still_pending)
    for future in done:
        results.append(future.result())


def fetch_once(base_url: str, path: str, headers: dict[str, str], timeout_seconds: float, max_read_bytes: int) -> RequestResult:
    url = urllib.parse.urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    request_headers = {
        "Accept": "application/json, text/plain, */*",
        "User-Agent": USER_AGENT,
        **headers,
    }
    req = urllib.request.Request(url, headers=request_headers, method="GET")
    started = time.perf_counter()
    status_code: int | None = None
    response_bytes = 0
    error_kind = ""
    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds) as response:
            status_code = response.status
            response_bytes = len(response.read(max_read_bytes))
    except urllib.error.HTTPError as exc:
        status_code = exc.code
        try:
            response_bytes = len(exc.read(max_read_bytes))
        except OSError as read_exc:
            error_kind = read_exc.__class__.__name__
        finally:
            exc.close()
    except TimeoutError:
        error_kind = "timeout"
    except urllib.error.URLError as exc:
        error_kind = classify_url_error(exc)
    except OSError as exc:
        error_kind = exc.__class__.__name__
    latency_ms = (time.perf_counter() - started) * 1000.0
    return RequestResult(path=path, status_code=status_code, latency_ms=latency_ms, response_bytes=response_bytes, error_kind=error_kind)


def summarize(*, base_url: str, paths: list[str], results: list[RequestResult], args: argparse.Namespace, started_at: float, finished_at: float) -> dict:
    total = len(results)
    status_counts: Counter[str] = Counter()
    path_counts: Counter[str] = Counter()
    error_kind_counts: Counter[str] = Counter()
    success_count = 0
    http_5xx_count = 0
    transport_error_count = 0
    latencies = sorted(result.latency_ms for result in results)
    for result in results:
        path_counts[result.path] += 1
        if result.status_code is None:
            status_counts["transport_error"] += 1
            transport_error_count += 1
            error_kind_counts[result.error_kind or "transport_error"] += 1
            continue
        status_counts[str(result.status_code)] += 1
        if 500 <= result.status_code <= 599:
            http_5xx_count += 1
        if args.success_status_min <= result.status_code <= args.success_status_max:
            success_count += 1
    error_count = total - success_count
    failures = evaluate_failures(
        total=total,
        p95_ms=percentile(latencies, 95),
        error_rate=rate(error_count, total),
        http_5xx_rate=rate(http_5xx_count, total),
        args=args,
    )
    return {
        "kind": "cerebro_load_smoke",
        "healthy": not failures,
        "failures": failures,
        "base_url": safe_base_url(base_url),
        "paths": paths,
        "started_at_unix": started_at,
        "finished_at_unix": finished_at,
        "duration_seconds": round(finished_at - started_at, 3),
        "target": {
            "duration_seconds": args.duration,
            "rps": args.rps,
            "concurrency": args.concurrency,
            "timeout_seconds": args.timeout,
            "success_status_min": args.success_status_min,
            "success_status_max": args.success_status_max,
        },
        "thresholds": {
            "min_requests": args.min_requests,
            "max_p95_ms": args.max_p95_ms,
            "max_error_rate": args.max_error_rate,
            "max_5xx_rate": args.max_5xx_rate,
        },
        "request_count": total,
        "success_count": success_count,
        "error_count": error_count,
        "error_rate": rate(error_count, total),
        "http_5xx_count": http_5xx_count,
        "http_5xx_rate": rate(http_5xx_count, total),
        "transport_error_count": transport_error_count,
        "status_counts": dict(sorted(status_counts.items())),
        "path_counts": dict(sorted(path_counts.items())),
        "error_kind_counts": dict(sorted(error_kind_counts.items())),
        "latency_ms": {
            "min": round(latencies[0], 3) if latencies else None,
            "p50": percentile(latencies, 50),
            "p95": percentile(latencies, 95),
            "p99": percentile(latencies, 99),
            "max": round(latencies[-1], 3) if latencies else None,
        },
    }


def evaluate_failures(*, total: int, p95_ms: float | None, error_rate: float, http_5xx_rate: float, args: argparse.Namespace) -> list[str]:
    failures: list[str] = []
    if total < args.min_requests:
        failures.append(f"completed {total} requests, below minimum {args.min_requests}")
    if p95_ms is None:
        failures.append("no latency samples recorded")
    elif p95_ms > args.max_p95_ms:
        failures.append(f"p95 latency {p95_ms:.1f}ms exceeds {args.max_p95_ms:.1f}ms")
    if error_rate > args.max_error_rate:
        failures.append(f"error rate {error_rate:.4f} exceeds {args.max_error_rate:.4f}")
    if http_5xx_rate > args.max_5xx_rate:
        failures.append(f"5xx rate {http_5xx_rate:.4f} exceeds {args.max_5xx_rate:.4f}")
    return failures


def write_outputs(summary: dict, args: argparse.Namespace) -> None:
    if args.json_out:
        write_text(args.json_out, json.dumps(summary, indent=2, sort_keys=True) + "\n")
    if args.markdown_out:
        write_text(args.markdown_out, render_markdown(summary))


def write_text(path: str, body: str) -> None:
    out = pathlib.Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(body, encoding="utf-8")


def render_console_summary(summary: dict) -> str:
    status = "passed" if summary["healthy"] else "failed"
    latency = summary["latency_ms"]
    return (
        f"load_smoke: {status}; "
        f"requests={summary['request_count']} "
        f"error_rate={summary['error_rate']:.4f} "
        f"5xx_rate={summary['http_5xx_rate']:.4f} "
        f"p95_ms={latency['p95']}"
    )


def render_markdown(summary: dict) -> str:
    latency = summary["latency_ms"]
    failures = summary["failures"] or ["none"]
    lines = [
        "# Cerebro Load Smoke",
        "",
        f"- Status: {'passed' if summary['healthy'] else 'failed'}",
        f"- Target: `{summary['base_url']}`",
        f"- Paths: `{', '.join(summary['paths'])}`",
        f"- Requests: {summary['request_count']}",
        f"- Error rate: {summary['error_rate']:.4f}",
        f"- 5xx rate: {summary['http_5xx_rate']:.4f}",
        f"- Latency ms: p50={latency['p50']}, p95={latency['p95']}, p99={latency['p99']}, max={latency['max']}",
        "",
        "## Failures",
        "",
    ]
    lines.extend(f"- {failure}" for failure in failures)
    lines.extend([
        "",
        "## Status Counts",
        "",
    ])
    lines.extend(f"- `{status}`: {count}" for status, count in summary["status_counts"].items())
    lines.append("")
    return "\n".join(lines)


def normalize_base_url(value: str) -> str:
    value = value.strip().rstrip("/")
    if not value:
        raise SmokeUsageError("provide --base-url or CEREBRO_LOAD_SMOKE_BASE_URL")
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise SmokeUsageError(f"invalid base URL {safe_base_url(value)!r}; expected http(s)://host")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise SmokeUsageError("base URL must be an origin without path, query, or fragment")
    return value


def normalize_paths(values: Sequence[str]) -> list[str]:
    paths = [value.strip() for value in values if value.strip()]
    if not paths:
        paths = ["/health"]
    normalized: list[str] = []
    for path in paths:
        parsed = urllib.parse.urlparse(path)
        if parsed.scheme or parsed.netloc:
            raise SmokeUsageError("--path must be a path, not a full URL")
        if not path.startswith("/"):
            path = "/" + path
        normalized.append(path)
    return normalized


def parse_headers(values: Sequence[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for raw in values:
        name, sep, value = raw.partition(":")
        name = name.strip()
        if sep != ":" or not name:
            raise SmokeUsageError(f"invalid header {raw!r}; expected 'Name: value'")
        headers[name] = value.strip()
    return headers


def percentile(sorted_values: list[float], pct: int) -> float | None:
    if not sorted_values:
        return None
    if len(sorted_values) == 1:
        return round(sorted_values[0], 3)
    rank = (pct / 100.0) * (len(sorted_values) - 1)
    lower = int(rank)
    upper = min(lower + 1, len(sorted_values) - 1)
    fraction = rank - lower
    value = sorted_values[lower] + ((sorted_values[upper] - sorted_values[lower]) * fraction)
    return round(value, 3)


def rate(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return numerator / denominator


def classify_url_error(exc: urllib.error.URLError) -> str:
    reason = getattr(exc, "reason", None)
    if isinstance(reason, TimeoutError):
        return "timeout"
    if reason is None:
        return "url_error"
    return reason.__class__.__name__


def safe_base_url(value: str) -> str:
    parsed = urllib.parse.urlparse(value)
    if not parsed.scheme or not parsed.netloc:
        return value.strip()
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))


def first_env(*names: str) -> str:
    for name in names:
        value = os.environ.get(name, "")
        if value:
            return value
    return ""


def positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def non_negative_float(value: str) -> float:
    parsed = float(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be non-negative")
    return parsed


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


class SmokeUsageError(RuntimeError):
    pass


if __name__ == "__main__":
    raise SystemExit(main())
