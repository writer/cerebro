#!/usr/bin/env python3
"""Compare two Cerebro releases through the security operator's core workflow."""

from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import hashlib
import json
import math
import os
import pathlib
import statistics
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Sequence


USER_AGENT = "cerebro-security-operator-benchmark/1"
VOLATILE_FIELDS = {"generated_at", "started_at", "finished_at", "updated_at"}


@dataclasses.dataclass(frozen=True)
class Target:
    name: str
    base_url: str
    headers: dict[str, str]


@dataclasses.dataclass(frozen=True)
class StepResult:
    name: str
    latency_ms: float
    status_code: int | None
    payload: Any
    error: str
    complete: bool


@dataclasses.dataclass(frozen=True)
class JourneyResult:
    target: str
    latency_ms: float
    steps: tuple[StepResult, ...]
    semantic_digest: str

    @property
    def successful(self) -> bool:
        return bool(self.steps) and all(
            step.status_code == 200 and not step.error for step in self.steps
        )

    @property
    def actionable(self) -> bool:
        return self.successful and all(step.complete for step in self.steps)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        scenario = load_scenario(args.scenario)
        headers = parse_headers(args.header)
        if args.bearer_token:
            headers["Authorization"] = f"Bearer {args.bearer_token}"
        targets = (
            Target("baseline", normalize_origin(args.baseline_url), headers),
            Target("candidate", normalize_origin(args.candidate_url), headers),
        )
        receipt = execute(targets, scenario, args)
        write_receipt(receipt, args)
        print(render_console(receipt))
        return 0 if receipt["status"] == "passed" else 1
    except BenchmarkUsageError as exc:
        print(f"security_operator_benchmark: {exc}", file=sys.stderr)
        return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--baseline-url", required=True, help="Origin for the currently trusted release"
    )
    parser.add_argument(
        "--candidate-url", required=True, help="Origin for the release under evaluation"
    )
    parser.add_argument(
        "--scenario", required=True, help="Security journey scenario JSON"
    )
    parser.add_argument(
        "--samples", type=positive_int, default=30, help="Completed journeys per target"
    )
    parser.add_argument(
        "--concurrency",
        type=positive_int,
        default=2,
        help="Concurrent analyst journeys per target",
    )
    parser.add_argument(
        "--timeout",
        type=positive_float,
        default=10.0,
        help="Timeout for each API request",
    )
    parser.add_argument(
        "--warmup",
        type=non_negative_int,
        default=3,
        help="Unmeasured journeys per target",
    )
    parser.add_argument(
        "--max-p95-regression-pct", type=non_negative_float, default=5.0
    )
    parser.add_argument("--min-actionable-rate", type=unit_float, default=1.0)
    parser.add_argument("--min-answer-retention-rate", type=unit_float, default=1.0)
    parser.add_argument("--min-semantic-parity-rate", type=unit_float, default=1.0)
    parser.add_argument(
        "--analyst-journeys-per-day",
        type=positive_int,
        default=50,
        help="Used only to project operator time returned",
    )
    parser.add_argument(
        "--header",
        action="append",
        default=[],
        help="HTTP header as 'Name: value'; repeatable",
    )
    parser.add_argument(
        "--bearer-token",
        default=os.environ.get("CEREBRO_BENCHMARK_BEARER_TOKEN", ""),
        help="Token; never written to receipts",
    )
    parser.add_argument("--json-out", default="tmp/security-operator-benchmark.json")
    parser.add_argument("--markdown-out", default="tmp/security-operator-benchmark.md")
    return parser


def load_scenario(path: str) -> dict[str, Any]:
    try:
        scenario = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BenchmarkUsageError(f"cannot read scenario: {exc}") from exc
    tenant_id = str(scenario.get("tenant_id", "")).strip()
    if not tenant_id:
        raise BenchmarkUsageError("scenario tenant_id is required")
    scenario.setdefault("finding_limit", 25)
    scenario.setdefault("attack_path_limit", 25)
    scenario.setdefault("asset_limit", 25)
    requirements = scenario.setdefault("requirements", {})
    requirements.setdefault("min_open_findings", 1)
    requirements.setdefault("min_attack_paths", 1)
    requirements.setdefault("min_assets", 1)
    requirements.setdefault("require_owned_finding", True)
    requirements.setdefault("require_finding_evidence", True)
    requirements.setdefault("require_finding_risk", True)
    requirements.setdefault("require_path_provenance", True)
    requirements.setdefault("require_asset_actions", True)
    expected = scenario.setdefault("expected", {})
    if not str(expected.get("finding_rule_id", "")).strip():
        raise BenchmarkUsageError("scenario expected.finding_rule_id is required")
    if not str(expected.get("resource_urn", "")).strip():
        raise BenchmarkUsageError("scenario expected.resource_urn is required")
    expected.setdefault("minimum_severity", "HIGH")
    return scenario


def execute(
    targets: tuple[Target, Target], scenario: dict[str, Any], args: argparse.Namespace
) -> dict[str, Any]:
    for _ in range(args.warmup):
        for target in targets:
            run_journey(target, scenario, args.timeout)
    started_at = time.time()
    results = run_paired_targets(
        targets, scenario, args.samples, args.concurrency, args.timeout
    )
    finished_at = time.time()
    baseline = summarize_target(results["baseline"])
    candidate = summarize_target(results["candidate"])
    comparison = compare_targets(
        results["baseline"],
        results["candidate"],
        baseline,
        candidate,
        args.analyst_journeys_per_day,
    )
    failures = evaluate_gates(candidate, comparison, args)
    scenario_digest = digest_json(redact_scenario(scenario))
    return {
        "schema_version": "cerebro.security-operator-benchmark/v1",
        "status": "passed" if not failures else "failed",
        "failures": failures,
        "purpose": "Measure how quickly and reliably an analyst can identify, explain, and route active risk.",
        "scenario_digest": scenario_digest,
        "target_origins": {
            target.name: safe_origin(target.base_url) for target in targets
        },
        "started_at_unix": started_at,
        "finished_at_unix": finished_at,
        "configuration": {
            "samples_per_target": args.samples,
            "concurrency_per_target": args.concurrency,
            "warmup_journeys": args.warmup,
            "timeout_seconds": args.timeout,
            "analyst_journeys_per_day": args.analyst_journeys_per_day,
        },
        "gates": {
            "max_p95_regression_pct": args.max_p95_regression_pct,
            "min_actionable_rate": args.min_actionable_rate,
            "min_answer_retention_rate": args.min_answer_retention_rate,
            "min_semantic_parity_rate": args.min_semantic_parity_rate,
        },
        "baseline": baseline,
        "candidate": candidate,
        "comparison": comparison,
    }


def run_paired_targets(
    targets: tuple[Target, Target],
    scenario: dict[str, Any],
    samples: int,
    concurrency: int,
    timeout: float,
) -> dict[str, list[JourneyResult]]:
    results: dict[str, list[JourneyResult]] = {target.name: [] for target in targets}
    remaining = samples
    round_index = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        while remaining > 0:
            batch_size = min(concurrency, remaining)
            ordered_targets = (
                targets if round_index % 2 == 0 else tuple(reversed(targets))
            )
            for target in ordered_targets:
                futures = [
                    pool.submit(run_journey, target, scenario, timeout)
                    for _ in range(batch_size)
                ]
                results[target.name].extend(future.result() for future in futures)
            remaining -= batch_size
            round_index += 1
    return results


def run_journey(
    target: Target, scenario: dict[str, Any], timeout: float
) -> JourneyResult:
    started = time.perf_counter()
    tenant = urllib.parse.quote(str(scenario["tenant_id"]), safe="")
    steps: list[StepResult] = []
    findings = request_json(
        target,
        "risk_inbox",
        f"/grc/findings?tenant_id={tenant}&status=open&limit={int(scenario['finding_limit'])}",
        timeout,
    )
    steps.append(
        dataclasses.replace(
            findings, complete=finding_answer_complete(findings.payload, scenario)
        )
    )
    paths = request_json(
        target,
        "exposure_to_privilege",
        f"/platform/graph/attack-paths?tenant_id={tenant}&limit={int(scenario['attack_path_limit'])}",
        timeout,
    )
    steps.append(
        dataclasses.replace(
            paths, complete=attack_path_answer_complete(paths.payload, scenario)
        )
    )
    assets = request_json(
        target,
        "affected_assets",
        f"/grc/inventory/assets?tenant_id={tenant}&surface=asset&limit={int(scenario['asset_limit'])}",
        timeout,
    )
    steps.append(
        dataclasses.replace(
            assets, complete=asset_list_complete(assets.payload, scenario)
        )
    )
    urn = str(scenario["expected"]["resource_urn"]).strip()
    if urn:
        detail_path = f"/grc/inventory/assets/detail?tenant_id={tenant}&urn={urllib.parse.quote(urn, safe='')}&limit={int(scenario['asset_limit'])}"
        detail = request_json(target, "investigation_context", detail_path, timeout)
        steps.append(
            dataclasses.replace(
                detail, complete=asset_detail_complete(detail.payload, scenario)
            )
        )
    else:
        steps.append(
            StepResult(
                "investigation_context",
                0.0,
                None,
                None,
                "no asset available for investigation",
                False,
            )
        )
    semantic = semantic_view(steps)
    return JourneyResult(
        target=target.name,
        latency_ms=(time.perf_counter() - started) * 1000.0,
        steps=tuple(steps),
        semantic_digest=digest_json(semantic),
    )


def request_json(target: Target, name: str, path: str, timeout: float) -> StepResult:
    request = urllib.request.Request(
        urllib.parse.urljoin(target.base_url.rstrip("/") + "/", path.lstrip("/")),
        headers={
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
            **target.headers,
        },
        method="GET",
    )
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read(4 << 20))
            return StepResult(
                name, elapsed_ms(started), response.status, payload, "", False
            )
    except urllib.error.HTTPError as exc:
        exc.close()
        return StepResult(
            name, elapsed_ms(started), exc.code, None, f"http_{exc.code}", False
        )
    except (OSError, TimeoutError, json.JSONDecodeError) as exc:
        return StepResult(
            name, elapsed_ms(started), None, None, exc.__class__.__name__, False
        )


def finding_answer_complete(payload: Any, scenario: dict[str, Any]) -> bool:
    findings = list_value(payload, "findings")
    req = scenario["requirements"]
    if len(findings) < int(req["min_open_findings"]):
        return False
    expected = scenario["expected"]
    minimum_severity = severity_rank(str(expected["minimum_severity"]))

    def useful(item: Any) -> bool:
        if (
            not isinstance(item, dict)
            or not item.get("severity")
            or not item.get("resource_urns")
        ):
            return False
        if item.get("rule_id") != expected["finding_rule_id"]:
            return False
        if expected["resource_urn"] not in item.get("resource_urns", []):
            return False
        if severity_rank(str(item.get("severity", ""))) < minimum_severity:
            return False
        if req["require_owned_finding"] and str(
            item.get("owner", "")
        ).strip().lower() in {"", "unassigned"}:
            return False
        if req["require_finding_evidence"] and int(item.get("evidence_count", 0)) < 1:
            return False
        if (
            req["require_finding_risk"]
            and not item.get("risk_reasons")
            and not item.get("risk_score")
        ):
            return False
        return True

    return any(useful(item) for item in findings)


def attack_path_answer_complete(payload: Any, scenario: dict[str, Any]) -> bool:
    paths = list_value(payload, "paths")
    req = scenario["requirements"]
    if len(paths) < int(req["min_attack_paths"]):
        return False
    if not req["require_path_provenance"]:
        return True
    material_edges = (
        "exposure_edge",
        "resource_account_edge",
        "privilege_edge",
        "permission_account_edge",
    )
    expected_urn = scenario["expected"]["resource_urn"]
    return any(
        isinstance(path, dict)
        and isinstance(path.get("exposed_resource"), dict)
        and path["exposed_resource"].get("urn") == expected_urn
        and all(
            isinstance(path.get(edge), dict)
            and (path[edge].get("source_event_id") or path[edge].get("source_id"))
            for edge in material_edges
        )
        for path in paths
    )


def asset_list_complete(payload: Any, scenario: dict[str, Any]) -> bool:
    assets = list_value(payload, "assets")
    return len(assets) >= int(scenario["requirements"]["min_assets"]) and any(
        isinstance(asset, dict)
        and asset.get("urn") == scenario["expected"]["resource_urn"]
        for asset in assets
    )


def asset_detail_complete(payload: Any, scenario: dict[str, Any]) -> bool:
    if not isinstance(payload, dict) or not isinstance(payload.get("asset"), dict):
        return False
    if payload["asset"].get("urn") != scenario["expected"]["resource_urn"]:
        return False
    if not payload.get("findings") or not payload.get("evidence"):
        return False
    if not any(
        isinstance(finding, dict)
        and finding.get("rule_id") == scenario["expected"]["finding_rule_id"]
        for finding in payload["findings"]
    ):
        return False
    if scenario["requirements"]["require_asset_actions"] and not payload.get("actions"):
        return False
    return True


def semantic_view(steps: Sequence[StepResult]) -> dict[str, Any]:
    view: dict[str, Any] = {}
    for step in steps:
        view[step.name] = {
            "status_code": step.status_code,
            "complete": step.complete,
            "payload": strip_volatile(step.payload),
        }
    return view


def strip_volatile(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: strip_volatile(item)
            for key, item in sorted(value.items())
            if key not in VOLATILE_FIELDS and not key.endswith("_at")
        }
    if isinstance(value, list):
        normalized = [strip_volatile(item) for item in value]
        return sorted(
            normalized,
            key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")),
        )
    return value


def summarize_target(results: Sequence[JourneyResult]) -> dict[str, Any]:
    latencies = sorted(result.latency_ms for result in results)
    successful = sum(result.successful for result in results)
    actionable = sum(result.actionable for result in results)
    step_names = sorted({step.name for result in results for step in result.steps})
    complete_answers = sum(step.complete for result in results for step in result.steps)
    question_count = sum(len(result.steps) for result in results)
    return {
        "journeys": len(results),
        "success_rate": rate(successful, len(results)),
        "actionable_answer_rate": rate(actionable, len(results)),
        "question_coverage_rate": rate(complete_answers, question_count),
        "analyst_journey_latency_ms": distribution(latencies),
        "questions": {
            name: {
                "latency_ms": distribution(
                    sorted(
                        step.latency_ms
                        for result in results
                        for step in result.steps
                        if step.name == name
                    )
                ),
                "complete_answer_rate": rate(
                    sum(
                        step.complete
                        for result in results
                        for step in result.steps
                        if step.name == name
                    ),
                    len(results),
                ),
                "error_rate": rate(
                    sum(
                        bool(step.error)
                        for result in results
                        for step in result.steps
                        if step.name == name
                    ),
                    len(results),
                ),
            }
            for name in step_names
        },
    }


def compare_targets(
    baseline_results: Sequence[JourneyResult],
    candidate_results: Sequence[JourneyResult],
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    analyst_journeys_per_day: int,
) -> dict[str, Any]:
    baseline_p95 = baseline["analyst_journey_latency_ms"]["p95"]
    candidate_p95 = candidate["analyst_journey_latency_ms"]["p95"]
    time_saved_ms = baseline_p95 - candidate_p95
    capacity_gain = (
        ((baseline_p95 / candidate_p95) - 1) * 100 if candidate_p95 else math.inf
    )
    paired = min(len(baseline_results), len(candidate_results))
    baseline_complete_answers = 0
    retained_answers = 0
    retained_matching_answers = 0
    for index in range(paired):
        candidate_steps = {step.name: step for step in candidate_results[index].steps}
        for baseline_step in baseline_results[index].steps:
            if not baseline_step.complete:
                continue
            baseline_complete_answers += 1
            candidate_step = candidate_steps.get(baseline_step.name)
            if candidate_step is None or not candidate_step.complete:
                continue
            retained_answers += 1
            if digest_json(strip_volatile(baseline_step.payload)) == digest_json(
                strip_volatile(candidate_step.payload)
            ):
                retained_matching_answers += 1
    latency_comparable = (
        baseline["question_coverage_rate"] == candidate["question_coverage_rate"]
        and baseline["actionable_answer_rate"] == candidate["actionable_answer_rate"]
    )
    question_deltas = {}
    for name in sorted(set(baseline["questions"]) & set(candidate["questions"])):
        question_deltas[name] = (
            percent_delta(
                baseline["questions"][name]["latency_ms"]["p95"],
                candidate["questions"][name]["latency_ms"]["p95"],
            )
            if baseline["questions"][name]["complete_answer_rate"]
            == candidate["questions"][name]["complete_answer_rate"]
            else None
        )
    return {
        "latency_comparable": latency_comparable,
        "p95_analyst_journey_delta_pct": percent_delta(baseline_p95, candidate_p95)
        if latency_comparable
        else None,
        "p95_analyst_journey_improvement_pct": -percent_delta(
            baseline_p95, candidate_p95
        )
        if latency_comparable
        else None,
        "p95_time_saved_per_journey_ms": round(time_saved_ms, 3)
        if latency_comparable
        else None,
        "projected_operator_minutes_returned_per_day": round(
            max(0.0, time_saved_ms) * analyst_journeys_per_day / 60000, 3
        )
        if latency_comparable
        else None,
        "serial_operator_capacity_gain_pct": round(capacity_gain, 3)
        if latency_comparable
        else None,
        "question_coverage_uplift_points": round(
            (candidate["question_coverage_rate"] - baseline["question_coverage_rate"])
            * 100,
            3,
        ),
        "actionable_answer_uplift_points": round(
            (candidate["actionable_answer_rate"] - baseline["actionable_answer_rate"])
            * 100,
            3,
        ),
        "answer_retention_rate": rate(retained_answers, baseline_complete_answers),
        "semantic_parity_rate": rate(retained_matching_answers, retained_answers),
        "baseline_complete_answers": baseline_complete_answers,
        "paired_journeys": paired,
        "p95_question_delta_pct": question_deltas,
    }


def evaluate_gates(
    candidate: dict[str, Any], comparison: dict[str, Any], args: argparse.Namespace
) -> list[str]:
    failures: list[str] = []
    if candidate["actionable_answer_rate"] < args.min_actionable_rate:
        failures.append(
            f"candidate actionable answer rate {candidate['actionable_answer_rate']:.4f} is below {args.min_actionable_rate:.4f}"
        )
    if comparison["answer_retention_rate"] < args.min_answer_retention_rate:
        failures.append(
            f"baseline answer retention rate {comparison['answer_retention_rate']:.4f} is below {args.min_answer_retention_rate:.4f}"
        )
    if comparison["semantic_parity_rate"] < args.min_semantic_parity_rate:
        failures.append(
            f"retained-answer semantic parity rate {comparison['semantic_parity_rate']:.4f} is below {args.min_semantic_parity_rate:.4f}"
        )
    if (
        comparison["latency_comparable"]
        and comparison["p95_analyst_journey_delta_pct"] > args.max_p95_regression_pct
    ):
        failures.append(
            f"candidate p95 analyst journey regressed {comparison['p95_analyst_journey_delta_pct']:.2f}%"
        )
    return failures


def write_receipt(receipt: dict[str, Any], args: argparse.Namespace) -> None:
    write_text(args.json_out, json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    write_text(args.markdown_out, render_markdown(receipt))


def render_console(receipt: dict[str, Any]) -> str:
    comparison = receipt["comparison"]
    return (
        f"security_operator_benchmark: {receipt['status']}; "
        f"coverage_uplift={comparison['question_coverage_uplift_points']:.2f}pp "
        f"actionable_uplift={comparison['actionable_answer_uplift_points']:.2f}pp "
        f"actionable_rate={receipt['candidate']['actionable_answer_rate']:.4f} "
        f"answer_retention={comparison['answer_retention_rate']:.4f} "
        f"retained_parity={comparison['semantic_parity_rate']:.4f}"
    )


def render_markdown(receipt: dict[str, Any]) -> str:
    baseline = receipt["baseline"]
    candidate = receipt["candidate"]
    comparison = receipt["comparison"]
    lines = [
        "# Security operator benchmark",
        "",
        f"- Status: {receipt['status']}",
        "- Decision measured: identify, explain, and route active risk.",
        f"- Security-question coverage: {baseline['question_coverage_rate']:.4f} baseline; {candidate['question_coverage_rate']:.4f} candidate ({comparison['question_coverage_uplift_points']:.2f} percentage points).",
        f"- Actionable investigation rate: {baseline['actionable_answer_rate']:.4f} baseline; {candidate['actionable_answer_rate']:.4f} candidate ({comparison['actionable_answer_uplift_points']:.2f} percentage points).",
        f"- Baseline answer retention: {comparison['answer_retention_rate']:.4f}",
        f"- Retained-answer semantic parity: {comparison['semantic_parity_rate']:.4f}",
        "",
        "## Analyst journey",
        "",
        "| Release | p50 ms | p95 ms | p99 ms | Question coverage | Actionable answer rate |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for name, result in (("Baseline", baseline), ("Candidate", candidate)):
        latency = result["analyst_journey_latency_ms"]
        lines.append(
            f"| {name} | {latency['p50']} | {latency['p95']} | {latency['p99']} | {result['question_coverage_rate']:.4f} | {result['actionable_answer_rate']:.4f} |"
        )
    if comparison["latency_comparable"]:
        lines.extend(
            [
                "",
                f"Comparable p95 journey improvement: {comparison['p95_analyst_journey_improvement_pct']:.2f}%.",
                f"Comparable p95 time returned per investigation: {comparison['p95_time_saved_per_journey_ms']:.3f} ms.",
                f"Projected operator time returned per day: {comparison['projected_operator_minutes_returned_per_day']:.3f} minutes.",
            ]
        )
    else:
        lines.extend(
            [
                "",
                "Latency comparison: not applicable because the releases did not answer the same set of security questions.",
            ]
        )
    lines.extend(
        [
            "",
            "## Security questions",
            "",
            "| Question | Baseline p95 ms | Candidate p95 ms | Delta | Candidate complete rate |",
            "| --- | ---: | ---: | ---: | ---: |",
        ]
    )
    for name in sorted(candidate["questions"]):
        before = baseline["questions"][name]["latency_ms"]["p95"]
        after = candidate["questions"][name]["latency_ms"]["p95"]
        delta = comparison["p95_question_delta_pct"][name]
        complete = candidate["questions"][name]["complete_answer_rate"]
        rendered_delta = "n/a" if delta is None else f"{delta:.2f}%"
        lines.append(
            f"| {name.replace('_', ' ')} | {before} | {after} | {rendered_delta} | {complete:.4f} |"
        )
    lines.extend(["", "## Gate failures", ""])
    lines.extend(f"- {failure}" for failure in (receipt["failures"] or ["none"]))
    lines.append("")
    return "\n".join(lines)


def distribution(values: Sequence[float]) -> dict[str, float | None]:
    if not values:
        return {"p50": None, "p95": None, "p99": None, "mean": None}
    return {
        "p50": percentile(values, 50),
        "p95": percentile(values, 95),
        "p99": percentile(values, 99),
        "mean": round(statistics.fmean(values), 3),
    }


def percentile(values: Sequence[float], pct: int) -> float:
    rank = (pct / 100) * (len(values) - 1)
    lower = math.floor(rank)
    upper = math.ceil(rank)
    value = values[lower] + (values[upper] - values[lower]) * (rank - lower)
    return round(value, 3)


def percent_delta(before: float, after: float) -> float:
    if before == 0:
        return 0.0 if after == 0 else math.inf
    return ((after - before) / before) * 100


def list_value(payload: Any, key: str) -> list[Any]:
    if not isinstance(payload, dict) or not isinstance(payload.get(key), list):
        return []
    return payload[key]


def redact_scenario(scenario: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in scenario.items() if key != "tenant_id"}


def digest_json(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def elapsed_ms(started: float) -> float:
    return (time.perf_counter() - started) * 1000


def normalize_origin(value: str) -> str:
    parsed = urllib.parse.urlparse(value.strip())
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise BenchmarkUsageError(
            "targets must be http(s) origins without paths, queries, or fragments"
        )
    return value.strip().rstrip("/")


def safe_origin(value: str) -> str:
    parsed = urllib.parse.urlparse(value)
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))


def parse_headers(values: Sequence[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for raw in values:
        name, separator, value = raw.partition(":")
        if separator != ":" or not name.strip():
            raise BenchmarkUsageError("headers must use 'Name: value'")
        headers[name.strip()] = value.strip()
    return headers


def write_text(path: str, body: str) -> None:
    output = pathlib.Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(body, encoding="utf-8")


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def non_negative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be non-negative")
    return parsed


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


def unit_float(value: str) -> float:
    parsed = float(value)
    if not 0 <= parsed <= 1:
        raise argparse.ArgumentTypeError("must be between zero and one")
    return parsed


def rate(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def severity_rank(value: str) -> int:
    return {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(
        value.strip().upper(), -1
    )


class BenchmarkUsageError(ValueError):
    pass


if __name__ == "__main__":
    raise SystemExit(main())
