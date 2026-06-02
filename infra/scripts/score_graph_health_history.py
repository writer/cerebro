#!/usr/bin/env python3
from __future__ import annotations

import argparse
import glob
import json
import sys
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from statistics import median

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.graph_health_precog_diff import GraphHealthSnapshot, load_snapshot


@dataclass(frozen=True)
class MetricScore:
    metric: str
    latest: float
    expected: float
    residual: float
    robust_z: float
    slope_per_hour: float
    sigma: float


@dataclass(frozen=True)
class StackRisk:
    stack: str
    status: str
    risk_score: int
    latest_checked_at: str
    latest_nodes: int
    latest_relations: int
    runtime_coverage: str
    findings: tuple[str, ...]
    metric_scores: tuple[MetricScore, ...]
    snapshots_used: int


def load_history(paths: list[Path]) -> tuple[dict[str, list[GraphHealthSnapshot]], list[Path]]:
    by_stack: dict[str, list[GraphHealthSnapshot]] = {}
    skipped: list[Path] = []
    for path in paths:
        if path.stat().st_size == 0:
            skipped.append(path)
            continue
        try:
            snapshot = load_snapshot(path)
        except ValueError:
            skipped.append(path)
            continue
        by_stack.setdefault(snapshot.stack, []).append(snapshot)
    for snapshots in by_stack.values():
        snapshots.sort(key=lambda snapshot: snapshot.checked_at)
    return by_stack, skipped


def score_history(
    snapshots: list[GraphHealthSnapshot],
    *,
    required_relations: set[str] | None = None,
    min_samples: int = 5,
) -> StackRisk:
    if not snapshots:
        raise ValueError("at least one snapshot is required")
    required_relations = required_relations or set()
    latest = snapshots[-1]
    baseline = snapshots[:-1] if len(snapshots) > 1 else snapshots
    findings: list[str] = []
    risk = 0

    if latest.integrity_failed > 0:
        risk += 60
        findings.append(f"critical: integrity_failed={latest.integrity_failed}")

    missing_required = sorted(required_relations - latest.graph_relations)
    if missing_required:
        risk += 45
        findings.append(f"critical: missing required relations {','.join(missing_required)}")

    if latest.declared_runtimes > 0 and latest.current_ingest_runtimes < latest.declared_runtimes:
        gap = latest.declared_runtimes - latest.current_ingest_runtimes
        risk += min(35, 12 + gap * 8)
        findings.append(f"watch: runtime coverage {latest.current_ingest_runtimes}/{latest.declared_runtimes} (gap {gap})")

    metric_scores: list[MetricScore] = []
    if len(baseline) >= min_samples and latest.checked_at:
        for metric in ("nodes", "relations"):
            score = _score_metric(baseline, latest, metric)
            metric_scores.append(score)
            if score.robust_z <= -3:
                risk += 25
                findings.append(f"degraded: {metric} below robust trend (z={score.robust_z:.2f})")
            elif score.robust_z <= -2:
                risk += 10
                findings.append(f"watch: {metric} below robust trend (z={score.robust_z:.2f})")
        density_score = _score_density(baseline, latest)
        if density_score is not None:
            metric_scores.append(density_score)
            if density_score.robust_z <= -3:
                risk += 20
                findings.append(f"degraded: relation density below historical baseline (z={density_score.robust_z:.2f})")
            elif abs(density_score.robust_z) >= 5:
                risk += 5
                findings.append(f"watch: relation density shifted from historical baseline (z={density_score.robust_z:.2f})")
    elif len(snapshots) < min_samples:
        risk += 5
        findings.append(f"watch: only {len(snapshots)} snapshot(s) available; robust trend confidence is low")

    risk = min(100, risk)
    status = _status(risk, findings)
    if not findings:
        findings.append("ok: latest graph-health snapshot is inside robust historical expectations")
    coverage = f"{latest.current_ingest_runtimes}/{latest.declared_runtimes}" if latest.declared_runtimes else "unknown"
    return StackRisk(
        stack=latest.stack,
        status=status,
        risk_score=risk,
        latest_checked_at=latest.checked_at,
        latest_nodes=latest.nodes,
        latest_relations=latest.relations,
        runtime_coverage=coverage,
        findings=tuple(findings),
        metric_scores=tuple(metric_scores),
        snapshots_used=len(snapshots),
    )


def format_text(results: list[StackRisk], skipped: list[Path]) -> str:
    lines: list[str] = []
    for result in results:
        lines.extend(
            [
                f"{result.status.upper()} {result.stack}: risk={result.risk_score}/100 snapshots={result.snapshots_used}",
                f"latest={result.latest_checked_at} nodes={result.latest_nodes} relations={result.latest_relations} runtime_coverage={result.runtime_coverage}",
            ]
        )
        for finding in result.findings:
            lines.append(f"- {finding}")
        for score in result.metric_scores:
            lines.append(
                f"  {score.metric}: latest={score.latest:.3f} expected={score.expected:.3f} "
                f"residual={score.residual:.3f} z={score.robust_z:.2f} slope_per_hour={score.slope_per_hour:.3f}"
            )
        lines.append("")
    if skipped:
        lines.append(f"Skipped {len(skipped)} empty or invalid artifact(s).")
    return "\n".join(lines).rstrip()


def format_json(results: list[StackRisk], skipped: list[Path]) -> str:
    return json.dumps(
        {
            "results": [_stack_risk_json(result) for result in results],
            "skipped_artifacts": [str(path) for path in skipped],
        },
        indent=2,
        sort_keys=True,
    )


def _stack_risk_json(result: StackRisk) -> dict[str, object]:
    payload = asdict(result)
    payload["findings"] = list(result.findings)
    payload["metric_scores"] = [asdict(score) for score in result.metric_scores]
    return payload


def _score_metric(baseline: list[GraphHealthSnapshot], latest: GraphHealthSnapshot, metric: str) -> MetricScore:
    times = [_hours_since_epoch(snapshot.checked_at) for snapshot in baseline]
    origin = times[0]
    xs = [value - origin for value in times]
    ys = [float(getattr(snapshot, metric)) for snapshot in baseline]
    latest_x = _hours_since_epoch(latest.checked_at) - origin
    slope, intercept, sigma = _theil_sen(xs, ys)
    expected = slope * latest_x + intercept
    actual = float(getattr(latest, metric))
    residual = actual - expected
    return MetricScore(metric, actual, expected, residual, residual / sigma, slope, sigma)


def _score_density(baseline: list[GraphHealthSnapshot], latest: GraphHealthSnapshot) -> MetricScore | None:
    densities = [snapshot.relations / snapshot.nodes for snapshot in baseline if snapshot.nodes > 0]
    if len(densities) < 5 or latest.nodes <= 0:
        return None
    expected = median(densities)
    sigma = _mad_sigma(densities)
    actual = latest.relations / latest.nodes
    residual = actual - expected
    return MetricScore("relation_density", actual, expected, residual, residual / sigma, 0.0, sigma)


def _theil_sen(xs: list[float], ys: list[float]) -> tuple[float, float, float]:
    slopes: list[float] = []
    for i in range(len(xs)):
        for j in range(i + 1, len(xs)):
            dx = xs[j] - xs[i]
            if dx != 0:
                slopes.append((ys[j] - ys[i]) / dx)
    slope = median(slopes) if slopes else 0.0
    intercept = median([y - slope * x for x, y in zip(xs, ys)])
    residuals = [y - (slope * x + intercept) for x, y in zip(xs, ys)]
    return slope, intercept, _mad_sigma(residuals)


def _mad_sigma(values: list[float]) -> float:
    center = median(values)
    mad = median([abs(value - center) for value in values])
    return max(mad * 1.4826, 1e-9)


def _hours_since_epoch(value: str) -> float:
    if value.endswith("Z"):
        value = f"{value[:-1]}+00:00"
    return datetime.fromisoformat(value).timestamp() / 3600


def _status(risk: int, findings: list[str]) -> str:
    if any(finding.startswith("critical:") for finding in findings) or risk >= 70:
        return "critical"
    if any(finding.startswith("degraded:") for finding in findings) or risk >= 40:
        return "degraded"
    if risk > 0:
        return "watch"
    return "ok"


def _expand_paths(values: list[str]) -> list[Path]:
    paths: list[Path] = []
    for value in values:
        matches = [Path(match) for match in sorted(glob.glob(value))] if any(char in value for char in "*?[") else []
        if matches:
            paths.extend(matches)
        else:
            paths.append(Path(value))
    return paths


def _parse_required_relations(value: str) -> set[str]:
    return {part.strip() for part in value.split(",") if part.strip()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Score graph-health history with a lightweight robust trend model.")
    parser.add_argument("graph_health_tsv", nargs="+", help="TSV paths or shell-style glob patterns")
    parser.add_argument("--required-relations", default="")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)

    history, skipped = load_history(_expand_paths(args.graph_health_tsv))
    results = [
        score_history(snapshots, required_relations=_parse_required_relations(args.required_relations))
        for _, snapshots in sorted(history.items())
    ]
    if args.format == "json":
        print(format_json(results, skipped))
    else:
        print(format_text(results, skipped))
    return 1 if any(result.status == "critical" for result in results) else 0


if __name__ == "__main__":
    sys.exit(main())
