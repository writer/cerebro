#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


ATTACK_RELATIONS = ("can_admin", "can_assume", "can_impersonate", "can_perform")
SENSITIVITY_RELATIONS = ("has_classification", "tagged_as")

ATTACK_PATH_RELS = frozenset({
    "can_admin", "can_assume", "can_impersonate", "can_perform",
    "can_reach", "can_delete", "can_read", "can_write",
})
ADMIN_HUB_RELS = frozenset({
    "belongs_to", "represents", "contains", "member_of", "located_in",
})
FINDING_PATH_RELS = frozenset({
    "has_finding", "has_evidence", "affected_by", "observed_on",
})


@dataclass(frozen=True)
class ActualGraphSnapshot:
    stack: str
    nodes: int
    relations: int
    relation_counts: dict[str, int]
    paths: dict[str, Any] | None = None


@dataclass(frozen=True)
class ActualGraphRisk:
    stack: str
    status: str
    risk_score: int
    nodes: int
    relations: int
    relation_density: float
    findings: tuple[str, ...]
    metrics: dict[str, float]


def load_snapshot_spec(spec: str) -> ActualGraphSnapshot:
    parts = spec.split(":")
    if len(parts) not in (4, 5):
        raise ValueError("snapshot spec must be stack:nodes:relations:relation_counts_json[:paths_json]")
    stack, nodes, relations, relation_path = parts[:4]
    paths_path = parts[4] if len(parts) == 5 else ""
    paths = _load_json(Path(paths_path)) if paths_path else None
    return ActualGraphSnapshot(
        stack=stack,
        nodes=int(nodes),
        relations=int(relations),
        relation_counts=_load_relation_counts(Path(relation_path)),
        paths=paths,
    )


def score_actual_graph(snapshot: ActualGraphSnapshot) -> ActualGraphRisk:
    findings: list[str] = []
    metrics: dict[str, float] = {
        "relation_density": snapshot.relations / snapshot.nodes if snapshot.nodes else 0.0,
    }
    risk = 0

    attack_total = sum(snapshot.relation_counts.get(relation, 0) for relation in ATTACK_RELATIONS)
    attack_per_10k = _per_10k(attack_total, snapshot.nodes)
    metrics["attack_relations_per_10k_nodes"] = attack_per_10k
    if attack_per_10k >= 250:
        risk += 25
        findings.append(f"degraded: attack-path relation pressure is high ({attack_per_10k:.1f}/10k nodes)")
    elif attack_per_10k >= 100:
        risk += 12
        findings.append(f"watch: attack-path relation pressure is elevated ({attack_per_10k:.1f}/10k nodes)")

    finding_per_10k = _per_10k(snapshot.relation_counts.get("has_finding", 0), snapshot.nodes)
    metrics["has_finding_per_10k_nodes"] = finding_per_10k
    if finding_per_10k >= 2000:
        risk += 20
        findings.append(f"degraded: finding-anchor pressure is very high ({finding_per_10k:.1f}/10k nodes)")
    elif finding_per_10k >= 750:
        risk += 8
        findings.append(f"watch: finding-anchor pressure is elevated ({finding_per_10k:.1f}/10k nodes)")

    sensitivity_total = sum(snapshot.relation_counts.get(relation, 0) for relation in SENSITIVITY_RELATIONS)
    metrics["sensitivity_relations"] = float(sensitivity_total)
    if sensitivity_total == 0:
        risk += 25
        findings.append("blindspot: no sensitivity/crown-jewel relations are present")

    owned_by = snapshot.relation_counts.get("owned_by", 0)
    owned_by_per_10k = _per_10k(owned_by, snapshot.nodes)
    metrics["owned_by_per_10k_nodes"] = owned_by_per_10k
    if owned_by == 0:
        risk += 20
        findings.append("blindspot: no ownership edges are present")
    elif owned_by_per_10k < 10:
        risk += 12
        findings.append(f"blindspot: ownership coverage is sparse ({owned_by_per_10k:.1f}/10k nodes)")

    if snapshot.paths is None:
        risk += 10
        findings.append("watch: path/topology sample unavailable; traversal may be timing out or uncollected")
    else:
        risk += _score_paths(snapshot, findings, metrics)

    risk = min(100, risk)
    if not findings:
        findings.append("ok: actual graph risk features are within current heuristic bounds")
    return ActualGraphRisk(
        stack=snapshot.stack,
        status=_status(risk, findings),
        risk_score=risk,
        nodes=snapshot.nodes,
        relations=snapshot.relations,
        relation_density=metrics["relation_density"],
        findings=tuple(findings),
        metrics=metrics,
    )


def compare_snapshots(snapshots: list[ActualGraphSnapshot]) -> list[str]:
    if len(snapshots) < 2:
        return []
    insights: list[str] = []
    keys = sorted({key for snapshot in snapshots for key in snapshot.relation_counts})
    for key in keys:
        normalized = [(snapshot.stack, _per_10k(snapshot.relation_counts.get(key, 0), snapshot.nodes)) for snapshot in snapshots]
        nonzero = [(stack, value) for stack, value in normalized if value > 0]
        if len(nonzero) < 2:
            continue
        low_stack, low_value = min(nonzero, key=lambda item: item[1])
        high_stack, high_value = max(nonzero, key=lambda item: item[1])
        if low_value > 0 and high_value / low_value >= 5:
            insights.append(f"skew: {key} is {high_value / low_value:.1f}x denser in {high_stack} than {low_stack}")
    return insights


def format_text(risks: list[ActualGraphRisk], comparisons: list[str]) -> str:
    lines: list[str] = []
    for risk in risks:
        lines.append(f"{risk.status.upper()} {risk.stack}: risk={risk.risk_score}/100 nodes={risk.nodes} relations={risk.relations} density={risk.relation_density:.3f}")
        for finding in risk.findings:
            lines.append(f"- {finding}")
        for key, value in sorted(risk.metrics.items()):
            lines.append(f"  {key}: {value:.3f}")
        lines.append("")
    if comparisons:
        lines.append("Cross-stack skews:")
        lines.extend(f"- {insight}" for insight in comparisons)
    return "\n".join(lines).rstrip()


def format_json(risks: list[ActualGraphRisk], comparisons: list[str]) -> str:
    return json.dumps(
        {"risks": [asdict(risk) for risk in risks], "comparisons": comparisons},
        indent=2,
        sort_keys=True,
    )


def _classify_pattern(pattern: dict[str, Any]) -> str:
    r1 = pattern.get("first_relation", "")
    r2 = pattern.get("second_relation", "")
    if r1 in ATTACK_PATH_RELS or r2 in ATTACK_PATH_RELS:
        return "attack"
    if r1 in ADMIN_HUB_RELS and r2 in FINDING_PATH_RELS:
        return "transitive"
    if r1 in FINDING_PATH_RELS or r2 in FINDING_PATH_RELS:
        return "direct"
    return "other"


def _score_paths(snapshot: ActualGraphSnapshot, findings: list[str], metrics: dict[str, float]) -> int:
    paths = snapshot.paths or {}
    risk = 0

    topology = paths.get("topology") if isinstance(paths.get("topology"), dict) else {}
    isolated_pct = _pct(float(topology.get("isolated") or 0), snapshot.nodes)
    sink_pct = _pct(float(topology.get("sinks_only") or 0), snapshot.nodes)
    source_pct = _pct(float(topology.get("sources_only") or 0), snapshot.nodes)
    metrics["isolated_pct"] = isolated_pct
    metrics["sinks_only_pct"] = sink_pct
    metrics["sources_only_pct"] = source_pct
    if isolated_pct >= 1.0:
        risk += 10
        findings.append(f"watch: isolated node share is elevated ({isolated_pct:.2f}%)")
    if sink_pct >= 40:
        risk += 5
        findings.append(f"watch: graph is sink-heavy ({sink_pct:.1f}% sink-only nodes)")

    raw_patterns = paths.get("patterns") if isinstance(paths.get("patterns"), list) else []
    family_totals: dict[str, int] = {"attack": 0, "transitive": 0, "direct": 0, "other": 0}
    top_actionable_count = 0
    top_actionable_label = ""
    for pattern in raw_patterns:
        if not isinstance(pattern, dict):
            continue
        count = int(pattern.get("count") or 0)
        family = _classify_pattern(pattern)
        family_totals[family] += count
        if family != "transitive" and count > top_actionable_count:
            top_actionable_count = count
            top_actionable_label = (
                f"{pattern.get('from_type')}--{pattern.get('first_relation')}-->"
                f"{pattern.get('via_type')}--{pattern.get('second_relation')}-->{pattern.get('to_type')}"
            )

    all_paths = sum(family_totals.values())
    metrics["path_family_attack"] = float(family_totals["attack"])
    metrics["path_family_transitive"] = float(family_totals["transitive"])
    metrics["path_family_direct"] = float(family_totals["direct"])
    metrics["path_family_other"] = float(family_totals["other"])

    if all_paths > 0:
        gravity_ratio = family_totals["transitive"] / all_paths
        metrics["gravity_well_ratio"] = gravity_ratio
        if gravity_ratio >= 0.8:
            findings.append(
                f"info: {gravity_ratio:.0%} of sampled paths are transitive "
                f"(admin-hub gravity wells); headline path count {all_paths:,} is inflated"
            )

    has_finding = max(snapshot.relation_counts.get("has_finding", 0), 1)
    if top_actionable_count > 0:
        explosion = top_actionable_count / has_finding
        metrics["top_actionable_pattern_count"] = float(top_actionable_count)
        metrics["top_actionable_to_finding_ratio"] = explosion
        if explosion >= 25:
            risk += 15
            findings.append(
                f"watch: actionable path fanout ({explosion:.1f}x has_finding) in {top_actionable_label}"
            )

    top_all = max((int(p.get("count") or 0) for p in raw_patterns if isinstance(p, dict)), default=0)
    metrics["top_path_pattern_count"] = float(top_all)
    metrics["top_path_to_finding_edge_ratio"] = top_all / has_finding

    return risk


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return payload


def _load_relation_counts(path: Path) -> dict[str, int]:
    payload = _load_json(path)
    counts = payload.get("relations") if isinstance(payload.get("relations"), dict) else payload
    return {str(key): int(value or 0) for key, value in counts.items()}


def _per_10k(value: int, nodes: int) -> float:
    return value / nodes * 10000 if nodes > 0 else 0.0


def _pct(value: float, total: int) -> float:
    return value / total * 100 if total > 0 else 0.0


def _status(risk: int, findings: list[str]) -> str:
    if any(finding.startswith("critical:") for finding in findings) or risk >= 70:
        return "critical"
    if any(finding.startswith("degraded:") for finding in findings) or risk >= 40:
        return "degraded"
    if risk > 0:
        return "watch"
    return "ok"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Score actual graph relation/path exports for precog risk signals.")
    parser.add_argument("--snapshot", action="append", required=True, help="stack:nodes:relations:relation_counts_json[:paths_json]")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)

    snapshots = [load_snapshot_spec(spec) for spec in args.snapshot]
    risks = [score_actual_graph(snapshot) for snapshot in snapshots]
    comparisons = compare_snapshots(snapshots)
    if args.format == "json":
        print(format_json(risks, comparisons))
    else:
        print(format_text(risks, comparisons))
    return 1 if any(risk.status == "critical" for risk in risks) else 0


if __name__ == "__main__":
    sys.exit(main())
