#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class GraphHealthSnapshot:
    checked_at: str
    stack: str
    nodes: int
    relations: int
    integrity_passed: int
    integrity_failed: int
    graph_relations: frozenset[str]
    current_ingest_runtimes: int
    declared_runtimes: int
    missing_ingest_runtimes: tuple[str, ...]


@dataclass(frozen=True)
class PrecogFinding:
    severity: str
    check: str
    message: str


def load_snapshot(path: Path) -> GraphHealthSnapshot:
    with path.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle, delimiter="\t"))
    if len(rows) != 1:
        raise ValueError(f"{path} must contain exactly one graph-health row")
    row = rows[0]
    return GraphHealthSnapshot(
        checked_at=str(row.get("checked_at") or "").strip(),
        stack=str(row.get("stack") or "").strip(),
        nodes=_int_field(row, "nodes"),
        relations=_int_field(row, "relations"),
        integrity_passed=_int_field(row, "integrity_passed"),
        integrity_failed=_int_field(row, "integrity_failed"),
        graph_relations=frozenset(_split_csv(row.get("graph_relations", ""))),
        current_ingest_runtimes=_int_field(row, "current_ingest_runtimes"),
        declared_runtimes=_int_field(row, "declared_runtimes"),
        missing_ingest_runtimes=tuple(_split_csv(row.get("missing_ingest_runtimes", ""))),
    )


def find_precog_drift(
    baseline: GraphHealthSnapshot,
    candidate: GraphHealthSnapshot,
    *,
    node_drop_warning_percent: float = 10.0,
    relation_drop_warning_percent: float = 10.0,
    required_relations: set[str] | None = None,
) -> list[PrecogFinding]:
    findings: list[PrecogFinding] = []
    required_relations = required_relations or set()

    if baseline.stack and candidate.stack and baseline.stack != candidate.stack:
        findings.append(PrecogFinding("error", "stack", f"stack changed from {baseline.stack} to {candidate.stack}"))

    if candidate.nodes <= 0:
        findings.append(PrecogFinding("error", "nodes", "candidate graph has no nodes"))
    if candidate.relations <= 0:
        findings.append(PrecogFinding("error", "relations", "candidate graph has no relationships"))

    if candidate.integrity_failed > 0:
        findings.append(PrecogFinding("error", "integrity", f"candidate has {candidate.integrity_failed} failed integrity check(s)"))
    if baseline.integrity_passed > 0 and candidate.integrity_passed < baseline.integrity_passed:
        findings.append(
            PrecogFinding(
                "warning",
                "integrity",
                f"integrity pass count dropped from {baseline.integrity_passed} to {candidate.integrity_passed}",
            )
        )

    _append_count_drop(
        findings,
        "nodes",
        baseline.nodes,
        candidate.nodes,
        node_drop_warning_percent,
        "node count",
    )
    _append_count_drop(
        findings,
        "relations",
        baseline.relations,
        candidate.relations,
        relation_drop_warning_percent,
        "relationship count",
    )

    lost_required_relations: set[str] = set()
    lost_relations = sorted(baseline.graph_relations - candidate.graph_relations)
    for relation in lost_relations:
        if relation in required_relations:
            lost_required_relations.add(relation)
            findings.append(PrecogFinding("error", "graph_relations", f"required relation disappeared: {relation}"))
        else:
            findings.append(PrecogFinding("warning", "graph_relations", f"observed relation disappeared: {relation}"))
    for relation in sorted((required_relations - candidate.graph_relations) - lost_required_relations):
        findings.append(PrecogFinding("error", "graph_relations", f"required relation missing: {relation}"))

    if candidate.declared_runtimes > 0 and candidate.current_ingest_runtimes < candidate.declared_runtimes:
        findings.append(
            PrecogFinding(
                "warning",
                "ingest_runtimes",
                "current ingest runtime coverage is "
                f"{candidate.current_ingest_runtimes}/{candidate.declared_runtimes} "
                f"(gap {candidate.declared_runtimes - candidate.current_ingest_runtimes})",
            )
        )
    if candidate.current_ingest_runtimes < baseline.current_ingest_runtimes:
        findings.append(
            PrecogFinding(
                "warning",
                "ingest_runtimes",
                f"current ingest runtimes dropped from {baseline.current_ingest_runtimes} to {candidate.current_ingest_runtimes}",
            )
        )
    new_missing = sorted(set(candidate.missing_ingest_runtimes) - set(baseline.missing_ingest_runtimes))
    for runtime_id in new_missing:
        findings.append(PrecogFinding("error", "ingest_runtimes", f"new missing ingest runtime history: {runtime_id}"))

    return findings


def format_text(baseline: GraphHealthSnapshot, candidate: GraphHealthSnapshot, findings: list[PrecogFinding]) -> str:
    error_count = sum(1 for finding in findings if finding.severity == "error")
    warning_count = sum(1 for finding in findings if finding.severity == "warning")
    status = "FAIL" if error_count else "WARN" if warning_count else "PASS"
    lines = [
        f"{status} graph precog diff for {candidate.stack or 'unknown-stack'}",
        f"baseline={baseline.checked_at or 'unknown'} candidate={candidate.checked_at or 'unknown'}",
        f"nodes={baseline.nodes}->{candidate.nodes} relations={baseline.relations}->{candidate.relations}",
        f"integrity_failed={candidate.integrity_failed} errors={error_count} warnings={warning_count}",
    ]
    if findings:
        for finding in findings:
            lines.append(f"{finding.severity.upper()} {finding.check}: {finding.message}")
    else:
        lines.append("No graph-health drift detected.")
    return "\n".join(lines)


def format_json(baseline: GraphHealthSnapshot, candidate: GraphHealthSnapshot, findings: list[PrecogFinding]) -> str:
    has_errors = any(finding.severity == "error" for finding in findings)
    has_warnings = any(finding.severity == "warning" for finding in findings)
    payload = {
        "status": "failed" if has_errors else "warning" if has_warnings else "passed",
        "baseline": _snapshot_json(baseline),
        "candidate": _snapshot_json(candidate),
        "findings": [asdict(finding) for finding in findings],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def _snapshot_json(snapshot: GraphHealthSnapshot) -> dict[str, object]:
    payload = asdict(snapshot)
    payload["graph_relations"] = sorted(snapshot.graph_relations)
    payload["missing_ingest_runtimes"] = list(snapshot.missing_ingest_runtimes)
    return payload


def _int_field(row: dict[str, str], key: str) -> int:
    value = str(row.get(key) or "").strip()
    if not value:
        return 0
    return int(value)


def _split_csv(value: str | None) -> list[str]:
    return sorted({part.strip() for part in str(value or "").split(",") if part.strip()})


def _append_count_drop(
    findings: list[PrecogFinding],
    check: str,
    baseline_value: int,
    candidate_value: int,
    threshold_percent: float,
    label: str,
) -> None:
    if baseline_value <= 0 or candidate_value >= baseline_value:
        return
    drop_percent = ((baseline_value - candidate_value) / baseline_value) * 100
    if drop_percent >= threshold_percent:
        findings.append(
            PrecogFinding(
                "warning",
                check,
                f"{label} dropped {drop_percent:.1f}% from {baseline_value} to {candidate_value}",
            )
        )


def _parse_required_relations(value: str) -> set[str]:
    return set(_split_csv(value))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare two graph-health TSV snapshots for early drift signals.")
    parser.add_argument("baseline_tsv", type=Path)
    parser.add_argument("candidate_tsv", type=Path)
    parser.add_argument("--node-drop-warning-percent", type=float, default=10.0)
    parser.add_argument("--relation-drop-warning-percent", type=float, default=10.0)
    parser.add_argument("--required-relations", default="")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)

    baseline = load_snapshot(args.baseline_tsv)
    candidate = load_snapshot(args.candidate_tsv)
    findings = find_precog_drift(
        baseline,
        candidate,
        node_drop_warning_percent=args.node_drop_warning_percent,
        relation_drop_warning_percent=args.relation_drop_warning_percent,
        required_relations=_parse_required_relations(args.required_relations),
    )
    if args.format == "json":
        print(format_json(baseline, candidate, findings))
    else:
        print(format_text(baseline, candidate, findings))
    return 1 if any(finding.severity == "error" for finding in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
