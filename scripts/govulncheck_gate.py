#!/usr/bin/env python3
"""Run govulncheck and fail on unsuppressed high/critical reachable findings."""

from __future__ import annotations

import argparse
import json
import math
import os
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TOOL = "golang.org/x/vuln/cmd/govulncheck@v1.1.4"
SEVERITY_RANK = {
    "LOW": 1,
    "MEDIUM": 2,
    "MODERATE": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def cvss3_base_score(vector: str) -> float | None:
    metrics = dict(part.split(":", 1) for part in vector.split("/") if ":" in part)
    required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    if not required.issubset(metrics):
        return None
    impact_values = {"H": 0.56, "L": 0.22, "N": 0.0}
    exploitability_values = {
        "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
        "AC": {"L": 0.77, "H": 0.44},
        "UI": {"N": 0.85, "R": 0.62},
    }
    privileges_required = {
        "U": {"N": 0.85, "L": 0.62, "H": 0.27},
        "C": {"N": 0.85, "L": 0.68, "H": 0.5},
    }
    scope = metrics["S"]
    try:
        isc_base = 1 - (
            (1 - impact_values[metrics["C"]])
            * (1 - impact_values[metrics["I"]])
            * (1 - impact_values[metrics["A"]])
        )
        if scope == "U":
            impact = 6.42 * isc_base
        elif scope == "C":
            impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
        else:
            return None
        exploitability = (
            8.22
            * exploitability_values["AV"][metrics["AV"]]
            * exploitability_values["AC"][metrics["AC"]]
            * privileges_required[scope][metrics["PR"]]
            * exploitability_values["UI"][metrics["UI"]]
        )
    except KeyError:
        return None
    if impact <= 0:
        return 0.0
    if scope == "U":
        score = min(impact + exploitability, 10)
    else:
        score = min(1.08 * (impact + exploitability), 10)
    return math.ceil(score * 10) / 10


def severity_from_score(score: float) -> str:
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "UNKNOWN"


def parse_ignore_file(path: Path) -> tuple[set[str], list[str]]:
    ignored: set[str] = set()
    errors: list[str] = []
    if not path.exists():
        return ignored, errors
    for index, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        vuln_id, marker, justification = stripped.partition("#")
        vuln_id = vuln_id.strip()
        justification = justification.strip()
        if not marker or not justification:
            errors.append(f"{path}:{index}: suppression for {vuln_id!r} must include a justification comment")
            continue
        ignored.add(vuln_id)
    return ignored, errors


def severity_from_osv(osv: dict[str, Any]) -> str:
    severities: list[str] = []
    for severity in osv.get("severity") or []:
        if not isinstance(severity, dict):
            continue
        score = severity.get("score")
        if not isinstance(score, str):
            continue
        try:
            severities.append(severity_from_score(float(score)))
            continue
        except ValueError:
            if not score.startswith("CVSS:3."):
                continue
        if score.startswith("CVSS:3."):
            parsed = cvss3_base_score(score)
            if parsed is not None:
                severities.append(severity_from_score(parsed))
    database_specific = osv.get("database_specific")
    if isinstance(database_specific, dict):
        value = database_specific.get("severity")
        if isinstance(value, str):
            severities.append(value)
    for affected in osv.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        ecosystem_specific = affected.get("ecosystem_specific")
        if isinstance(ecosystem_specific, dict):
            value = ecosystem_specific.get("severity")
            if isinstance(value, str):
                severities.append(value)
    ranked = [(SEVERITY_RANK.get(value.upper(), 0), value.upper()) for value in severities]
    ranked.sort(reverse=True)
    return ranked[0][1] if ranked else "UNKNOWN"


def parse_json_stream(output: str) -> list[dict[str, Any]]:
    decoder = json.JSONDecoder()
    messages: list[dict[str, Any]] = []
    index = 0
    while index < len(output):
        while index < len(output) and output[index].isspace():
            index += 1
        if index >= len(output):
            break
        value, index = decoder.raw_decode(output, index)
        if isinstance(value, list):
            messages.extend(item for item in value if isinstance(item, dict))
        elif isinstance(value, dict):
            messages.append(value)
    return messages


def finding_osv_id(finding: dict[str, Any]) -> str:
    value = finding.get("osv") or finding.get("osv_id")
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        osv_id = value.get("id")
        if isinstance(osv_id, str):
            return osv_id
    return ""


def is_reachable_finding(finding: dict[str, Any]) -> bool:
    trace = finding.get("trace")
    if not isinstance(trace, list) or not trace:
        return False
    top_frame = trace[0]
    return isinstance(top_frame, dict) and isinstance(top_frame.get("function"), str) and top_frame["function"] != ""


def run_govulncheck(patterns: list[str]) -> tuple[int, str, str]:
    env = os.environ.copy()
    env["GOFLAGS"] = ""
    env["GOTOOLCHAIN"] = env.get("GOTOOLCHAIN", "go1.26.3")
    command = ["go", "run", DEFAULT_TOOL, "-format", "json", *patterns]
    completed = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True, check=False)
    return completed.returncode, completed.stdout, completed.stderr


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("patterns", nargs="*", default=["./..."])
    parser.add_argument("--ignore-file", default=".govulncheck-ignore")
    parser.add_argument("--min-severity", default="HIGH", choices=sorted(SEVERITY_RANK))
    args = parser.parse_args()

    ignored, ignore_errors = parse_ignore_file(ROOT / args.ignore_file)
    if ignore_errors:
        print("govulncheck suppression errors:", file=sys.stderr)
        for error in ignore_errors:
            print(f"- {error}", file=sys.stderr)
        return 2

    exit_code, stdout, stderr = run_govulncheck(args.patterns)
    if stderr:
        print(stderr, file=sys.stderr, end="" if stderr.endswith("\n") else "\n")
    try:
        messages = parse_json_stream(stdout)
    except json.JSONDecodeError as exc:
        print(f"govulncheck emitted invalid JSON: {exc}", file=sys.stderr)
        if stdout:
            print(stdout, file=sys.stderr)
        return 2

    osvs: dict[str, dict[str, Any]] = {}
    findings: list[dict[str, Any]] = []
    for message in messages:
        osv = message.get("osv")
        if isinstance(osv, dict) and isinstance(osv.get("id"), str):
            osvs[osv["id"]] = osv
        finding = message.get("finding")
        if isinstance(finding, dict):
            findings.append(finding)

    threshold = SEVERITY_RANK[args.min_severity]
    blocking: list[tuple[str, str, str]] = []
    suppressed: list[str] = []
    for finding in findings:
        if not is_reachable_finding(finding):
            continue
        osv_id = finding_osv_id(finding)
        if not osv_id:
            continue
        if osv_id in ignored:
            suppressed.append(osv_id)
            continue
        severity = severity_from_osv(osvs.get(osv_id, {}))
        if SEVERITY_RANK.get(severity, 0) >= threshold:
            summary = osvs.get(osv_id, {}).get("summary") or "reachable vulnerability"
            blocking.append((osv_id, severity, str(summary)))

    if blocking:
        print(f"govulncheck found {len(blocking)} unsuppressed {args.min_severity}+ reachable vulnerabilities:", file=sys.stderr)
        for osv_id, severity, summary in blocking:
            print(f"- {osv_id} [{severity}]: {summary}", file=sys.stderr)
        print(f"Add accepted risks to {args.ignore_file} with a justification comment.", file=sys.stderr)
        return 1
    if exit_code != 0 and not findings:
        print("govulncheck failed before producing findings", file=sys.stderr)
        return exit_code
    if suppressed:
        print(f"govulncheck: suppressed {len(set(suppressed))} accepted findings")
    print("govulncheck: no unsuppressed high/critical reachable vulnerabilities")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
