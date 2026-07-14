#!/usr/bin/env python3
"""Run govulncheck and fail on unsuppressed high/critical reachable findings."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TOOL = "golang.org/x/vuln/cmd/govulncheck@v1.1.4"
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
    env["GOTOOLCHAIN"] = env.get("GOTOOLCHAIN", "go1.26.5")
    command = ["go", "run", DEFAULT_TOOL, "-format", "json", *patterns]
    completed = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True, check=False)
    return completed.returncode, completed.stdout, completed.stderr


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("patterns", nargs="*", default=["./..."])
    parser.add_argument("--ignore-file", default=".govulncheck-ignore")
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

    findings: list[dict[str, Any]] = []
    for message in messages:
        finding = message.get("finding")
        if isinstance(finding, dict):
            findings.append(finding)

    blocking: list[str] = []
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
        blocking.append(osv_id)

    if blocking:
        print(f"govulncheck found {len(blocking)} unsuppressed reachable vulnerabilities:", file=sys.stderr)
        for osv_id in blocking:
            print(f"- {osv_id}", file=sys.stderr)
        print(f"Add accepted risks to {args.ignore_file} with a justification comment.", file=sys.stderr)
        return 1
    if exit_code != 0 and not findings:
        print("govulncheck failed before producing findings", file=sys.stderr)
        return exit_code
    if suppressed:
        print(f"govulncheck: suppressed {len(set(suppressed))} accepted findings")
    print("govulncheck: no unsuppressed reachable vulnerabilities")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
