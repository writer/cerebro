#!/usr/bin/env python3
"""Fail fast on documentation claims that drift from the bootstrap runtime."""

from __future__ import annotations

import json
import pathlib
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]


FORBIDDEN_DOC_MARKERS = {
    "docs/FINDINGS_PLATFORM_ARCHITECTURE.md": [
        "Today the built-in catalog contains one rule",
        "first built-in finding rule",
    ],
    "docs/VULNERABILITY_DB_ARCHITECTURE.md": [
        "SQLite via `internal/vulndb.SQLiteStore`",
        "persisted by default at `VULNDB_STATE_FILE`",
    ],
}


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def check_forbidden_markers() -> list[str]:
    failures: list[str] = []
    for rel, markers in FORBIDDEN_DOC_MARKERS.items():
        body = read(rel)
        for marker in markers:
            if marker in body:
                failures.append(f"{rel}: stale marker still present: {marker!r}")
    return failures


def check_findings_catalog_reference() -> list[str]:
    catalog = json.loads(read("internal/findings/public_detection_catalog.json"))
    count = len(catalog.get("detections") or [])
    body = read("docs/FINDINGS_PLATFORM_ARCHITECTURE.md")
    expected = f"currently contains {count} rules"
    if expected not in body:
        return [
            "docs/FINDINGS_PLATFORM_ARCHITECTURE.md: "
            f"expected public detection catalog count phrase {expected!r}"
        ]
    return []


def main() -> int:
    failures = []
    failures.extend(check_forbidden_markers())
    failures.extend(check_findings_catalog_reference())
    if failures:
        print("docs drift check failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print("docs drift check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
