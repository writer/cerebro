#!/usr/bin/env python3
"""Fail fast on documentation claims that drift from the bootstrap runtime."""

from __future__ import annotations

import json
import pathlib
import re
import sys
from typing import Optional


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


CONFIG_DEFAULT_DOCS = {
    "README.md": {
        "CEREBRO_API_AUTH_ENABLED": (2, "true outside acknowledged dev mode"),
        "CEREBRO_RATE_LIMIT_ENABLED": (2, "true outside acknowledged dev mode"),
        "CEREBRO_RATE_LIMIT_RPS": (2, "100"),
        "CEREBRO_RATE_LIMIT_BURST": (2, "150"),
    },
    "docs/CONFIG_ENV_VARS.md": {
        "CEREBRO_API_AUTH_ENABLED": (1, "true outside acknowledged dev mode"),
        "CEREBRO_RATE_LIMIT_ENABLED": (1, "true outside acknowledged dev mode"),
        "CEREBRO_RATE_LIMIT_RPS": (1, "100"),
        "CEREBRO_RATE_LIMIT_BURST": (1, "150"),
    },
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


def markdown_row_cells(body: str, variable: str) -> Optional[list[str]]:
    marker = f"`{variable}`"
    for line in body.splitlines():
        if marker not in line or not line.lstrip().startswith("|"):
            continue
        cells = [normalize_markdown_cell(cell) for cell in line.strip().strip("|").split("|")]
        if cells and cells[0] == variable:
            return cells
    return None


def normalize_markdown_cell(value: str) -> str:
    return re.sub(r"\s+", " ", value.replace("`", "").strip())


def check_config_default_docs() -> list[str]:
    failures: list[str] = []
    config_go = read("internal/config/config.go")
    runtime_markers = [
        'parseBoolEnvDefault("CEREBRO_API_AUTH_ENABLED", !cfg.DevMode)',
        'parseBoolEnvDefault("CEREBRO_RATE_LIMIT_ENABLED", !cfg.DevMode)',
        'parseFloatEnv("CEREBRO_RATE_LIMIT_RPS", 100)',
        'parseIntEnv("CEREBRO_RATE_LIMIT_BURST", 150)',
    ]
    for marker in runtime_markers:
        if marker not in config_go:
            failures.append(f"internal/config/config.go: expected runtime default marker {marker!r}")
    for rel, expectations in CONFIG_DEFAULT_DOCS.items():
        body = read(rel)
        for variable, (default_index, expected) in expectations.items():
            cells = markdown_row_cells(body, variable)
            if cells is None:
                failures.append(f"{rel}: missing documented row for {variable}")
                continue
            if default_index >= len(cells):
                failures.append(f"{rel}: row for {variable} has no default column")
                continue
            actual = cells[default_index]
            if actual != expected:
                failures.append(f"{rel}: {variable} default is {actual!r}, want {expected!r}")
    env_example = read(".env.example")
    for line in [
        "CEREBRO_API_AUTH_ENABLED=true",
        "CEREBRO_RATE_LIMIT_ENABLED=true",
        "CEREBRO_RATE_LIMIT_RPS=100",
        "CEREBRO_RATE_LIMIT_BURST=150",
    ]:
        if line not in env_example:
            failures.append(f".env.example: expected {line!r}")
    return failures


def main() -> int:
    failures = []
    failures.extend(check_forbidden_markers())
    failures.extend(check_findings_catalog_reference())
    failures.extend(check_config_default_docs())
    if failures:
        print("docs drift check failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print("docs drift check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
