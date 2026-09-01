#!/usr/bin/env python3
"""Fail fast on documentation claims that drift from the runtime or machine ledgers."""

from __future__ import annotations

import json
import pathlib
import re
import sys
from typing import Optional


ROOT = pathlib.Path(__file__).resolve().parents[1]


FORBIDDEN_DOC_MARKERS = {
    "docs/domains/findings-platform-architecture.md": [
        "Today the built-in catalog contains one rule",
        "first built-in finding rule",
    ],
    "docs/engineering/vulnerability-db-architecture.md": [
        "SQLite via `internal/vulndb.SQLiteStore`",
        "persisted by default at `VULNDB_STATE_FILE`",
    ],
}


CONFIG_DEFAULT_DOCS = {
    "docs/reference/config-env-vars.md": {
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
    body = read("docs/domains/findings-platform-architecture.md")
    expected = f"currently contains {count} rules"
    if expected not in body:
        return [
            "docs/domains/findings-platform-architecture.md: "
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


RUST_MIGRATION_LEDGER = "docs/engineering/rust-migration-ledger.json"
RUST_MIGRATION_DOC = "docs/engineering/rust-organizational-platform.md"
RUST_MIGRATION_DOC_HEADING = "## Remaining compatibility callers"


def markdown_section(body: str, heading: str) -> Optional[str]:
    """Return the text under `heading` up to the next heading of the same or higher level."""
    lines = body.splitlines()
    level = len(heading) - len(heading.lstrip("#"))
    start = None
    for index, line in enumerate(lines):
        if line.strip() == heading:
            start = index + 1
            break
    if start is None:
        return None
    end = len(lines)
    for index in range(start, len(lines)):
        stripped = lines[index].lstrip()
        if stripped.startswith("#"):
            depth = len(stripped) - len(stripped.lstrip("#"))
            if depth <= level:
                end = index
                break
    return "\n".join(lines[start:end])


TABLE_ROW_PACKAGE = re.compile(r"^\|\s*`(internal/[A-Za-z0-9_./-]+)`")


def table_row_packages(section: str) -> list[str]:
    """Return the package named at the start of each table row, in order (duplicates kept)."""
    packages: list[str] = []
    for line in section.splitlines():
        match = TABLE_ROW_PACKAGE.match(line.strip())
        if match:
            packages.append(match.group(1))
    return packages


def rust_migration_ledger_doc_failures(ledger: dict, doc_body: str) -> list[str]:
    """Compare the compat-callers table and permanent-caller prose against the ledger.

    The table's row set must equal the ledger's `compat` packages (a package may
    own several rows), and every `permanent` package must be named in the
    section prose rather than the table.
    """
    by_status: dict[str, set[str]] = {}
    for entry in ledger.get("callers", []):
        by_status.setdefault(entry["status"], set()).add(entry["package"])
    compat = by_status.get("compat", set())
    permanent = by_status.get("permanent", set())

    section = markdown_section(doc_body, RUST_MIGRATION_DOC_HEADING)
    if section is None:
        return [f"{RUST_MIGRATION_DOC}: missing section {RUST_MIGRATION_DOC_HEADING!r}"]

    failures: list[str] = []
    rows = set(table_row_packages(section))
    for package in sorted(compat - rows):
        failures.append(
            f"{RUST_MIGRATION_DOC}: ledger lists {package} as 'compat' but the "
            "compatibility callers table has no row for it"
        )
    for package in sorted(rows - compat):
        status = next((s for s, pkgs in by_status.items() if package in pkgs), None)
        reason = f"ledger status is {status!r}" if status else "it is not in the ledger"
        failures.append(
            f"{RUST_MIGRATION_DOC}: compatibility callers table lists {package} but {reason}"
        )

    prose = "\n".join(line for line in section.splitlines() if not line.strip().startswith("|"))
    for package in sorted(permanent):
        if f"`{package}`" not in prose:
            failures.append(
                f"{RUST_MIGRATION_DOC}: ledger lists {package} as 'permanent' but the "
                "compatibility callers section prose does not name it"
            )
    for package in sorted(permanent & rows):
        failures.append(
            f"{RUST_MIGRATION_DOC}: {package} is 'permanent' in the ledger and must not "
            "appear as a compatibility callers table row"
        )
    return failures


def check_rust_migration_ledger_doc() -> list[str]:
    ledger = json.loads(read(RUST_MIGRATION_LEDGER))
    return rust_migration_ledger_doc_failures(ledger, read(RUST_MIGRATION_DOC))


def main() -> int:
    failures = []
    failures.extend(check_forbidden_markers())
    failures.extend(check_findings_catalog_reference())
    failures.extend(check_config_default_docs())
    failures.extend(check_rust_migration_ledger_doc())
    if failures:
        print("docs drift check failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print("docs drift check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
