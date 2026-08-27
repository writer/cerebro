#!/usr/bin/env python3
"""Verify the Rust migration ledger against the code.

docs/engineering/rust-migration-ledger.json tracks every package that
directly references the retained raw-Cypher compatibility surface
(`ports.RawCypherQueryStore` / `ExecuteReadCypher`). This check keeps the
ledger honest in both directions:

- a `compat` or `permanent` entry whose package no longer references the
  surface is stale (the migration landed; record it), and
- a package that references the surface without a ledger entry is a new
  legacy caller sneaking in unledgered.

It also prints the migrated/compat counts so migration progress is visible
in CI output without any tenant or environment data.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "docs" / "engineering" / "rust-migration-ledger.json"
SCAN_ROOTS = ("internal", "cmd", "apps", "sources")
MARKERS = ("RawCypherQueryStore", "ExecuteReadCypher")


def referencing_packages(root: Path) -> set[str]:
    packages: set[str] = set()
    for scan_root in SCAN_ROOTS:
        base = root / scan_root
        if not base.is_dir():
            continue
        for path in base.rglob("*.go"):
            if "node_modules" in path.parts:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            if any(marker in text for marker in MARKERS):
                packages.add(str(path.parent.relative_to(root)))
    return packages


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT, help="Repo root to check.")
    args = parser.parse_args()
    root = args.root.resolve()

    ledger = json.loads((root / "docs" / "engineering" / "rust-migration-ledger.json").read_text(encoding="utf-8"))
    infrastructure = {entry["package"] for entry in ledger.get("infrastructure", [])}
    callers = {entry["package"]: entry["status"] for entry in ledger.get("callers", [])}
    actual = referencing_packages(root)

    problems: list[str] = []

    overlap = infrastructure & set(callers)
    if overlap:
        problems.append(f"packages listed as both infrastructure and caller: {sorted(overlap)}")

    def covered_by(package_dir: str, entry: str) -> bool:
        return package_dir == entry or package_dir.startswith(entry + "/")

    for package, status in sorted(callers.items()):
        references = any(covered_by(pkg, package) for pkg in actual)
        if status in ("compat", "permanent") and not references:
            problems.append(
                f"{package}: ledger says '{status}' but the package no longer references the "
                "compatibility surface — record the migration (status 'migrated')"
            )
        elif status == "migrated" and references:
            problems.append(
                f"{package}: ledger says 'migrated' but the package still references the "
                "compatibility surface"
            )
        elif status not in ("compat", "permanent", "migrated"):
            problems.append(f"{package}: unknown status '{status}'")

    entries = infrastructure | set(callers)
    unledgered = {
        pkg for pkg in actual if not any(covered_by(pkg, entry) for entry in entries)
    }
    for package in sorted(unledgered):
        problems.append(
            f"{package}: references the raw-Cypher compatibility surface without a ledger entry — "
            "add it to docs/engineering/rust-migration-ledger.json (new legacy callers need an "
            "explicit, reviewed reason to exist)"
        )

    if problems:
        print("rust-migration-ledger-check: ledger and code disagree", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1

    statuses = list(callers.values())
    print(
        "rust-migration-ledger-check: ok — "
        f"{statuses.count('migrated')} migrated, "
        f"{statuses.count('compat')} compat, "
        f"{statuses.count('permanent')} permanent, "
        f"{len(infrastructure)} infrastructure"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
