#!/usr/bin/env python3
"""Verify agent instruction files against the repo they describe.

Agent instruction files (CLAUDE.md, AGENTS.md, and agent skills) rot
silently: a renamed make target or moved doc keeps being recommended to
every agent session long after it stops existing. This check fails when an
agent instruction file references a make target that the Makefile does not
define or links to a repo file that does not exist.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

INSTRUCTION_GLOBS = (
    "CLAUDE.md",
    "AGENTS.md",
    ".claude/skills/*/SKILL.md",
    ".factory/skills/*/SKILL.md",
)

# `make target` or `make target-a target-b` inside inline code spans.
MAKE_REF_RE = re.compile(r"`make ([a-z0-9][a-z0-9 _.-]*?)`")
MAKE_TOKEN_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]*$")
# Markdown links; external schemes and pure anchors are skipped later.
LINK_RE = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
MAKEFILE_TARGET_RE = re.compile(r"^([A-Za-z0-9_.-]+):", re.MULTILINE)


def makefile_targets(root: Path) -> set[str]:
    return set(MAKEFILE_TARGET_RE.findall((root / "Makefile").read_text(encoding="utf-8")))


def instruction_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for pattern in INSTRUCTION_GLOBS:
        files.extend(sorted(root.glob(pattern)))
    return [f for f in files if f.is_file()]


def check_file(path: Path, root: Path, targets: set[str]) -> list[str]:
    problems: list[str] = []
    text = path.read_text(encoding="utf-8")
    rel = path.relative_to(root)

    for match in MAKE_REF_RE.finditer(text):
        for token in match.group(1).split():
            if not MAKE_TOKEN_RE.match(token):
                continue  # flags, VAR=..., placeholders
            if token not in targets:
                problems.append(f"{rel}: references undefined make target `{token}`")

    for match in LINK_RE.finditer(text):
        target = match.group(1)
        if target.startswith(("http://", "https://", "mailto:", "#")):
            continue
        candidate = target.split("#", 1)[0]
        if not candidate:
            continue
        resolved = (path.parent / candidate) if not candidate.startswith("/") else (root / candidate.lstrip("/"))
        if not resolved.exists() and not (root / candidate).exists():
            problems.append(f"{rel}: links to missing file `{candidate}`")

    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT, help="Repo root to check.")
    args = parser.parse_args()
    root = args.root.resolve()

    targets = makefile_targets(root)
    files = instruction_files(root)
    problems: list[str] = []
    for path in files:
        problems.extend(check_file(path, root, targets))

    if problems:
        print("agent-docs-check: stale agent instructions detected", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1
    print(f"agent-docs-check: {len(files)} instruction file(s) consistent with the repo")
    return 0


if __name__ == "__main__":
    sys.exit(main())
