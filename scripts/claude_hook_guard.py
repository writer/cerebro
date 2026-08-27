#!/usr/bin/env python3
"""Claude Code tool hooks for this repo.

`pre` mode (PreToolUse on Edit/Write): block hand-edits to generated or
contract-governed outputs and point the agent at the owning regeneration
target instead. Exit code 2 blocks the tool call; the stderr message is
fed back to the agent.

`post` mode (PostToolUse on Edit/Write): best-effort format of the edited
file with the repo's canonical formatter (gofmt for Go, rustfmt with the
workspace edition for Rust). Never fails the turn.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

RUST_EDITION = "2024"

# Repo-relative generated roots. Regeneration runs through make, which
# writes files directly, so blocking agent Edit/Write here is safe.
GENERATED_ROOTS = (
    "crates/cerebro-platform/src/generated",
    "sdk/typescript/src/generated",
    "sdk/go/cerebroapi/genproto",
    "gen",
)

GENERATED_SUFFIXES = ("_gen.go", ".pb.go")

BLOCK_MESSAGE = (
    "{rel} is a generated output; hand-edits are overwritten and fail CI. "
    "Change the generator input instead, then regenerate with the owning make "
    "target (see the 'Generated / contract-governed surfaces' section of "
    "CLAUDE.md): `make proto-generate` for protobuf-derived code, `make "
    "openapi-sync` for OpenAPI route metadata, or the focused `*-check`/"
    "`*-sync` target for the surface you changed. `make contracts-check` "
    "verifies the result."
)


def edited_path(payload: dict) -> Path | None:
    file_path = (payload.get("tool_input") or {}).get("file_path")
    if not file_path:
        return None
    return Path(file_path)


def repo_relative(path: Path) -> Path | None:
    try:
        return path.resolve().relative_to(ROOT)
    except ValueError:
        return None


def run_pre(payload: dict) -> int:
    path = edited_path(payload)
    rel = repo_relative(path) if path else None
    if rel is None:
        return 0
    rel_str = str(rel)
    in_generated_root = any(
        rel_str == root or rel_str.startswith(root + "/") for root in GENERATED_ROOTS
    )
    if in_generated_root or rel_str.endswith(GENERATED_SUFFIXES):
        print(BLOCK_MESSAGE.format(rel=rel_str), file=sys.stderr)
        return 2
    return 0


def run_post(payload: dict) -> int:
    path = edited_path(payload)
    rel = repo_relative(path) if path else None
    if rel is None or path is None or not path.is_file():
        return 0
    if path.suffix == ".go" and shutil.which("gofmt"):
        subprocess.run(["gofmt", "-w", str(path)], check=False, capture_output=True)
    elif path.suffix == ".rs" and shutil.which("rustfmt"):
        subprocess.run(
            ["rustfmt", "--edition", RUST_EDITION, str(path)],
            check=False,
            capture_output=True,
        )
    return 0


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return 0
    if mode == "pre":
        return run_pre(payload)
    if mode == "post":
        return run_post(payload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
