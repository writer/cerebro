#!/usr/bin/env python3
"""Validate inherited Rust workspace dependency and lint policy."""

from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path
from typing import Any


REQUIRED_RUST_LINTS = {
    "unsafe_code": "deny",
    "unsafe_op_in_unsafe_fn": "deny",
}
REQUIRED_CLIPPY_LINTS = {"undocumented_unsafe_blocks": "deny"}
DEPENDENCY_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")
ALLOWED_UNSAFE_FILES = {
    "internal/graphagent/staticvalidator/src/wasm_abi.rs",
    "internal/mitre/evaluator/src/wasm_abi.rs",
    "internal/sourcecoverage/evaluator/src/wasm_abi.rs",
    "internal/sourceprojection/panopticonresources/src/wasm_abi.rs",
    "internal/wasmguest/src/lib.rs",
}


def load_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as manifest:
        return tomllib.load(manifest)


def dependency_tables(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    tables = [manifest.get(name, {}) for name in DEPENDENCY_TABLES]
    for target in manifest.get("target", {}).values():
        tables.extend(target.get(name, {}) for name in DEPENDENCY_TABLES)
    return tables


def validate_workspace(root: Path) -> list[str]:
    root = root.resolve()
    root_manifest = load_toml(root / "Cargo.toml")
    workspace = root_manifest.get("workspace", {})
    errors: list[str] = []

    workspace_lints = workspace.get("lints", {})
    for lint, level in REQUIRED_RUST_LINTS.items():
        if workspace_lints.get("rust", {}).get(lint) != level:
            errors.append(f"Cargo.toml: workspace rust lint {lint} must be {level}")
    for lint, level in REQUIRED_CLIPPY_LINTS.items():
        if workspace_lints.get("clippy", {}).get(lint) != level:
            errors.append(f"Cargo.toml: workspace Clippy lint {lint} must be {level}")

    workspace_dependencies = workspace.get("dependencies", {})
    if not workspace_dependencies:
        errors.append("Cargo.toml: workspace.dependencies must not be empty")

    for member in workspace.get("members", []):
        manifest_path = root / member / "Cargo.toml"
        relative_manifest = manifest_path.relative_to(root)
        if not manifest_path.is_file():
            errors.append(f"{relative_manifest}: workspace member manifest is missing")
            continue
        manifest = load_toml(manifest_path)
        if manifest.get("lints") != {"workspace": True}:
            errors.append(f"{relative_manifest}: [lints] must set workspace = true")

        for dependencies in dependency_tables(manifest):
            for name, specification in dependencies.items():
                if name not in workspace_dependencies:
                    errors.append(
                        f"{relative_manifest}: dependency {name} must be declared in [workspace.dependencies]"
                    )
                    continue
                if not isinstance(specification, dict) or specification.get("workspace") is not True:
                    errors.append(f"{relative_manifest}: dependency {name} must inherit with workspace = true")
                    continue
                forbidden = {"version", "path", "git", "branch", "tag", "rev"}.intersection(specification)
                if forbidden:
                    fields = ", ".join(sorted(forbidden))
                    errors.append(
                        f"{relative_manifest}: dependency {name} overrides centralized fields: {fields}"
                    )

        for source_path in (root / member).rglob("*.rs"):
            source = source_path.read_text(encoding="utf-8")
            relative_source = source_path.relative_to(root).as_posix()
            if "allow(unsafe_code)" in source and relative_source not in ALLOWED_UNSAFE_FILES:
                errors.append(f"{relative_source}: unsafe_code allow is outside the audited ABI boundary")
            if "unsafe {" in source and relative_source != "internal/wasmguest/src/lib.rs":
                errors.append(f"{relative_source}: unsafe block must be isolated in internal/wasmguest")

    return errors


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    errors = validate_workspace(args.repo)
    if errors:
        for error in errors:
            print(f"rust-workspace-policy: {error}", file=sys.stderr)
        return 1
    print("rust-workspace-policy: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
