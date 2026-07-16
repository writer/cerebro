#!/usr/bin/env python3
"""Validate inherited Rust workspace dependency and lint policy."""

from __future__ import annotations

import argparse
import re
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
AUDITED_UNSAFE_POLICIES = {
    "internal/graphagent/staticvalidator/src/wasm_abi.rs": ("attribute",) * 3,
    "internal/mitre/evaluator/src/wasm_abi.rs": ("attribute",) * 3,
    "internal/sourcecoverage/evaluator/src/wasm_abi.rs": ("attribute",) * 3,
    "internal/sourceprojection/panopticonresources/src/wasm_abi.rs": ("attribute",) * 3,
    "internal/sourceruntime/eventadmission/src/wasm_abi.rs": ("attribute",) * 3,
    "internal/sourceruntime/recordkernel/src/wasm_abi.rs": ("attribute",) * 3,
    "internal/wasmguest/src/lib.rs": ("block", "block"),
}
SAFE_ONLY_CRATE_ROOTS = {
    "crates/control-kernel/src/lib.rs": "crates/control-kernel",
    "tools/graphactiongen/src/lib.rs": "tools/graphactiongen",
    "tools/graphactiongen/src/main.rs": "tools/graphactiongen",
}
RAW_STRING_START = r'(?:br|rb|cr|rc|r)(?P<hashes>#{0,255})"'
THIN_CRATE_ROOTS = {
    "internal/mitre/evaluator/src/lib.rs": ("mod evaluation;", "mod model;", "mod normalization;"),
    "internal/sourcecoverage/evaluator/src/lib.rs": ("mod evaluation;", "mod model;"),
    "internal/sourceprojection/panopticonresources/src/lib.rs": (
        "mod extraction;",
        "mod normalization;",
    ),
    "tools/graphactiongen/src/lib.rs": (
        "mod catalog;",
        "mod error;",
        "mod filesystem;",
        "mod render;",
    ),
}
PURE_RUST_MODULES = (
    "internal/mitre/evaluator/src/evaluation.rs",
    "internal/mitre/evaluator/src/normalization.rs",
    "internal/sourcecoverage/evaluator/src/evaluation.rs",
    "internal/sourceprojection/panopticonresources/src/extraction.rs",
    "internal/sourceprojection/panopticonresources/src/normalization.rs",
    "tools/graphactiongen/src/catalog.rs",
)
FILESYSTEM_MARKERS = ("std::fs", "std::path", "File::", "OpenOptions", "fs::")


def load_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as manifest:
        return tomllib.load(manifest)


def dependency_tables(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    tables = [manifest.get(name, {}) for name in DEPENDENCY_TABLES]
    for target in manifest.get("target", {}).values():
        tables.extend(target.get(name, {}) for name in DEPENDENCY_TABLES)
    return tables


def rust_tokens(source: str) -> list[str]:
    """Return Rust identifiers and punctuation, excluding comments and literals."""
    tokens: list[str] = []
    index = 0
    while index < len(source):
        if source.startswith("//", index):
            newline = source.find("\n", index + 2)
            index = len(source) if newline < 0 else newline + 1
            continue
        if source.startswith("/*", index):
            depth = 1
            index += 2
            while index < len(source) and depth:
                if source.startswith("/*", index):
                    depth += 1
                    index += 2
                elif source.startswith("*/", index):
                    depth -= 1
                    index += 2
                else:
                    index += 1
            continue

        raw_string = re.match(RAW_STRING_START, source[index:])
        if raw_string:
            terminator = '"' + raw_string.group("hashes")
            end = source.find(terminator, index + raw_string.end())
            index = len(source) if end < 0 else end + len(terminator)
            continue

        prefix_length = 0
        if source.startswith(('b"', 'c"'), index):
            prefix_length = 1
        if source[index + prefix_length : index + prefix_length + 1] == '"':
            index += prefix_length + 1
            while index < len(source):
                if source[index] == "\\":
                    index += 2
                elif source[index] == '"':
                    index += 1
                    break
                else:
                    index += 1
            continue

        if source[index] == "'" and index + 2 < len(source):
            cursor = index + 1
            if source[cursor] == "\\":
                cursor += 2
            else:
                cursor += 1
            if cursor < len(source) and source[cursor] == "'":
                index = cursor + 1
                continue

        if source[index].isalpha() or source[index] == "_":
            end = index + 1
            while end < len(source) and (source[end].isalnum() or source[end] == "_"):
                end += 1
            tokens.append(source[index:end])
            index = end
            continue
        if not source[index].isspace():
            tokens.append(source[index])
        index += 1
    return tokens


def unsafe_code_control_attributes(tokens: list[str]) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """Return allow/expect attributes that suppress unsafe_code."""
    controls: list[tuple[str, tuple[str, ...]]] = []
    index = 0
    while index < len(tokens):
        cursor = index
        if tokens[cursor : cursor + 1] != ["#"]:
            index += 1
            continue
        cursor += 1
        if tokens[cursor : cursor + 1] == ["!"]:
            cursor += 1
        if tokens[cursor : cursor + 1] != ["["]:
            index += 1
            continue
        cursor += 1
        if tokens[cursor : cursor + 1] not in (["allow"], ["expect"]):
            index += 1
            continue
        level = tokens[cursor]
        cursor += 1
        if tokens[cursor : cursor + 1] != ["("]:
            index += 1
            continue
        cursor += 1
        depth = 1
        attribute_tokens: list[str] = []
        while cursor < len(tokens) and depth:
            if tokens[cursor] == "(":
                depth += 1
            elif tokens[cursor] == ")":
                depth -= 1
            if depth:
                attribute_tokens.append(tokens[cursor])
            cursor += 1
        if "unsafe_code" in attribute_tokens:
            lints = tuple(token for token in attribute_tokens if token.isidentifier())
            controls.append((level, lints))
        index = cursor
    return tuple(controls)


def unsafe_token_kinds(tokens: list[str]) -> tuple[str, ...]:
    """Classify every Rust unsafe keyword by the syntax it introduces."""
    kinds: list[str] = []
    for index, token in enumerate(tokens):
        if token != "unsafe":
            continue
        previous = tokens[index - 2 : index]
        following = tokens[index + 1 : index + 2]
        if previous == ["#", "["] and following == ["("]:
            kinds.append("attribute")
        elif following == ["{"]:
            kinds.append("block")
        elif following and following[0] in {"extern", "fn", "impl", "trait"}:
            kinds.append(following[0])
        else:
            kinds.append("other")
    return tuple(kinds)


def validate_unsafe_source(relative_source: str, source: str) -> list[str]:
    """Validate one Rust source file against the exact audited unsafe boundary."""
    tokens = rust_tokens(source)
    controls = unsafe_code_control_attributes(tokens)
    unsafe_kinds = unsafe_token_kinds(tokens)
    expected_kinds = AUDITED_UNSAFE_POLICIES.get(relative_source)
    if expected_kinds is None:
        errors = []
        if controls:
            errors.append(
                f"{relative_source}: unsafe_code allow or expect is outside the audited ABI boundary"
            )
        if unsafe_kinds:
            forms = ", ".join(unsafe_kinds)
            errors.append(f"{relative_source}: unsafe syntax is outside the audited ABI boundary: {forms}")
        return errors
    if controls != (("allow", ("unsafe_code",)),):
        return [
            f"{relative_source}: audited unsafe module must contain exactly #![allow(unsafe_code)]"
        ]
    if unsafe_kinds != expected_kinds:
        actual = ", ".join(unsafe_kinds) or "none"
        expected = ", ".join(expected_kinds)
        return [
            f"{relative_source}: audited unsafe syntax changed: expected {expected}; found {actual}"
        ]
    return []


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
            errors.extend(validate_unsafe_source(relative_source, source))

    workspace_members = set(workspace.get("members", []))
    for relative_root, member in SAFE_ONLY_CRATE_ROOTS.items():
        if member not in workspace_members:
            continue
        root_path = root / relative_root
        if not root_path.is_file():
            errors.append(f"{relative_root}: safe-only crate root is missing")
            continue
        tokens = rust_tokens(root_path.read_text(encoding="utf-8"))
        required = ["#", "!", "[", "forbid", "(", "unsafe_code", ")", "]"]
        if tokens[: len(required)] != required:
            errors.append(f"{relative_root}: safe-only crate must forbid unsafe_code")

    workspace_members = set(workspace.get("members", []))
    for relative_root, required_modules in THIN_CRATE_ROOTS.items():
        member = relative_root.removesuffix("/src/lib.rs")
        if member not in workspace_members:
            continue
        root_path = root / relative_root
        if not root_path.is_file():
            errors.append(f"{relative_root}: crate root is missing")
            continue
        source = root_path.read_text(encoding="utf-8")
        if len(source.splitlines()) > 40:
            errors.append(f"{relative_root}: crate root must remain a thin module facade")
        for module in required_modules:
            if module not in source:
                errors.append(f"{relative_root}: required boundary {module} is missing")

    for relative_module in PURE_RUST_MODULES:
        module_path = root / relative_module
        if not module_path.is_file():
            continue
        source = module_path.read_text(encoding="utf-8")
        for marker in FILESYSTEM_MARKERS:
            if marker in source:
                errors.append(
                    f"{relative_module}: pure evaluation module must not access filesystem marker {marker}"
                )

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
