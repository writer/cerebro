#!/usr/bin/env python3
"""Validate README facts that tend to drift."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
SOURCE_CATALOG = ROOT / "docs" / "SOURCES.md"
CONTROL_INDEX_DOC_FLAGS = {"init-extension", "extension", "profile", "output", "write", "check"}
CONTROL_INDEX_README_FLAGS = {"init-extension", "extension", "profile", "output", "write"}


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def fail(message: str) -> None:
    raise SystemExit(f"readme-check: {message}")


def go_toolchain() -> str:
    match = re.search(r"^toolchain\s+(go[0-9.]+)\s*$", read(ROOT / "go.mod"), re.MULTILINE)
    if not match:
        fail("go.mod does not declare a toolchain")
    return match.group(1)


def builtin_source_ids() -> list[str]:
    registry = read(ROOT / "internal" / "sourceregistry" / "registry.go")
    return sorted(set(re.findall(r'name:\s+"([^"]+)"', registry)))


def documented_source_ids() -> list[str]:
    source_catalog = read(SOURCE_CATALOG)
    match = re.search(r"# Built-In Sources\n\n.*?(\| Source ID \|.*?)(?:\n## |\Z)", source_catalog, re.S)
    if not match:
        fail("docs/SOURCES.md is missing the Built-In Sources table")
    return sorted(set(re.findall(r"^\| `([^`]+)` \|", match.group(1), re.MULTILINE)))


def usage_commands() -> list[str]:
    main_go = read(ROOT / "cmd" / "cerebro" / "main.go")
    match = re.search(r"\[([a-z|-]+)\]", main_go)
    if not match:
        fail("could not find top-level CLI usage in cmd/cerebro/main.go")
    return sorted(match.group(1).split("|"))


def readme_commands(readme: str) -> list[str]:
    match = re.search(r"Top-level commands are (.+?)\.", readme)
    if not match:
        fail("README is missing top-level command sentence")
    return sorted(re.findall(r"`([^`]+)`", match.group(1)))


def controlindex_flags() -> set[str]:
    body = read(ROOT / "tools" / "controlindex" / "main.go")
    flags = set(re.findall(r'flag\.(?:String|Bool)\("([^"]+)"', body))
    flags.update(re.findall(r'flag\.Var\([^,\n]+,\s*"([^"]+)"', body))
    return flags


def require_controlindex_docs(readme: str) -> None:
    flags = controlindex_flags()
    missing_code_flags = sorted(CONTROL_INDEX_DOC_FLAGS - flags)
    if missing_code_flags:
        fail("controlindex lost README-tracked flags: " + ", ".join(f"--{flag}" for flag in missing_code_flags))

    compliance_docs = read(ROOT / "docs" / "COMPLIANCE_CONTROLS.md")
    missing_doc_flags = sorted(f"--{flag}" for flag in CONTROL_INDEX_DOC_FLAGS if f"--{flag}" not in compliance_docs)
    if missing_doc_flags:
        fail("COMPLIANCE_CONTROLS.md missing controlindex flags: " + ", ".join(missing_doc_flags))

    missing_readme_flags = sorted(f"--{flag}" for flag in CONTROL_INDEX_README_FLAGS if f"--{flag}" not in readme)
    if missing_readme_flags:
        fail("README missing controlindex workflow flags: " + ", ".join(missing_readme_flags))


def repository_env_vars() -> set[str]:
    values: set[str] = set()
    for path in [*ROOT.glob("internal/config/*.go"), ROOT / ".env.example"]:
        if not path.exists():
            continue
        values.update(re.findall(r"CEREBRO_[A-Z0-9_]+", read(path)))
    return values


def exact_readme_env_vars(readme: str) -> set[str]:
    values = set(re.findall(r"`(CEREBRO_[A-Z0-9_]+)`", readme))
    # Wildcard families such as CEREBRO_MCP_OAUTH_* are intentionally prose.
    return {value for value in values if not value.endswith("_")}


def require_contains(readme: str, snippets: list[str]) -> None:
    missing = [snippet for snippet in snippets if snippet not in readme]
    if missing:
        fail("README missing required text: " + ", ".join(missing))


def main() -> int:
    readme = read(README)

    toolchain = go_toolchain()
    if toolchain not in readme:
        fail(f"README does not mention current Go toolchain {toolchain}")

    sources = builtin_source_ids()
    documented_sources = documented_source_ids()
    if documented_sources != sources:
        fail(f"built-in source table drift: docs/SOURCES.md={documented_sources} registry={sources}")

    commands = usage_commands()
    documented_commands = readme_commands(readme)
    if documented_commands != commands:
        fail(f"top-level command drift: README={documented_commands} CLI={commands}")

    env_vars = repository_env_vars()
    documented_env_vars = exact_readme_env_vars(readme)
    missing_env_vars = sorted(documented_env_vars - env_vars)
    if missing_env_vars:
        fail("README documents env vars not found in config sources: " + ", ".join(missing_env_vars))

    require_controlindex_docs(readme)

    require_contains(
        readme,
        [
            "This public repository is authoritative for runtime behavior",
            "Environment-specific deployment details",
            "cerebro-runtime-contract.json",
            ".env.example",
            "docs/CONFIG_ENV_VARS.md",
            "docs/GETTING_STARTED.md",
            "sdk/python/README.md",
            "sdk/typescript/README.md",
            "docs/MCP_DROID_SETUP.md",
            "docs/ENDPOINT_SECURITY_PLATFORM_INTEGRATION.md",
            "docs/COMPLIANCE_CONTROLS.md",
            "make control-index-check",
            "make policy-rule-check",
            "make detection-catalog-check",
            "Control extension packs",
            "make readme-check",
        ],
    )

    print("readme-check: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
