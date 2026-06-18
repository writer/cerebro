#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


ALLOWED_CONFIG_TYPES = {"string", "integer", "boolean", "array", "object"}


@dataclass(frozen=True)
class Finding:
    path: Path
    key: str
    message: str

    def format(self) -> str:
        return f"{self.path}: {self.key}: {self.message}"


def _default_project_paths() -> list[Path]:
    infra_root = Path(__file__).resolve().parents[1]
    return sorted(infra_root.glob("*/Pulumi.yaml"))


def _default_matches_type(config_type: str, default: Any) -> bool:
    if default is None:
        return True
    if config_type == "string":
        return isinstance(default, str)
    if config_type == "integer":
        return isinstance(default, int) and not isinstance(default, bool)
    if config_type == "boolean":
        return isinstance(default, bool)
    if config_type == "array":
        return isinstance(default, list)
    if config_type == "object":
        return isinstance(default, dict)
    return False


def validate_project(path: Path) -> list[Finding]:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    config = loaded.get("config")
    if config is None:
        return []
    if not isinstance(config, dict):
        return [Finding(path, "config", "Pulumi project config must be a mapping")]

    findings: list[Finding] = []
    for key, declaration in config.items():
        key_text = str(key)
        if not isinstance(declaration, dict) or "type" not in declaration:
            continue

        config_type = declaration.get("type")
        if not isinstance(config_type, str):
            findings.append(Finding(path, key_text, "config type must be a string"))
            continue
        if config_type not in ALLOWED_CONFIG_TYPES:
            allowed = ", ".join(sorted(ALLOWED_CONFIG_TYPES))
            findings.append(
                Finding(path, key_text, f"unsupported config type {config_type!r}; allowed types: {allowed}")
            )
            continue

        if "default" in declaration and not _default_matches_type(config_type, declaration.get("default")):
            findings.append(Finding(path, key_text, f"default value must match declared type {config_type!r}"))

    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate Pulumi project config declarations before Pulumi CLI commands run."
    )
    parser.add_argument("project_files", nargs="*", type=Path, help="Pulumi.yaml project files to validate")
    args = parser.parse_args(argv)

    project_files = args.project_files or _default_project_paths()
    findings: list[Finding] = []
    for project_file in project_files:
        findings.extend(validate_project(project_file))

    for finding in findings:
        print(f"ERROR: {finding.format()}", file=sys.stderr)
    if findings:
        return 1

    print(f"Validated {len(project_files)} Pulumi project file(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
