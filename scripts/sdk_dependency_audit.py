#!/usr/bin/env python3
"""Audit SDK dependency manifests without installing the SDK packages globally."""

from __future__ import annotations

import pathlib
import subprocess
import sys
import tempfile
import tomllib


ROOT = pathlib.Path(__file__).resolve().parents[1]


def run(command: list[str], cwd: pathlib.Path | None = None) -> int:
    print("+", " ".join(command))
    return subprocess.run(command, cwd=str(cwd) if cwd else None, check=False).returncode


def python_requirements_from_pyproject(pyproject: pathlib.Path) -> list[str]:
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    return list(data.get("project", {}).get("dependencies", []) or [])


def audit_python_sdk() -> int:
    dependencies = python_requirements_from_pyproject(ROOT / "sdk" / "python" / "pyproject.toml")
    if not dependencies:
        print("sdk/python has no project dependencies to audit")
        return 0
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as requirements:
        for dependency in dependencies:
            requirements.write(dependency + "\n")
        requirements_path = pathlib.Path(requirements.name)
    try:
        return run(["python3", "-m", "pip_audit", "--requirement", str(requirements_path)])
    finally:
        requirements_path.unlink(missing_ok=True)


def main() -> int:
    failures = 0
    failures += run(["npm", "audit", "--audit-level=high"], ROOT / "sdk" / "typescript")
    failures += audit_python_sdk()
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
