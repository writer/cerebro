#!/usr/bin/env python3

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts import sdk_dependency_audit


class SDKDependencyAuditTest(unittest.TestCase):
    def test_fallback_project_dependencies_reads_project_array(self) -> None:
        pyproject = """
[build-system]
requires = ["setuptools"]

[project]
name = "example"
dependencies = [
  "protobuf>=5.29.5,<8",
  "requests>=2.31",
]

[tool.example]
dependencies = [
  "ignored",
]
"""
        self.assertEqual(
            sdk_dependency_audit.fallback_project_dependencies(pyproject),
            ["protobuf>=5.29.5,<8", "requests>=2.31"],
        )

    def test_python_requirements_uses_fallback_without_tomllib(self) -> None:
        original_tomllib = sdk_dependency_audit.tomllib
        try:
            sdk_dependency_audit.tomllib = None
            with tempfile.TemporaryDirectory() as tmpdir:
                pyproject = Path(tmpdir) / "pyproject.toml"
                pyproject.write_text(
                    """
[project]
dependencies = [
  "protobuf>=5.29.5,<8",
]
""",
                    encoding="utf-8",
                )
                self.assertEqual(
                    sdk_dependency_audit.python_requirements_from_pyproject(pyproject),
                    ["protobuf>=5.29.5,<8"],
                )
        finally:
            sdk_dependency_audit.tomllib = original_tomllib


if __name__ == "__main__":
    unittest.main()
