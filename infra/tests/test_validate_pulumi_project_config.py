from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.validate_pulumi_project_config import validate_project


class ValidatePulumiProjectConfigTest(unittest.TestCase):
    def _project(self, content: str) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "Pulumi.yaml"
        path.write_text(content, encoding="utf-8")
        return path

    def test_repository_project_configs_are_valid(self) -> None:
        root = Path(__file__).resolve().parents[1]
        for project_file in sorted(root.glob("*/Pulumi.yaml")):
            with self.subTest(project_file=project_file):
                self.assertEqual([], validate_project(project_file))

    def test_rejects_unsupported_number_type(self) -> None:
        path = self._project(
            """\
name: demo
runtime: python
config:
  demo:sampleRate:
    type: number
    default: 1
"""
        )

        findings = validate_project(path)

        self.assertEqual(len(findings), 1)
        self.assertIn("unsupported config type 'number'", findings[0].message)

    def test_rejects_default_that_does_not_match_declared_type(self) -> None:
        path = self._project(
            """\
name: demo
runtime: python
config:
  demo:sampleRate:
    type: string
    default: 1
"""
        )

        findings = validate_project(path)

        self.assertEqual(len(findings), 1)
        self.assertIn("default value must match declared type 'string'", findings[0].message)

    def test_accepts_string_encoded_fractional_sample_rate(self) -> None:
        path = self._project(
            """\
name: demo
runtime: python
config:
  demo:sampleRate:
    type: string
    default: "0.25"
"""
        )

        self.assertEqual([], validate_project(path))


if __name__ == "__main__":
    unittest.main()
