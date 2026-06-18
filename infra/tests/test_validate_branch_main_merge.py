from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts import validate_branch_main_merge


class ValidateBranchMainMergeTest(unittest.TestCase):
    def test_changed_infra_paths_filters_non_infra_files(self) -> None:
        with patch.object(
            validate_branch_main_merge,
            "_run",
            return_value=SimpleNamespace(stdout="README.md\ninfra/aws/__main__.py\ninfra/tests/test_stack.py\n"),
        ):
            paths = validate_branch_main_merge._changed_infra_paths(Path("/repo"), "origin/main", "HEAD")

        self.assertEqual(paths, ["infra/aws/__main__.py", "infra/tests/test_stack.py"])

    def test_validate_skips_when_branch_has_no_infra_changes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(validate_branch_main_merge, "_changed_infra_paths", return_value=[]):
                with patch.object(validate_branch_main_merge, "_run_validators") as run_validators:
                    result = validate_branch_main_merge.validate_branch_main_merge(
                        Path(directory),
                        "origin/main",
                        "HEAD",
                        fetch=False,
                        remote="origin",
                        remote_branch="main",
                    )

        self.assertEqual(result, 0)
        run_validators.assert_not_called()

    def test_validation_commands_include_static_checks_and_tests(self) -> None:
        commands = validate_branch_main_merge.VALIDATION_COMMANDS

        self.assertIn(("uv", "run", "python", "scripts/validate_pulumi_project_config.py"), commands)
        self.assertIn(("uv", "run", "python", "scripts/validate_stack_config.py"), commands)
        self.assertIn(("uv", "run", "python", "-m", "unittest", "discover", "-s", "tests"), commands)


if __name__ == "__main__":
    unittest.main()
