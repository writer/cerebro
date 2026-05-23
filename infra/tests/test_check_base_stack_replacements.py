from __future__ import annotations

import tempfile
import textwrap
import unittest
from pathlib import Path

from scripts import check_base_stack_replacements


class CheckBaseStackReplacementsTest(unittest.TestCase):
    def _check(self, source: str) -> list[str]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "test_validate_stack_config.py"
            path.write_text(textwrap.dedent(source))
            return check_base_stack_replacements.check_file(path)

    def test_allows_replace_anchor_present_in_base_stack(self) -> None:
        errors = self._check(
            '''
            BASE_STACK = """
            config:
              cerebro:apiMaxInstances: 2
            """

            def test_stack():
                return BASE_STACK.replace("  cerebro:apiMaxInstances: 2\\n", "  cerebro:apiMaxInstances: 1\\n")
            '''
        )

        self.assertEqual(errors, [])

    def test_rejects_replace_anchor_missing_from_base_stack(self) -> None:
        errors = self._check(
            '''
            BASE_STACK = """
            config:
              cerebro:apiMaxInstances: 2
            """

            def test_stack():
                return BASE_STACK.replace("  cerebro:apiMaxInstances: 1\\n", "  cerebro:apiMaxInstances: 2\\n")
            '''
        )

        self.assertEqual(len(errors), 1)
        self.assertIn("BASE_STACK.replace anchor is not present", errors[0])


if __name__ == "__main__":
    unittest.main()
