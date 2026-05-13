from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.set_image_tag import set_image_tag


class SetImageTagTest(unittest.TestCase):
    def test_updates_image_tag_in_place(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "Pulumi.go-prod.yaml"
            path.write_text("config:\n  cerebro:imageTag: v2.1.28\n", encoding="utf-8")

            changed = set_image_tag(path, "v2.1.29")

            self.assertTrue(changed)
            self.assertEqual(path.read_text(encoding="utf-8"), "config:\n  cerebro:imageTag: v2.1.29\n")

    def test_current_image_tag_is_noop(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "Pulumi.go-prod.yaml"
            path.write_text("config:\n  cerebro:imageTag: v2.1.29\n", encoding="utf-8")

            self.assertFalse(set_image_tag(path, "v2.1.29"))

    def test_rejects_non_semver_tag(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "Pulumi.go-prod.yaml"
            path.write_text("config:\n  cerebro:imageTag: v2.1.29\n", encoding="utf-8")

            with self.assertRaises(ValueError):
                set_image_tag(path, "latest")


if __name__ == "__main__":
    unittest.main()
