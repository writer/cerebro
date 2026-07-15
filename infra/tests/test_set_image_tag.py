from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.set_image_tag import (
    ensure_image_tag_at_least,
    read_image_digest,
    read_image_tag,
    set_image_release,
    set_image_tag,
)


class SetImageTagTest(unittest.TestCase):
    def test_updates_image_tag_in_place(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "Pulumi.go-prod.yaml"
            path.write_text("config:\n  cerebro:imageTag: v2.1.28\n", encoding="utf-8")

            changed = set_image_tag(path, "v2.1.29")

            self.assertTrue(changed)
            self.assertEqual(
                path.read_text(encoding="utf-8"),
                "config:\n  cerebro:imageTag: v2.1.29\n",
            )

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

    def test_ensure_image_tag_at_least_updates_lower_tag(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "Pulumi.sec-dev.yaml"
            path.write_text("config:\n  cerebro:imageTag: v2.1.28\n", encoding="utf-8")

            changed = ensure_image_tag_at_least(path, "v2.1.29")

            self.assertTrue(changed)
            self.assertEqual(read_image_tag(path), "v2.1.29")

    def test_ensure_image_tag_at_least_does_not_downgrade(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "Pulumi.sec-dev.yaml"
            path.write_text("config:\n  cerebro:imageTag: v2.1.30\n", encoding="utf-8")

            changed = ensure_image_tag_at_least(path, "v2.1.29")

            self.assertFalse(changed)
            self.assertEqual(read_image_tag(path), "v2.1.30")

    def test_sets_tag_and_digest_as_one_release_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "Pulumi.sec-dev.yaml"
            path.write_text("config:\n  cerebro:imageTag: v2.1.28\n", encoding="utf-8")
            digest = f"sha256:{'a' * 64}"

            changed = set_image_release(path, "v2.1.29", digest)

            self.assertTrue(changed)
            self.assertEqual(read_image_tag(path), "v2.1.29")
            self.assertEqual(read_image_digest(path), digest)

    def test_updates_existing_digest_without_duplicating_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "Pulumi.sec-dev.yaml"
            path.write_text(
                f"config:\n  cerebro:imageTag: v2.1.29\n  cerebro:imageDigest: sha256:{'a' * 64}\n",
                encoding="utf-8",
            )

            changed = set_image_release(path, "v2.1.29", f"sha256:{'b' * 64}")

            text = path.read_text(encoding="utf-8")
            self.assertTrue(changed)
            self.assertEqual(text.count("cerebro:imageDigest:"), 1)
            self.assertIn(f"sha256:{'b' * 64}", text)


if __name__ == "__main__":
    unittest.main()
