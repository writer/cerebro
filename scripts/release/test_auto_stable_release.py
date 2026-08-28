from __future__ import annotations

import tempfile
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from auto_stable_release import next_patch_tag, render_notes


class AutoStableReleaseTest(unittest.TestCase):
    def test_next_patch_ignores_drafts_prereleases_and_non_semver_tags(self) -> None:
        releases = [
            {"tag_name": "v2.1.769", "draft": False, "prerelease": False},
            {"tag_name": "v2.1.900", "draft": True, "prerelease": False},
            {"tag_name": "v3.0.0-rc.1", "draft": False, "prerelease": True},
            {"tag_name": "latest", "draft": False, "prerelease": False},
        ]

        self.assertEqual(next_patch_tag(releases), ("v2.1.770", "v2.1.769"))

    def test_empty_inventory_starts_at_v0_1_0(self) -> None:
        self.assertEqual(next_patch_tag([]), ("v0.1.0", None))

    def test_notes_bind_candidate_smoke_and_portable_artifacts(self) -> None:
        sha = "0123456789abcdef0123456789abcdef01234567"
        notes = render_notes(
            release_tag="v2.1.770",
            candidate_sha=sha,
            candidate_run_id="12345",
            smoke_url="https://github.com/writer/cerebro/actions/runs/67890",
            previous_tag="v2.1.769",
        )

        self.assertIn(sha, notes)
        self.assertIn("Candidate Build run `12345`", notes)
        self.assertIn("actions/runs/67890", notes)
        self.assertIn("Evidence mode: `machine_verified_portable`", notes)
        self.assertIn("TypeScript Slack companion archive", notes)
        self.assertNotIn("TODO", notes)
        self.assertNotIn("TBD", notes)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "notes.md"
            path.write_text(notes, encoding="utf-8")
            self.assertGreater(len(path.read_text(encoding="utf-8").split()), 40)

    def test_notes_reject_unbound_inputs(self) -> None:
        with self.assertRaisesRegex(ValueError, "full lowercase Git SHA"):
            render_notes(
                release_tag="v2.1.770",
                candidate_sha="main",
                candidate_run_id="12345",
                smoke_url="https://github.com/writer/cerebro/actions/runs/67890",
                previous_tag="v2.1.769",
            )


if __name__ == "__main__":
    unittest.main()
