from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
CUT_RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "cut-release.yml"


class ReleaseWorkflowSerializationTest(unittest.TestCase):
    def test_release_publication_is_serialized_across_tags(self) -> None:
        workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("group: stable-release-publication", workflow)
        self.assertIn("cancel-in-progress: false", workflow)
        self.assertNotIn("group: release-${{ inputs.release_tag }}", workflow)

    def test_release_tag_reservation_is_serialized_across_triggers(self) -> None:
        workflow = CUT_RELEASE_WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("group: stable-release-tag-reservation", workflow)
        self.assertIn("cancel-in-progress: false", workflow)
        self.assertNotIn("group: cut-release-${{", workflow)


if __name__ == "__main__":
    unittest.main()
