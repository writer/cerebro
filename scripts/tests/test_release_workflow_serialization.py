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

    def test_candidate_web_images_use_native_architecture_runners(self) -> None:
        workflow = CUT_RELEASE_WORKFLOW.read_text(encoding="utf-8")
        web_image = workflow.split("  web-image:\n", 1)[1].split(
            "\n  web-manifest:", 1
        )[0]

        self.assertIn("runs-on: ${{ matrix.runner }}", web_image)
        self.assertIn("timeout-minutes: 30", web_image)
        self.assertIn("runner: ubuntu-24.04", web_image)
        self.assertIn("runner: ubuntu-24.04-arm", web_image)
        self.assertNotIn("docker/setup-qemu-action", web_image)


if __name__ == "__main__":
    unittest.main()
