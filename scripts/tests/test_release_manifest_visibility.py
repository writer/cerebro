from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
CANDIDATE_WORKFLOW = ROOT / ".github" / "workflows" / "cut-release.yml"


class ReleaseManifestVisibilityTest(unittest.TestCase):
    def test_candidate_manifests_retry_registry_visibility(self) -> None:
        workflow = CANDIDATE_WORKFLOW.read_text(encoding="utf-8")

        self.assertEqual(workflow.count("for attempt in 1 2 3 4 5 6; do"), 2)
        self.assertEqual(
            workflow.count('if digest="$(docker buildx imagetools inspect'),
            2,
        )
        self.assertEqual(workflow.count('sleep "$((attempt * 2))"'), 2)
        self.assertIn("candidate manifest was not readable", workflow)
        self.assertIn("candidate web manifest was not readable", workflow)


if __name__ == "__main__":
    unittest.main()
