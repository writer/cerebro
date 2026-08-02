from pathlib import Path
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DROID_WORKFLOWS = (
    REPOSITORY_ROOT / ".github/workflows/droid-create.yml",
    REPOSITORY_ROOT / ".github/workflows/droid.yml",
)
DETERMINISTIC_WORKFLOW = REPOSITORY_ROOT / ".github/workflows/deterministic-review.yml"


class DroidWorkflowTests(unittest.TestCase):
    def test_workflows_fall_back_when_infisical_bootstrap_is_incomplete(self):
        for workflow in DROID_WORKFLOWS:
            with self.subTest(workflow=workflow.name):
                contents = workflow.read_text()
                self.assertIn("id: infisical", contents)
                self.assertGreaterEqual(
                    contents.count("steps.infisical.outputs.configured == 'true'"),
                    2,
                )
                self.assertIn(
                    "REPOSITORY_FACTORY_API_KEY: ${{ secrets.FACTORY_API_KEY }}",
                    contents,
                )
                self.assertIn(
                    'echo "FACTORY_API_KEY=${FACTORY_API_KEY}" >> "$GITHUB_ENV"',
                    contents,
                )

    def test_automatic_review_is_deterministic_and_read_only(self):
        contents = DETERMINISTIC_WORKFLOW.read_text()
        self.assertIn("name: Deterministic Review", contents)
        self.assertIn("contents: read", contents)
        self.assertIn("make deterministic-review", contents)
        self.assertIn("git merge-base --is-ancestor", contents)
        for forbidden in (
            "Factory-AI/droid-action",
            "FACTORY_API_KEY",
            "secrets.",
            "pull-requests: write",
            "issues: write",
            "id-token: write",
        ):
            self.assertNotIn(forbidden, contents)


if __name__ == "__main__":
    unittest.main()
