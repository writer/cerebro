from __future__ import annotations

from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
DROID_REVIEW = REPO_ROOT / ".github" / "workflows" / "droid-review.yml"
LEGACY_DROID_REVIEW = REPO_ROOT / ".github" / "workflows" / "droid-code-review.yml"
MAKEFILE = REPO_ROOT / "Makefile"


class DroidReviewWorkflowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = DROID_REVIEW.read_text(encoding="utf-8")
        cls.makefile = MAKEFILE.read_text(encoding="utf-8")

    def test_full_review_workflow_is_present(self) -> None:
        self.assertIn("name: Droid Auto Review", self.workflow)
        self.assertIn("droid-review-preflight:", self.workflow)
        self.assertIn("Run Droid SAST context", self.workflow)
        self.assertIn("Run Droid CI context", self.workflow)
        self.assertIn("Run Droid feedback context", self.workflow)
        self.assertIn("Publish consolidated Droid context", self.workflow)
        self.assertIn("Factory-AI/droid-action@", self.workflow)

    def test_review_workflow_is_same_repo_and_non_draft_guarded(self) -> None:
        self.assertIn("github.event.pull_request.draft == false", self.workflow)
        self.assertIn("github.event.pull_request.head.repo.full_name == github.repository", self.workflow)
        self.assertIn("github.event.pull_request.user.login != 'dependabot[bot]'", self.workflow)
        self.assertIn("github.event.pull_request.user.login != 'writer-cerebro-deploy[bot]'", self.workflow)
        self.assertIn("DROID_REVIEW_ACTOR: ${{ github.event.pull_request.user.login }}", self.workflow)

    def test_context_runs_before_droid_action(self) -> None:
        self.assertLess(self.workflow.index("droid-review-preflight:"), self.workflow.index("droid-review:"))
        self.assertLess(self.workflow.index("Publish consolidated Droid context"), self.workflow.index("Run Droid Auto Review"))
        self.assertIn("needs: droid-review-preflight", self.workflow)

    def test_internal_secret_flow_is_preserved(self) -> None:
        self.assertIn("Infisical/secrets-action@", self.workflow)
        self.assertIn("INFISICAL_REPO_IDENTITY_UUID", self.workflow)
        self.assertIn("INFISICAL_REPO_PROJECT_SLUG", self.workflow)
        self.assertIn("Resolve Factory API key", self.workflow)
        self.assertIn("steps.factory_key.outputs.factory_api_key", self.workflow)

    def test_legacy_code_review_workflow_removed(self) -> None:
        self.assertFalse(LEGACY_DROID_REVIEW.exists())

    def test_makefile_exposes_review_targets(self) -> None:
        for target in (
            "droid-review-preflight:",
            "droid-review-sast:",
            "droid-ci-context:",
            "droid-feedback:",
            "droid-review-context:",
        ):
            self.assertIn(target, self.makefile)


if __name__ == "__main__":
    unittest.main()
