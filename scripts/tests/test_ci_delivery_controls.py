import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
EPHEMERAL_WORKFLOW = ROOT / ".github" / "workflows" / "ephemeral-cerebro.yml"
PRE_PUSH_HOOK = ROOT / ".githooks" / "pre-push"


class CIDeliveryControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ephemeral = EPHEMERAL_WORKFLOW.read_text(encoding="utf-8")
        cls.pre_push = PRE_PUSH_HOOK.read_text(encoding="utf-8")

    def test_ephemeral_workflow_filters_pull_requests_to_runtime_inputs(self):
        pull_request = self.ephemeral.split("  pull_request:\n", 1)[1].split(
            "  workflow_dispatch:\n",
            1,
        )[0]
        self.assertIn("    paths:\n", pull_request)
        for runtime_path in (
            "      - Dockerfile\n",
            "      - Dockerfile.rust\n",
            "      - cmd/**\n",
            "      - crates/**\n",
            "      - internal/**\n",
            "      - proto/**\n",
            "      - sources/**\n",
        ):
            with self.subTest(runtime_path=runtime_path):
                self.assertIn(runtime_path, pull_request)
        self.assertNotIn("apps/web/**", pull_request)
        self.assertNotIn("docs/**", pull_request)

    def test_ephemeral_workflow_cancels_only_superseded_pull_requests(self):
        self.assertIn(
            "cancel-in-progress: ${{ github.event_name == 'pull_request' }}",
            self.ephemeral,
        )

    def test_pre_push_defaults_to_changed_checks_and_keeps_full_verify_opt_in(self):
        self.assertIn('CEREBRO_PRE_PUSH_FULL_VERIFY:-', self.pre_push)
        self.assertEqual(self.pre_push.count("make changed-check"), 1)
        self.assertEqual(self.pre_push.count("make verify"), 1)
        self.assertLess(
            self.pre_push.index("CEREBRO_PRE_PUSH_FULL_VERIFY"),
            self.pre_push.index("make verify"),
        )


if __name__ == "__main__":
    unittest.main()
