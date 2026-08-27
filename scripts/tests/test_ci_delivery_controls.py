import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
DETERMINISTIC_WORKFLOW = ROOT / ".github" / "workflows" / "deterministic-review.yml"
EPHEMERAL_WORKFLOW = ROOT / ".github" / "workflows" / "ephemeral-cerebro.yml"
PRE_PUSH_HOOK = ROOT / ".githooks" / "pre-push"
GO_SETUP = ROOT / ".github" / "actions" / "setup-go-cached" / "action.yml"
RUST_SETUP = ROOT / ".github" / "actions" / "setup-rust-cached" / "action.yml"
WORKFLOWS = ROOT / ".github" / "workflows"


class CIDeliveryControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ci = CI_WORKFLOW.read_text(encoding="utf-8")
        cls.deterministic = DETERMINISTIC_WORKFLOW.read_text(encoding="utf-8")
        cls.ephemeral = EPHEMERAL_WORKFLOW.read_text(encoding="utf-8")
        cls.pre_push = PRE_PUSH_HOOK.read_text(encoding="utf-8")
        cls.go_setup = GO_SETUP.read_text(encoding="utf-8")
        cls.rust_setup = RUST_SETUP.read_text(encoding="utf-8")
        cls.all_workflows = "\n".join(
            path.read_text(encoding="utf-8") for path in sorted(WORKFLOWS.glob("*.yml"))
        )

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

    def test_shared_actions_own_go_and_rust_cache_keys(self):
        self.assertIn("go-v3-${{ inputs.cache-scope }}", self.go_setup)
        self.assertIn("rust-v2-${{ inputs.cache-scope }}", self.rust_setup)
        self.assertGreaterEqual(self.ci.count("uses: ./.github/actions/setup-go-cached"), 7)
        self.assertGreaterEqual(self.ci.count("uses: ./.github/actions/setup-rust-cached"), 3)
        self.assertNotIn("name: Cache Go build data", self.ci)

    def test_deterministic_review_reuses_dedicated_security_scanners(self):
        self.assertIn("uses: ./.github/actions/setup-go-cached", self.deterministic)
        self.assertIn("uses: ./.github/actions/setup-rust-cached", self.deterministic)
        self.assertIn("Restore workflow lint tools", self.deterministic)
        for duplicate in (
            "deterministic-review-vulnerability",
            "Run Semgrep",
            "Install Semgrep",
            "Run changed-range leak scan",
            "semgrep.sarif",
        ):
            with self.subTest(duplicate=duplicate):
                self.assertNotIn(duplicate, self.deterministic)
        self.assertEqual(self.all_workflows.count("semgrep scan"), 1)
        self.assertEqual(self.ci.count("make govulncheck"), 1)
        self.assertNotIn("govulncheck", self.deterministic)
        self.assertEqual(self.all_workflows.count("./scripts/leak_check.sh range"), 1)


if __name__ == "__main__":
    unittest.main()
