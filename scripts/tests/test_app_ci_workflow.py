import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


class AppCIWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_keeps_stable_terminal_verify_job(self):
        self.assertIn("\n  verify:\n", self.workflow)
        self.assertIn("if: always()", self.workflow)
        self.assertIn("All selected CI scopes passed", self.workflow)
        self.assertNotIn("paths-ignore:", self.workflow)

    def test_core_matrices_use_the_tested_scope(self):
        self.assertEqual(
            self.workflow.count("if: needs.ci-scope.outputs.core == 'true'"),
            5,
        )
        for job in ("verify-shard", "go-lint-shard", "catalog-shard", "go-test-shard", "go-race-shard"):
            self.assertIn(f"  {job}:\n", self.workflow)

    def test_scope_diff_includes_every_change_type_and_both_rename_paths(self):
        self.assertIn(
            "git diff --name-only --no-renames -z",
            self.workflow,
        )
        self.assertNotIn("--diff-filter=", self.workflow)

    def test_app_jobs_are_first_class_verify_dependencies(self):
        expected_jobs = (
            "app-workspace-contract",
            "web",
            "web-image",
            "slack-companion",
            "typescript-sdk",
            "javascript-dependency-audit",
        )
        for job in expected_jobs:
            self.assertIn(f"  {job}:\n", self.workflow)
        self.assertIn(
            "needs: [ci-scope, app-workspace-contract, web, web-image, slack-companion, typescript-sdk, javascript-dependency-audit, verify-shard, catalog, test, race, lint]",
            self.workflow,
        )

    def test_app_jobs_run_owned_checks(self):
        self.assertIn("npm run check --workspace @writer/cerebro-web", self.workflow)
        self.assertIn("make web-docker-smoke", self.workflow)
        self.assertIn("npm run check --workspace @writer/cerebro-slack-companion", self.workflow)
        self.assertIn("npm run check --workspace @writer/cerebro-sdk", self.workflow)

    def test_verify_binds_scope_outputs_before_using_them(self):
        verify_job = self.workflow.split("\n  verify:\n", 1)[1]
        step = verify_job.split("- name: Check selected CI scopes", 1)[1]
        environment, run_block = step.split("run: |", 1)
        variables = {
            "CI_SCOPE_CORE": "core",
            "CI_SCOPE_SDK": "sdk",
            "CI_SCOPE_SLACK": "slack",
            "CI_SCOPE_WEB": "web",
            "CI_SCOPE_WEB_IMAGE": "web_image",
        }
        for variable, output in variables.items():
            with self.subTest(variable=variable):
                self.assertIn(
                    f"{variable}: ${{{{ needs.ci-scope.outputs.{output} }}}}",
                    environment,
                )
                self.assertIn(f'"${{{variable}}}"', run_block)
        self.assertNotIn("needs.ci-scope.outputs.", run_block)

    def test_first_class_web_image_job_is_the_only_image_smoke_owner(self):
        self.assertEqual(self.workflow.count("make web-docker-smoke"), 1)
        verify_matrix = self.workflow.split("\n  verify-shard:\n", 1)[1].split(
            "\n  go-lint-shard:\n",
            1,
        )[0]
        self.assertNotIn("web-docker-smoke", verify_matrix)

    def test_javascript_audit_blocks_production_advisories_at_moderate(self):
        self.assertIn("npm audit --omit=dev --audit-level=moderate", self.workflow)
        self.assertNotIn("npm audit --audit-level=high", self.workflow)


if __name__ == "__main__":
    unittest.main()
