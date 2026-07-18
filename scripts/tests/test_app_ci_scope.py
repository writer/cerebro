import io
import unittest

from scripts.app_ci_scope import CIScope, select_scope, write_github_outputs


class AppCIScopeTests(unittest.TestCase):
    def test_web_only_change_skips_core_and_selects_image(self):
        self.assertEqual(
            select_scope(["apps/web/src/app/page.tsx"]),
            CIScope(core=False, sdk=False, slack=False, web=True, web_image=True),
        )

    def test_slack_only_change_skips_core(self):
        self.assertEqual(
            select_scope(["apps/slack-companion/src/admission.ts"]),
            CIScope(core=False, sdk=False, slack=True, web=False, web_image=False),
        )

    def test_sdk_change_checks_sdk_and_its_consumer(self):
        self.assertEqual(
            select_scope(["sdk/typescript/src/index.ts"]),
            CIScope(core=False, sdk=True, slack=True, web=False, web_image=False),
        )

    def test_root_npm_change_selects_every_javascript_workspace(self):
        self.assertEqual(
            select_scope(["package-lock.json"]),
            CIScope(core=False, sdk=True, slack=True, web=True, web_image=True),
        )

    def test_core_contract_changes_select_consuming_apps(self):
        scope = select_scope(
            [
                "api/openapi.yaml",
                "schemas/agent-service-lifecycle.schema.json",
            ]
        )
        self.assertEqual(scope, CIScope(core=True, sdk=True, slack=True, web=True, web_image=True))

    def test_ci_controller_changes_run_every_scope(self):
        for path in (
            ".github/workflows/ci.yml",
            "Makefile",
            "scripts/app_ci_scope.py",
            "scripts/app_workspace_contract.py",
        ):
            with self.subTest(path=path):
                self.assertEqual(select_scope([path]), CIScope.all())

    def test_mixed_change_runs_core_and_changed_app(self):
        self.assertEqual(
            select_scope(["apps/web/src/app/page.tsx", "internal/bootstrap/bootstrap.go"]),
            CIScope(core=True, sdk=False, slack=False, web=True, web_image=True),
        )

    def test_empty_diff_and_explicit_all_fail_safe_to_every_scope(self):
        self.assertEqual(select_scope([]), CIScope.all())
        self.assertEqual(select_scope(["apps/web/README.md"], run_all=True), CIScope.all())

    def test_filenames_are_written_only_as_constant_boolean_outputs(self):
        scope = select_scope(["apps/web/$(touch unexpected).tsx"])
        output = io.StringIO()
        write_github_outputs(scope, output)
        self.assertEqual(
            output.getvalue(),
            "core=false\nsdk=false\nslack=false\nweb=true\nweb_image=true\n",
        )


if __name__ == "__main__":
    unittest.main()
