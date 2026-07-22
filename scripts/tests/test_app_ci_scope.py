import io
import unittest

from scripts.app_ci_scope import CIScope, MAPPED_APP_DIRS, select_scope, write_github_outputs
from scripts.app_workspace_contract import MAPPED_APP_DIRS as CONTRACT_MAPPED_APP_DIRS


class AppCIScopeTests(unittest.TestCase):
    def test_web_only_change_skips_core_and_selects_image(self):
        self.assertEqual(
            select_scope(["apps/web/src/app/page.tsx"]),
            CIScope(core=False, sdk=False, slack=False, web=True, web_image=True, web_integration=True),
        )

    def test_slack_only_change_skips_core(self):
        self.assertEqual(
            select_scope(["apps/slack-companion/src/admission.ts"]),
            CIScope(core=False, sdk=False, slack=True, web=False, web_image=False),
        )

    def test_slack_host_only_change_uses_slack_scope(self):
        self.assertEqual(
            select_scope(["apps/slack-companion-host/src/main.ts"]),
            CIScope(core=False, sdk=False, slack=True, web=False, web_image=False),
        )

    def test_deleted_known_app_path_selects_its_owned_checks(self):
        self.assertEqual(
            select_scope(["apps/web/src/removed.ts"]),
            CIScope(core=False, sdk=False, slack=False, web=True, web_image=True, web_integration=True),
        )

    def test_type_changed_known_app_path_selects_its_owned_checks(self):
        self.assertEqual(
            select_scope(["apps/web/src/linked-config.ts"]),
            CIScope(core=False, sdk=False, slack=False, web=True, web_image=True, web_integration=True),
        )

    def test_rename_old_and_new_paths_cannot_hide_owned_checks(self):
        self.assertEqual(
            select_scope(
                [
                    "apps/slack-companion/src/old-name.ts",
                    "docs/new-name.ts",
                ]
            ),
            CIScope(core=True, sdk=False, slack=True, web=False, web_image=False),
        )

    def test_unknown_application_path_fails_safe_to_every_scope(self):
        self.assertEqual(select_scope(["apps/new-surface/package.json"]), CIScope.all())

    def test_unknown_two_component_application_path_fails_safe_to_every_scope(self):
        self.assertEqual(select_scope(["apps/new-surface"]), CIScope.all())

    def test_unknown_application_root_file_fails_safe_to_every_scope(self):
        self.assertEqual(select_scope(["apps/shared-config.ts"]), CIScope.all())

    def test_scope_and_workspace_contract_share_the_same_app_mapping(self):
        self.assertEqual(MAPPED_APP_DIRS, CONTRACT_MAPPED_APP_DIRS)

    def test_sdk_change_checks_sdk_and_its_consumer(self):
        self.assertEqual(
            select_scope(["sdk/typescript/src/index.ts"]),
            CIScope(core=False, sdk=True, slack=True, web=False, web_image=False),
        )

    def test_root_npm_change_selects_every_javascript_workspace(self):
        self.assertEqual(
            select_scope(["package-lock.json"]),
            CIScope(core=False, sdk=True, slack=True, web=True, web_image=True, web_integration=True),
        )

    def test_core_contract_changes_select_consuming_apps(self):
        scope = select_scope(
            [
                "api/openapi.yaml",
                "schemas/agent-service-lifecycle.schema.json",
            ]
        )
        self.assertEqual(
            scope,
            CIScope(core=True, sdk=True, slack=True, web=True, web_image=True, web_integration=True),
        )

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
            CIScope(core=True, sdk=False, slack=False, web=True, web_image=True, web_integration=True),
        )

    def test_relevant_service_paths_select_real_web_integration(self):
        for path in (
            "cmd/cerebro/main.go",
            "internal/bootstrap/grc.go",
            "internal/graphstore/neo4j/store.go",
            "internal/querycache/cache.go",
            "internal/sourcecoverage/coverage.go",
            "internal/sourcehttp/responseview/response_view.go",
            "internal/sourceruntime/runtime.go",
            "internal/statestore/postgres/store.go",
        ):
            with self.subTest(path=path):
                self.assertTrue(select_scope([path]).web_integration)

    def test_docs_and_unrelated_core_paths_skip_real_web_integration(self):
        for path in (
            "apps/web/README.md",
            "docs/engineering/monorepo.md",
            "internal/unrelated/example.go",
        ):
            with self.subTest(path=path):
                self.assertFalse(select_scope([path]).web_integration)

    def test_empty_diff_and_explicit_all_fail_safe_to_every_scope(self):
        self.assertEqual(select_scope([]), CIScope.all())
        self.assertEqual(select_scope(["apps/web/README.md"], run_all=True), CIScope.all())

    def test_filenames_are_written_only_as_constant_boolean_outputs(self):
        scope = select_scope(["apps/web/$(touch unexpected).tsx"])
        output = io.StringIO()
        write_github_outputs(scope, output)
        self.assertEqual(
            output.getvalue(),
            "core=false\nsdk=false\nslack=false\nweb=true\nweb_image=true\nweb_integration=true\n",
        )


if __name__ == "__main__":
    unittest.main()
