import tempfile
import unittest
from pathlib import Path

import scripts.changed_checks as changed
from scripts.embedded_wasm import EMBEDDED_WASM_MODULES


class ChangedChecksTests(unittest.TestCase):
    def command_names(self, files):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for path in files:
                full = root / path
                full.parent.mkdir(parents=True, exist_ok=True)
                full.write_text("package demo\n", encoding="utf-8")
            return [command.name for command in changed.select_commands(files, root)]

    def test_sourcegen_paths_select_sourcegen_and_catalog_checks(self):
        names = self.command_names(["internal/connectorcatalog/catalog/devops-ci-cd.yaml"])
        self.assertIn("sourcegen-check", names)
        self.assertIn("catalog-check", names)
        self.assertIn("connector-catalog-review", names)

    def test_connector_review_tooling_selects_catalog_review(self):
        names = self.command_names(["tools/connectorcatalogreview/main.go"])
        self.assertIn("connector-catalog-review", names)

    def test_policy_paths_select_rule_and_detection_checks(self):
        names = self.command_names(["policies/aws/example.yaml"])
        self.assertIn("catalog-check", names)
        self.assertIn("finding-dsl-check", names)
        self.assertIn("policy-rule-check", names)
        self.assertIn("detection-catalog-check", names)

    def test_policy_schema_paths_select_dsl_check(self):
        names = self.command_names(["schemas/policy-finding-rule.schema.json"])
        self.assertIn("finding-dsl-check", names)

    def test_script_paths_select_python_tests(self):
        names = self.command_names(["scripts/droid_review_context.py"])
        self.assertIn("python-script-tests", names)

    def test_rust_workspace_paths_select_graph_action_check(self):
        for path in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "tools/graphactiongen/src/lib.rs"):
            with self.subTest(path=path):
                self.assertIn("graph-action-check", self.command_names([path]))

    def test_shared_embedded_wasm_paths_select_aggregate_check(self):
        for path in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "scripts/embedded_wasm.py"):
            with self.subTest(path=path):
                names = self.command_names([path])
                self.assertIn("rust-wasm-check", names)
                for module in EMBEDDED_WASM_MODULES:
                    self.assertNotIn(module.check_target, names)

    def test_module_paths_select_registered_module_check(self):
        for module in EMBEDDED_WASM_MODULES:
            paths = [
                *(f"{prefix}src/lib.rs" for prefix in module.changed_prefixes),
                *module.changed_paths,
            ]
            for path in paths:
                with self.subTest(module=module.name, path=path):
                    self.assertIn(module.check_target, self.command_names([path]))

    def test_readme_source_paths_select_readme_check(self):
        names = self.command_names(["tools/controlindex/main.go"])
        self.assertIn("readme-check", names)
        self.assertIn("control-index-check", names)

    def test_go_files_select_package_tests(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package_dir = root / "internal" / "demo"
            package_dir.mkdir(parents=True)
            (package_dir / "demo.go").write_text("package demo\n", encoding="utf-8")
            commands = changed.select_commands(["internal/demo/demo.go"], root)
            go_tests = [command for command in commands if command.name == "go-test-changed-packages"]
            self.assertEqual(len(go_tests), 1)
            self.assertIn("./internal/demo", go_tests[0].argv)

    def test_go_files_under_nested_modules_do_not_select_root_package_tests(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nested = root / "tools" / "linters"
            package_dir = nested / "maxfields"
            package_dir.mkdir(parents=True)
            (nested / "go.mod").write_text("module example.com/linters\n", encoding="utf-8")
            (package_dir / "maxfields.go").write_text("package maxfields\n", encoding="utf-8")
            commands = changed.select_commands(["tools/linters/maxfields/maxfields.go"], root)
            self.assertNotIn("go-test-changed-packages", [command.name for command in commands])


if __name__ == "__main__":
    unittest.main()
