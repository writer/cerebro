import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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
        names = self.command_names(["scripts/land_pr.py"])
        self.assertIn("python-script-tests", names)

    def test_rust_workspace_paths_select_graph_action_check(self):
        for path in (
            "Cargo.toml",
            "Cargo.lock",
            "rust-toolchain.toml",
            "crates/action-catalog/src/lib.rs",
            "tools/graphactiongen/src/lib.rs",
        ):
            with self.subTest(path=path):
                self.assertIn("graph-action-check", self.command_names([path]))

    def test_rust_workspace_paths_select_policy_catalog_check(self):
        for path in (
            "Cargo.toml",
            "Cargo.lock",
            "rust-toolchain.toml",
            "crates/policy-catalog/src/lib.rs",
            "tools/policycataloggen/src/main.rs",
        ):
            with self.subTest(path=path):
                self.assertIn("policy-catalog-check", self.command_names([path]))

    def test_rust_dependency_policy_paths_select_deny(self):
        for path in ("Cargo.toml", "Cargo.lock", "deny.toml"):
            with self.subTest(path=path):
                self.assertIn("rust-deny", self.command_names([path]))

    def test_source_runtime_crates_select_focused_rust_validation(self):
        packages = [
            "-p",
            "cerebro-platform",
            "-p",
            "cerebro-source-catalog",
            "-p",
            "cerebro-source-runtime-next",
        ]
        for path in (
            "crates/cerebro-platform/src/main.rs",
            "crates/source-catalog/src/lib.rs",
            "crates/source-runtime-next/src/http.rs",
        ):
            with self.subTest(path=path):
                selected = changed.select_commands([path], Path("."))
                commands = {plan.name: plan.argv for plan in selected}
                self.assertEqual(
                    commands["rust-source-runtime-fmt"],
                    ["cargo", "fmt", "--all", "--", "--check"],
                )
                self.assertEqual(
                    commands["rust-source-runtime-test"],
                    ["cargo", "test", "--locked", *packages],
                )
                self.assertEqual(
                    commands["rust-source-runtime-clippy"],
                    [
                        "cargo",
                        "clippy",
                        "--locked",
                        *packages,
                        "--all-targets",
                        "--all-features",
                        "--",
                        "-D",
                        "warnings",
                    ],
                )

    def test_workspace_manifests_and_policy_select_workspace_check(self):
        for path in (
            "Cargo.toml",
            "crates/control-kernel/Cargo.toml",
            "internal/wasmguest/Cargo.toml",
            "scripts/rust_workspace_policy.py",
            "scripts/tests/test_rust_workspace_policy.py",
        ):
            with self.subTest(path=path):
                self.assertIn("rust-workspace-policy", self.command_names([path]))

    def test_shared_embedded_wasm_paths_select_aggregate_check(self):
        for path in (
            "Cargo.toml",
            "Cargo.lock",
            "rust-toolchain.toml",
            "scripts/embedded_wasm.py",
            "internal/wasmguest/Cargo.toml",
            "internal/wasmguest/src/lib.rs",
        ):
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

    def test_wasm_json_corpora_select_owning_go_test(self):
        cases = (
            (
                "internal/mitre/testdata/wasmjson/current_metadata.json",
                "mitre-wasm-parity-corpus",
                ["go", "test", "./internal/mitre", "-run", "^TestContextEvaluatorCorpus$", "-count=1"],
            ),
            (
                "internal/sourcecoverage/testdata/wasmjson/mixed_states.json",
                "sourcecoverage-wasm-parity-corpus",
                ["go", "test", "./internal/sourcecoverage", "-run", "^TestCoverageEvaluatorCorpus$", "-count=1"],
            ),
            (
                "internal/sourceprojection/testdata/panopticonresources/nested_aliases.json",
                "panopticon-wasm-parity-corpus",
                ["go", "test", "./internal/sourceprojection", "-run", "^TestPanopticonResourceObjectsWasmCorpus$", "-count=1"],
            ),
        )
        for path, command, argv in cases:
            with self.subTest(path=path):
                selected = [plan for plan in changed.select_commands([path], Path(".")) if plan.name == command]
                self.assertEqual(len(selected), 1)
                self.assertEqual(selected[0].argv, argv)

    def test_shared_wasm_json_helper_selects_all_parity_corpora(self):
        selected = changed.select_commands(["internal/wasmjson/wasmjsontest/corpus.go"], Path("."))
        command = [plan for plan in selected if plan.name == "wasm-json-parity-corpora"]
        self.assertEqual(len(command), 1)
        self.assertEqual(
            command[0].argv,
            [
                "go",
                "test",
                "./internal/mitre",
                "./internal/sourcecoverage",
                "./internal/sourceprojection",
                "-run",
                "^(TestContextEvaluatorCorpus|TestCoverageEvaluatorCorpus|TestPanopticonResourceObjectsWasmCorpus)$",
                "-count=1",
            ],
        )

    def test_static_validator_property_and_fuzz_paths_select_deterministic_properties(self):
        for path in (
            "internal/graphagent/staticvalidator/tests/properties.rs",
            "internal/graphagent/staticvalidator/fuzz/fuzz_targets/validate.rs",
            "internal/graphagent/staticvalidator/fuzz/corpus/validate/scoped-read",
        ):
            with self.subTest(path=path):
                names = self.command_names([path])
                self.assertIn("graphagent-static-validator-check", names)
                self.assertIn("rust-validator-properties", names)

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

    def test_print_go_packages_uses_validated_package_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package_dir = root / "internal" / "demo"
            package_dir.mkdir(parents=True)
            (package_dir / "demo.go").write_text("package demo\n", encoding="utf-8")
            stdout = io.StringIO()
            with (
                mock.patch.object(changed, "changed_files", return_value=["internal/demo/demo.go"]),
                mock.patch("sys.argv", ["changed_checks.py", "--repo", str(root), "--print-go-packages"]),
                contextlib.redirect_stdout(stdout),
            ):
                exit_code = changed.main()
            self.assertEqual(exit_code, 0)
            self.assertEqual(stdout.getvalue(), "./internal/demo\n")

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
