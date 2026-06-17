import tempfile
import unittest
from pathlib import Path

import scripts.changed_checks as changed


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

    def test_policy_paths_select_rule_and_detection_checks(self):
        names = self.command_names(["policies/aws/example.json"])
        self.assertIn("catalog-check", names)
        self.assertIn("policy-rule-check", names)
        self.assertIn("detection-catalog-check", names)

    def test_script_paths_select_python_tests(self):
        names = self.command_names(["scripts/droid_review_context.py"])
        self.assertIn("python-script-tests", names)

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


if __name__ == "__main__":
    unittest.main()
