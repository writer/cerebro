import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class MakefileTargetTests(unittest.TestCase):
    def makefile_text(self):
        return (ROOT / "Makefile").read_text(encoding="utf-8")

    def make_env(self, **overrides):
        env = os.environ.copy()
        for key in (
            "GITHUB_OWNER",
            "GITHUB_REPO",
            "GITHUB_TOKEN",
            "CEREBRO_SOURCE_GITHUB_OWNER",
            "CEREBRO_SOURCE_GITHUB_REPO",
            "CEREBRO_SOURCE_GITHUB_TOKEN",
        ):
            env.pop(key, None)
        env.update(overrides)
        return env

    def run_make(self, env):
        return subprocess.run(
            ["make", "--no-print-directory", "github-business-demo-env"],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_github_business_demo_env_rejects_missing_owner(self):
        result = self.run_make(self.make_env())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("CEREBRO_SOURCE_GITHUB_OWNER is required", result.stderr)
        self.assertNotIn("docker compose", result.stdout + result.stderr)

    def test_github_business_demo_env_accepts_github_aliases(self):
        result = self.run_make(
            self.make_env(
                GITHUB_OWNER="writer",
                GITHUB_REPO="cerebro",
                GITHUB_TOKEN="ghp_test",
            )
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_local_postgres_password_default_is_generated(self):
        makefile = self.makefile_text()
        self.assertIn("CEREBRO_LOCAL_POSTGRES_PASSWORD_FILE ?= tmp/local-postgres-password", makefile)
        self.assertIn("secrets.token_urlsafe", makefile)
        self.assertNotIn("CEREBRO_LOCAL_POSTGRES_PASSWORD ?= cerebro", makefile)
        self.assertNotIn("CEREBRO_LOCAL_POSTGRES_PASSWORD ?= $(shell", makefile)

    def test_make_help_does_not_generate_local_postgres_password(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            password_file = Path(tmpdir) / "local-postgres-password"
            result = subprocess.run(
                ["make", "--no-print-directory", "help"],
                cwd=ROOT,
                env=self.make_env(CEREBRO_LOCAL_POSTGRES_PASSWORD_FILE=str(password_file)),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(password_file.exists())

    def test_embedded_wasm_targets_keep_stable_names_and_use_registry(self):
        makefile = self.makefile_text()
        targets = (
            "graphagent-static-validator",
            "sourcecoverage-evaluator",
            "panopticon-resource-extractor",
            "mitre-context-evaluator",
        )
        for module in targets:
            with self.subTest(module=module):
                self.assertIn(f"{module}-generate:", makefile)
                self.assertIn(f"{module}-check:", makefile)
                self.assertIn(f"scripts/embedded_wasm.py generate {module}", makefile)
                self.assertIn(f"scripts/embedded_wasm.py check {module}", makefile)
        self.assertIn("scripts/embedded_wasm.py check all", makefile)


if __name__ == "__main__":
    unittest.main()
