import os
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class MakefileTargetTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
