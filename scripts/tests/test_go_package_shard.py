import subprocess
import sys
import unittest

import scripts.go_package_shard as go_package_shard


class GoPackageShardTests(unittest.TestCase):
    def test_select_packages_is_stable_and_complete(self):
        packages = [
            "./api",
            "./cmd/cerebro",
            "./internal/bootstrap",
            "./internal/grcvendor",
            "./sources/okta",
        ]

        shards = [go_package_shard.select_packages(packages, 3, index) for index in range(3)]

        flattened = sorted(package for shard in shards for package in shard)
        self.assertEqual(flattened, sorted(packages))
        for shard in shards:
            self.assertEqual(len(shard), len(set(shard)))

    def test_cli_rejects_invalid_index(self):
        result = subprocess.run(
            [sys.executable, "scripts/go_package_shard.py", "--total", "2", "--index", "2"],
            input="./api\n",
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--index", result.stderr)


if __name__ == "__main__":
    unittest.main()
