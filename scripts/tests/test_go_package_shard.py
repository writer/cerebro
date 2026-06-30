import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

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

    def test_weighted_packages_keep_expensive_packages_apart(self):
        packages = [
            "github.com/writer/cerebro/cmd/cerebro",
            "github.com/writer/cerebro/internal/bootstrap",
            "github.com/writer/cerebro/internal/findings",
            "github.com/writer/cerebro/sources/aws",
        ]
        weights = {
            "github.com/writer/cerebro/cmd/cerebro": 100,
            "github.com/writer/cerebro/internal/bootstrap": 90,
        }

        shards = [go_package_shard.select_packages(packages, 2, index, weights) for index in range(2)]

        flattened = sorted(package for shard in shards for package in shard)
        self.assertEqual(flattened, sorted(packages))
        heavy_locations = {
            package: index
            for index, shard in enumerate(shards)
            for package in shard
            if package in weights
        }
        self.assertNotEqual(
            heavy_locations["github.com/writer/cerebro/cmd/cerebro"],
            heavy_locations["github.com/writer/cerebro/internal/bootstrap"],
        )

    def test_weighted_packages_use_default_weight_for_unknown_packages(self):
        packages = [
            "github.com/writer/cerebro/cmd/cerebro",
            "github.com/writer/cerebro/internal/a",
            "github.com/writer/cerebro/internal/b",
            "github.com/writer/cerebro/internal/c",
            "github.com/writer/cerebro/internal/d",
            "github.com/writer/cerebro/internal/e",
        ]
        weights = {"github.com/writer/cerebro/cmd/cerebro": 100}

        light_default = [go_package_shard.select_packages(packages, 2, index, weights) for index in range(2)]
        heavier_default = [
            go_package_shard.select_packages(packages, 2, index, weights, default_weight=25) for index in range(2)
        ]

        self.assertEqual(sorted(package for shard in heavier_default for package in shard), sorted(packages))
        self.assertNotEqual([len(shard) for shard in light_default], [len(shard) for shard in heavier_default])

    def test_cli_accepts_weight_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            weights_path = Path(tmp) / "weights.json"
            weights_path.write_text(json.dumps({"./heavy": 100}), encoding="utf-8")

            result = subprocess.run(
                [
                    sys.executable,
                    "scripts/go_package_shard.py",
                    "--total",
                    "2",
                    "--index",
                    "0",
                    "--weights",
                    str(weights_path),
                    "--default-weight",
                    "2",
                ],
                input="./heavy\n./light\n",
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("./heavy", result.stdout)

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
