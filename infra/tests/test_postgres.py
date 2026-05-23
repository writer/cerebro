from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


spec = importlib.util.spec_from_file_location("postgres", Path(__file__).resolve().parents[1] / "aws" / "postgres.py")
postgres = importlib.util.module_from_spec(spec)
spec.loader.exec_module(postgres)


class PostgresStorageTest(unittest.TestCase):
    def test_storage_args_default_to_gp3_without_burst_credit_dependency(self) -> None:
        args = postgres._postgres_storage_args(allocated_storage=100, storage_type="")

        self.assertEqual(args["storage_type"], "gp3")
        self.assertEqual(args["max_allocated_storage"], 200)
        self.assertNotIn("iops", args)
        self.assertNotIn("storage_throughput", args)

    def test_storage_args_pass_through_explicit_gp3_capacity(self) -> None:
        args = postgres._postgres_storage_args(
            allocated_storage=400,
            storage_type="gp3",
            max_allocated_storage=800,
            iops=3000,
            storage_throughput=125,
        )

        self.assertEqual(
            args,
            {
                "storage_type": "gp3",
                "max_allocated_storage": 800,
                "iops": 3000,
                "storage_throughput": 125,
            },
        )

    def test_storage_args_reject_invalid_autoscaling_ceiling(self) -> None:
        with self.assertRaises(ValueError):
            postgres._postgres_storage_args(
                allocated_storage=100,
                storage_type="gp3",
                max_allocated_storage=50,
            )


if __name__ == "__main__":
    unittest.main()
