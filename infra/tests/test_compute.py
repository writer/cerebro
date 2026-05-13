from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


spec = importlib.util.spec_from_file_location("compute", Path(__file__).resolve().parents[1] / "aws" / "compute.py")
compute = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compute)


class SourceRuntimeEnvironmentTest(unittest.TestCase):
    def test_adds_aws_role_allowlist_from_source_runtimes(self) -> None:
        env = compute._source_runtime_environment(
            {"CEREBRO_ENVIRONMENT": "sec-dev"},
            [
                {"sourceId": "aws", "tenantId": "writer", "config": {"role_arn": "arn:aws:iam::222222222222:role/cerebro-org-scan-role"}},
                {"source_id": "aws", "tenant_id": "other", "config": {"role_arn": "arn:aws:iam::111111111111:role/cerebro-org-scan-role"}},
                {"sourceId": "github", "config": {"role_arn": "arn:aws:iam::333333333333:role/ignored"}},
            ],
        )
        self.assertEqual(
            env["CEREBRO_AWS_ASSUME_ROLE_ARNS"],
            "other=arn:aws:iam::111111111111:role/cerebro-org-scan-role,writer=arn:aws:iam::222222222222:role/cerebro-org-scan-role",
        )
        self.assertEqual(env["CEREBRO_ENVIRONMENT"], "sec-dev")

    def test_preserves_explicit_aws_role_allowlist(self) -> None:
        env = compute._source_runtime_environment(
            {"CEREBRO_AWS_ASSUME_ROLE_ARNS": "custom=arn:aws:iam::999999999999:role/custom"},
            [{"sourceId": "aws", "tenantId": "writer", "config": {"role_arn": "arn:aws:iam::111111111111:role/cerebro-org-scan-role"}}],
        )
        self.assertEqual(env["CEREBRO_AWS_ASSUME_ROLE_ARNS"], "custom=arn:aws:iam::999999999999:role/custom")


if __name__ == "__main__":
    unittest.main()
