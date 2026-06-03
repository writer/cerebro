from __future__ import annotations

import sys
from pathlib import Path
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import plan_aws_deploy_verifications


class PlanAwsDeployVerificationsTest(unittest.TestCase):
    def test_targets_changed_runtime_ids_for_single_source(self) -> None:
        previous = {
            "sourceRuntimes": [
                {"id": "writer-aws-prod-us1-ec2-instance", "sourceId": "aws", "config": {"family": "ec2_instance", "region": "us-east-1"}},
                {"id": "writer-aws-prod-us1-lambda-function", "sourceId": "aws", "config": {"family": "lambda_function", "region": "us-east-1"}},
            ]
        }
        current = {
            "sourceRuntimes": [
                {"id": "writer-aws-prod-us1-ec2-instance", "sourceId": "aws", "config": {"family": "ec2_instance", "region": "us-east-1", "per_page": "100"}},
                {"id": "writer-aws-prod-us1-lambda-function", "sourceId": "aws", "config": {"family": "lambda_function", "region": "us-east-1"}},
            ]
        }

        plan = plan_aws_deploy_verifications.plan(previous, current)

        self.assertEqual(plan["source_id"], "aws")
        self.assertEqual(plan["runtime_ids"], "writer-aws-prod-us1-ec2-instance")
        self.assertEqual(plan["source_runtime_scope"], "targeted")

    def test_falls_back_to_smoke_scope_for_multiple_sources(self) -> None:
        previous = {
            "sourceRuntimes": [
                {"id": "aws-runtime", "sourceId": "aws", "config": {"family": "ec2_instance"}},
                {"id": "cosmo-runtime", "sourceId": "cosmo", "config": {"family": "fact"}},
            ]
        }
        current = {
            "sourceRuntimes": [
                {"id": "aws-runtime", "sourceId": "aws", "config": {"family": "lambda_function"}},
                {"id": "cosmo-runtime", "sourceId": "cosmo", "config": {"family": "session"}},
            ]
        }

        plan = plan_aws_deploy_verifications.plan(previous, current)

        self.assertEqual(plan["source_id"], "cosmo")
        self.assertEqual(plan["runtime_ids"], "")
        self.assertEqual(plan["source_runtime_scope"], "smoke")

    def test_falls_back_to_smoke_scope_without_base_config(self) -> None:
        current = {"sourceRuntimes": [{"id": "aws-runtime", "sourceId": "aws", "config": {"family": "ec2_instance"}}]}

        plan = plan_aws_deploy_verifications.plan(None, current)

        self.assertEqual(plan["source_id"], "cosmo")
        self.assertEqual(plan["runtime_ids"], "")
        self.assertEqual(plan["source_runtime_scope"], "smoke")


if __name__ == "__main__":
    unittest.main()
