import importlib.util
from pathlib import Path
import sys
import unittest


spec = importlib.util.spec_from_file_location("verify_aws_scan_role_trust", Path(__file__).resolve().parents[1] / "scripts" / "verify_aws_scan_role_trust.py")
verify_aws_scan_role_trust = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = verify_aws_scan_role_trust
spec.loader.exec_module(verify_aws_scan_role_trust)


class AwsScanRoleTrustTest(unittest.TestCase):
    def test_expected_principals_include_worker_role_for_scheduled_stack(self) -> None:
        self.assertEqual(
            verify_aws_scan_role_trust._expected_stack_principals("go-prod", {"environment": "go-production"}, "837279440628"),
            [
                "arn:aws:iam::837279440628:role/cerebro-go-production-task-role",
                "arn:aws:iam::837279440628:role/cerebro-go-production-worker-task-role",
            ],
        )

    def test_missing_worker_trust_is_reported(self) -> None:
        target_role = "arn:aws:iam::381491964434:role/cerebro-org-scan-role"
        findings = verify_aws_scan_role_trust._find_missing_trust(
            [target_role],
            [
                "arn:aws:iam::837279440628:role/cerebro-go-production-task-role",
                "arn:aws:iam::837279440628:role/cerebro-go-production-worker-task-role",
            ],
            {
                target_role: {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": "arn:aws:iam::837279440628:role/cerebro-go-production-task-role"},
                            "Action": ["sts:AssumeRole", "sts:TagSession"],
                        }
                    ]
                }
            },
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].account_id, "381491964434")
        self.assertEqual(findings[0].role_name, "cerebro-org-scan-role")
        self.assertEqual(findings[0].principal_arn, "arn:aws:iam::837279440628:role/cerebro-go-production-worker-task-role")

    def test_trusted_worker_role_passes(self) -> None:
        target_role = "arn:aws:iam::837279440628:role/cerebro-org-scan-role"
        findings = verify_aws_scan_role_trust._find_missing_trust(
            [target_role],
            ["arn:aws:iam::837279440628:role/cerebro-go-production-worker-task-role"],
            {
                target_role: {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": ["arn:aws:iam::837279440628:role/cerebro-go-production-worker-task-role"]},
                            "Action": "sts:AssumeRole",
                        }
                    ]
                }
            },
        )

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
