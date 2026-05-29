import importlib.util
from pathlib import Path
import sys
import unittest


spec = importlib.util.spec_from_file_location("verify_aws_scan_role_trust", Path(__file__).resolve().parents[1] / "scripts" / "verify_aws_scan_role_trust.py")
verify_aws_scan_role_trust = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = verify_aws_scan_role_trust
spec.loader.exec_module(verify_aws_scan_role_trust)


class AwsScanRoleTrustTest(unittest.TestCase):
    def test_source_runtime_role_arns_include_all_source_types(self) -> None:
        self.assertEqual(
            verify_aws_scan_role_trust._source_runtime_role_arns(
                {
                    "sourceRuntimes": [
                        {"sourceId": "aws", "config": {"role_arn": "arn:aws:iam::222222222222:role/cerebro-org-scan-role"}},
                        {"sourceId": "aurelius", "config": {"role_arn": "arn:aws:iam::333333333333:role/cerebro-aurelius-source-dev"}},
                        {"sourceId": "github", "config": {"token": "env:GITHUB_TOKEN"}},
                    ]
                }
            ),
            [
                "arn:aws:iam::222222222222:role/cerebro-org-scan-role",
                "arn:aws:iam::333333333333:role/cerebro-aurelius-source-dev",
            ],
        )

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

    def test_same_account_role_filter_keeps_stack_account_roles(self) -> None:
        self.assertEqual(
            verify_aws_scan_role_trust._same_account_role_arns(
                [
                    "arn:aws:iam::009160076449:role/cerebro-org-scan-role",
                    "arn:aws:iam::837279440628:role/cerebro-org-scan-role",
                    "arn:aws:iam::944130631940:role/cerebro-org-scan-role",
                ],
                "837279440628",
            ),
            ["arn:aws:iam::837279440628:role/cerebro-org-scan-role"],
        )


if __name__ == "__main__":
    unittest.main()
