import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


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

    def test_source_runtime_role_arns_can_exclude_dry_run_only_sources(self) -> None:
        self.assertEqual(
            verify_aws_scan_role_trust._source_runtime_role_arns(
                {
                    "sourceRuntimes": [
                        {"sourceId": "panopticon", "config": {"role_arn": "arn:aws:iam::222222222222:role/panopticon-export-reader"}},
                        {"sourceId": "cosmo", "config": {"role_arn": "arn:aws:iam::222222222222:role/cerebro-org-scan-role"}},
                    ]
                },
                excluded_source_ids={"panopticon"},
            ),
            ["arn:aws:iam::222222222222:role/cerebro-org-scan-role"],
        )

    def test_expected_principals_include_worker_role_for_scheduled_stack(self) -> None:
        self.assertEqual(
            verify_aws_scan_role_trust._expected_stack_principals("go-prod", {"environment": "go-production"}, "837279440628"),
            [
                "arn:aws:iam::837279440628:role/cerebro-go-production-task-role",
                "arn:aws:iam::837279440628:role/cerebro-go-production-worker-task-role",
            ],
        )

    def test_expected_principals_accept_matching_pulumi_outputs(self) -> None:
        self.assertEqual(
            verify_aws_scan_role_trust._expected_stack_principals_from_outputs(
                "sec-dev",
                {"environment": "sec-dev"},
                "944130631940",
                {
                    "task_role_arn": "arn:aws:iam::944130631940:role/cerebro-sec-dev-task-role",
                    "worker_task_role_arn": "arn:aws:iam::944130631940:role/cerebro-sec-dev-worker-task-role",
                },
            ),
            [
                "arn:aws:iam::944130631940:role/cerebro-sec-dev-task-role",
                "arn:aws:iam::944130631940:role/cerebro-sec-dev-worker-task-role",
            ],
        )

    def test_expected_principals_reject_mismatched_pulumi_outputs(self) -> None:
        with self.assertRaisesRegex(ValueError, "disagrees with derived fallback"):
            verify_aws_scan_role_trust._expected_stack_principals_from_outputs(
                "go-prod",
                {"environment": "go-production"},
                "837279440628",
                {"task_role_arn": "arn:aws:iam::837279440628:role/cerebro-go-prod-task-role"},
            )

    def test_load_outputs_requires_json_object(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "outputs.json"
            path.write_text(json.dumps(["not", "an", "object"]), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "must contain a JSON object"):
                verify_aws_scan_role_trust._load_outputs(path)

    def test_aws_parses_stdout_when_success_emits_stderr_warning(self) -> None:
        with patch.object(verify_aws_scan_role_trust.subprocess, "run") as run:
            run.return_value = subprocess.CompletedProcess(
                ["aws"],
                0,
                stdout=json.dumps({"Role": {"RoleName": "present"}}),
                stderr="WARNING: non-fatal AWS CLI warning\n",
            )

            self.assertEqual(
                verify_aws_scan_role_trust._aws(["iam", "get-role", "--role-name", "present"], "us-east-1"),
                {"Role": {"RoleName": "present"}},
            )

        _, kwargs = run.call_args
        self.assertTrue(kwargs["capture_output"])
        self.assertTrue(kwargs["check"])

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

    def test_summary_markdown_lists_missing_trust(self) -> None:
        summary = verify_aws_scan_role_trust._summary_markdown(
            "go-prod",
            ["arn:aws:iam::837279440628:role/cerebro-org-scan-role"],
            [
                "arn:aws:iam::837279440628:role/cerebro-go-production-task-role",
                "arn:aws:iam::837279440628:role/cerebro-go-production-worker-task-role",
            ],
            [
                verify_aws_scan_role_trust.TrustFinding(
                    "837279440628",
                    "cerebro-org-scan-role",
                    "arn:aws:iam::837279440628:role/cerebro-go-production-task-role",
                )
            ],
        )

        self.assertIn("Status: **failed**", summary)
        self.assertIn("Checked roles: `1`", summary)
        self.assertIn("`arn:aws:iam::837279440628:role/cerebro-org-scan-role`", summary)
        self.assertIn("`arn:aws:iam::837279440628:role/cerebro-go-production-task-role`", summary)

    def test_summary_markdown_reports_success(self) -> None:
        summary = verify_aws_scan_role_trust._summary_markdown(
            "sec-dev",
            ["arn:aws:iam::944130631940:role/cerebro-org-scan-role"],
            ["arn:aws:iam::944130631940:role/cerebro-sec-dev-task-role"],
            [],
        )

        self.assertIn("Status: **passed**", summary)
        self.assertIn("All checked source runtime roles trust the expected task principals.", summary)

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

    def test_go_prod_config_no_longer_checks_panopticon_export_reader_role(self) -> None:
        config = verify_aws_scan_role_trust._load_config(Path(__file__).resolve().parents[1] / "aws" / "Pulumi.go-prod.yaml")

        role_arns = verify_aws_scan_role_trust._same_account_role_arns(
            verify_aws_scan_role_trust._source_runtime_role_arns(config),
            "837279440628",
        )

        self.assertNotIn(
            "arn:aws:iam::837279440628:role/panopticon-prod-cerebro-export-reader",
            role_arns,
        )

    def test_missing_role_preflight_reports_role_arn(self) -> None:
        role_arn = "arn:aws:iam::837279440628:role/panopticon-prod-cerebro-export-reader"
        original_aws = verify_aws_scan_role_trust._aws

        def fail_get_role(*_args, **_kwargs):
            raise subprocess.CalledProcessError(
                254,
                ["aws", "iam", "get-role"],
                stderr="An error occurred (NoSuchEntity) when calling the GetRole operation: role missing",
            )

        verify_aws_scan_role_trust._aws = fail_get_role
        try:
            with self.assertRaisesRegex(
                RuntimeError,
                "panopticon-prod-cerebro-export-reader.*producer-owned role",
            ):
                verify_aws_scan_role_trust._load_role_policies(
                    [role_arn],
                    "837279440628",
                    "us-east-1",
                    {},
                )
        finally:
            verify_aws_scan_role_trust._aws = original_aws


if __name__ == "__main__":
    unittest.main()
