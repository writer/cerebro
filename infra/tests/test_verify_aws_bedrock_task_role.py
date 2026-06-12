import importlib.util
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "verify_aws_bedrock_task_role",
    Path(__file__).resolve().parents[1] / "scripts" / "verify_aws_bedrock_task_role.py",
)
verify_aws_bedrock_task_role = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = verify_aws_bedrock_task_role
spec.loader.exec_module(verify_aws_bedrock_task_role)


class VerifyAWSBedrockTaskRoleTest(unittest.TestCase):
    def test_bedrock_resource_arns_cover_profile_and_foundation_model(self) -> None:
        self.assertCountEqual(
            verify_aws_bedrock_task_role.bedrock_resource_arns(["us.anthropic.claude-sonnet-4-6"], "123456789012"),
            [
                "arn:aws:bedrock:*::foundation-model/anthropic.claude-sonnet-4-6",
                "arn:aws:bedrock:*:123456789012:inference-profile/us.anthropic.claude-sonnet-4-6",
            ],
        )

    def test_bedrock_model_ids_are_empty_for_non_bedrock_provider(self) -> None:
        self.assertEqual(
            verify_aws_bedrock_task_role.bedrock_model_ids(
                {"graphAgentLlmProvider": "openrouter", "graphAgentLlmModel": "anthropic/claude-sonnet-4.6"}
            ),
            [],
        )

    def test_verify_skips_without_bedrock_provider(self) -> None:
        with TemporaryDirectory() as raw:
            stack = Path(raw) / "Pulumi.sec-dev.yaml"
            stack.write_text(
                """
config:
  cerebro:graphAgentLlmProvider: openrouter
  cerebro:graphAgentLlmModel: anthropic/claude-sonnet-4.6
""",
                encoding="utf-8",
            )

            with (
                patch.object(verify_aws_bedrock_task_role, "caller_account_id") as caller,
                patch.object(verify_aws_bedrock_task_role, "simulate_role") as simulate,
            ):
                verify_aws_bedrock_task_role.verify_bedrock_permissions(stack)

        caller.assert_not_called()
        simulate.assert_not_called()

    def test_verify_fails_on_denied_decision(self) -> None:
        with TemporaryDirectory() as raw:
            stack = Path(raw) / "Pulumi.sec-dev.yaml"
            stack.write_text(
                """
config:
  cerebro:environment: sec-dev
  cerebro:graphAgentLlmProvider: bedrock
  cerebro:graphAgentLlmModel: us.anthropic.claude-sonnet-4-6
""",
                encoding="utf-8",
            )

            with (
                patch.object(verify_aws_bedrock_task_role, "caller_account_id", return_value="123456789012"),
                patch.object(verify_aws_bedrock_task_role, "bedrock_inline_policy_documents", return_value=[]),
                patch.object(
                    verify_aws_bedrock_task_role,
                    "simulate_role",
                    return_value=[{"Action": "bedrock:InvokeModel", "Decision": "implicitDeny", "Resource": "*"}],
                ),
            ):
                with self.assertRaisesRegex(RuntimeError, "preflight failed"):
                    verify_aws_bedrock_task_role.verify_bedrock_permissions(stack)

    def test_simulate_role_queries_resource_specific_decisions(self) -> None:
        with patch.object(verify_aws_bedrock_task_role, "aws_json", return_value=[]) as aws_json:
            verify_aws_bedrock_task_role.simulate_role(
                None,
                "arn:aws:iam::123456789012:role/cerebro-sec-dev-task-role",
                ["arn:aws:bedrock:*::foundation-model/anthropic.claude-sonnet-4-6"],
            )

        args = aws_json.call_args.args[0]
        query = args[args.index("--query") + 1]
        self.assertIn("ResourceSpecificResults", query)
        self.assertIn("EvalResourceDecision", query)

    def test_verify_fails_on_resource_specific_denied_decision(self) -> None:
        with TemporaryDirectory() as raw:
            stack = Path(raw) / "Pulumi.sec-dev.yaml"
            stack.write_text(
                """
config:
  cerebro:environment: sec-dev
  cerebro:graphAgentLlmProvider: bedrock
  cerebro:graphAgentLlmModel: us.anthropic.claude-sonnet-4-6
""",
                encoding="utf-8",
            )

            with (
                patch.object(verify_aws_bedrock_task_role, "caller_account_id", return_value="123456789012"),
                patch.object(verify_aws_bedrock_task_role, "bedrock_inline_policy_documents", return_value=[]),
                patch.object(
                    verify_aws_bedrock_task_role,
                    "simulate_role",
                    return_value=[
                        {
                            "Action": "bedrock:InvokeModel",
                            "Decision": "allowed",
                            "Resource": "arn:aws:bedrock:*:123456789012:inference-profile/us.anthropic.claude-sonnet-4-6",
                            "ResourceSpecificResults": [
                                {
                                    "Decision": "allowed",
                                    "Resource": "arn:aws:bedrock:*:123456789012:inference-profile/us.anthropic.claude-sonnet-4-6",
                                },
                                {
                                    "Decision": "implicitDeny",
                                    "Resource": "arn:aws:bedrock:*::foundation-model/anthropic.claude-sonnet-4-6",
                                },
                            ],
                        }
                    ],
                ),
            ):
                with self.assertRaisesRegex(RuntimeError, "preflight failed"):
                    verify_aws_bedrock_task_role.verify_bedrock_permissions(stack)

    def test_verify_accepts_inline_bedrock_policy_when_principal_simulation_false_denies(self) -> None:
        with TemporaryDirectory() as raw:
            stack = Path(raw) / "Pulumi.go-prod.yaml"
            stack.write_text(
                """
config:
  cerebro:environment: go-production
  cerebro:orchestratorEnabled: true
  cerebro:graphAgentLlmProvider: bedrock
  cerebro:graphAgentLlmModel: us.anthropic.claude-sonnet-4-6
""",
                encoding="utf-8",
            )

            with (
                patch.object(verify_aws_bedrock_task_role, "caller_account_id", return_value="123456789012"),
                patch.object(
                    verify_aws_bedrock_task_role,
                    "simulate_role",
                    return_value=[{"Action": "bedrock:InvokeModel", "Decision": "implicitDeny", "Resource": "*"}],
                ),
                patch.object(verify_aws_bedrock_task_role, "bedrock_inline_policy_documents", return_value=[{"Statement": []}]),
                patch.object(
                    verify_aws_bedrock_task_role,
                    "simulate_custom_policies",
                    return_value=[
                        {
                            "Action": "bedrock:InvokeModel",
                            "Decision": "allowed",
                            "Resource": "arn:aws:bedrock:*:123456789012:inference-profile/us.anthropic.claude-sonnet-4-6",
                        }
                    ],
                ) as simulate_custom,
            ):
                verify_aws_bedrock_task_role.verify_bedrock_permissions(stack)

        self.assertEqual(simulate_custom.call_count, 2)

    def test_inline_policy_documents_load_only_bedrock_policies(self) -> None:
        bedrock_document = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["bedrock:InvokeModel"], "Resource": "*"}],
        }
        cloudwatch_document = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["cloudwatch:PutMetricData"], "Resource": "*"}],
        }
        with patch.object(
            verify_aws_bedrock_task_role,
            "aws_json",
            side_effect=[
                ["cerebro-go-production-task-cloudwatch", "cerebro-go-production-task-bedrock"],
                bedrock_document,
                cloudwatch_document,
            ],
        ) as aws_json:
            documents = verify_aws_bedrock_task_role.bedrock_inline_policy_documents(
                "writer-sec-prod-us1",
                "arn:aws:iam::123456789012:role/cerebro-go-production-task-role",
            )

        self.assertEqual(documents, [bedrock_document])
        calls = [call.args[0] for call in aws_json.call_args_list]
        self.assertIn("--profile", calls[0])
        self.assertIn("writer-sec-prod-us1", calls[0])

    def test_simulate_custom_policies_queries_resource_specific_decisions(self) -> None:
        with patch.object(verify_aws_bedrock_task_role, "aws_json", return_value=[]) as aws_json:
            verify_aws_bedrock_task_role.simulate_custom_policies(
                None,
                [{"Statement": [{"Effect": "Allow", "Action": ["bedrock:InvokeModel"], "Resource": "*"}]}],
                ["arn:aws:bedrock:*::foundation-model/anthropic.claude-sonnet-4-6"],
            )

        args = aws_json.call_args.args[0]
        query = args[args.index("--query") + 1]
        self.assertIn("simulate-custom-policy", " ".join(args))
        self.assertIn("ResourceSpecificResults", query)


if __name__ == "__main__":
    unittest.main()
