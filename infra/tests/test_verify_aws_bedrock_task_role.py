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


if __name__ == "__main__":
    unittest.main()
