import importlib.util
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("verify_aws_secret_imports", Path(__file__).resolve().parents[1] / "scripts" / "verify_aws_secret_imports.py")
verify_aws_secret_imports = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = verify_aws_secret_imports
spec.loader.exec_module(verify_aws_secret_imports)


class AwsSecretImportsTest(unittest.TestCase):
    def test_expected_imports_use_infisical_prefix_for_runtime_inputs(self) -> None:
        imports = verify_aws_secret_imports.expected_secret_imports(
            {
                "environment": "go-production",
                "apiAuthEnabled": True,
                "infisicalSecretsPrefix": "cerebro-go-production/aws-sync",
                "capabilityTokenSecretName": "CAPABILITY_PROD",
                "sourceSecretKeys": [
                    "SOURCE_TOKEN",
                    {"name": "SOURCE_ALIAS", "source": "SOURCE_CANONICAL", "prefix": "custom-prefix"},
                ],
            },
            "go-prod",
        )

        by_env = {item.env_name: item for item in imports}
        self.assertEqual(by_env["CEREBRO_POSTGRES_DSN"].secret_id, "cerebro-go-production/CEREBRO_POSTGRES_DSN")
        self.assertEqual(by_env["CEREBRO_CAPABILITY_TOKEN_SECRETS"].secret_id, "cerebro-go-production/aws-sync/CAPABILITY_PROD")
        self.assertEqual(by_env["SOURCE_TOKEN"].secret_id, "cerebro-go-production/aws-sync/SOURCE_TOKEN")
        self.assertEqual(by_env["SOURCE_ALIAS"].secret_id, "custom-prefix/SOURCE_CANONICAL")

    def test_expected_imports_include_openrouter_when_configured(self) -> None:
        imports = verify_aws_secret_imports.expected_secret_imports(
            {
                "environment": "sec-dev",
                "graphAgentLlmProvider": "openrouter",
                "openrouterApiKeySecret": "OPENROUTER_RUNTIME_TOKEN",
            },
            "sec-dev",
        )

        by_env = {item.env_name: item for item in imports}
        self.assertEqual(by_env["CEREBRO_OPENROUTER_API_KEY"].secret_id, "cerebro-sec-dev/OPENROUTER_RUNTIME_TOKEN")
        self.assertEqual(by_env["CEREBRO_OPENROUTER_API_KEY"].category, "runtime-import")

    def test_expected_imports_include_otel_collector_config_secret(self) -> None:
        imports = verify_aws_secret_imports.expected_secret_imports(
            {
                "environment": "go-production",
                "infisicalSecretsPrefix": "cerebro-go-production/aws-sync",
                "otelCollectorEnabled": True,
                "otelCollectorConfigSecretName": "CEREBRO_OTEL_COLLECTOR_CONFIG",
            },
            "go-prod",
        )

        by_env = {item.env_name: item for item in imports}
        self.assertEqual(by_env["AOT_CONFIG_CONTENT"].secret_id, "cerebro-go-production/aws-sync/CEREBRO_OTEL_COLLECTOR_CONFIG")
        self.assertEqual(by_env["AOT_CONFIG_CONTENT"].category, "otel-collector")

    def test_missing_env_refs_are_reported_without_names(self) -> None:
        imports = [
            verify_aws_secret_imports.SecretImport(
                env_name="DECLARED",
                source="DECLARED",
                prefix="prefix",
                category="runtime-import",
            )
        ]
        findings = verify_aws_secret_imports.missing_env_ref_findings(
            {"sourceRuntimes": [{"config": {"token": "env:MISSING_SOURCE_TOKEN"}}]},
            imports,
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].reason, "undeclared")
        self.assertNotEqual(findings[0].fingerprint, "MISSING_SOURCE_TOKEN")

    def test_missing_nested_env_refs_are_reported_without_names(self) -> None:
        findings = verify_aws_secret_imports.missing_env_ref_findings(
            {"sourceRuntimes": [{"config": {"auth": {"headers": [{"value": "env:MISSING_NESTED_TOKEN"}]}}}]},
            [],
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].reason, "undeclared")
        self.assertNotEqual(findings[0].fingerprint, "MISSING_NESTED_TOKEN")

    def test_verifier_uses_describe_secret_only(self) -> None:
        commands: list[list[str]] = []

        def fake_run(command, text, capture_output):
            commands.append(command)
            return subprocess.CompletedProcess(
                command,
                0,
                stdout='{"VersionIdsToStages":{"v1":["AWSCURRENT"]}}',
                stderr="",
            )

        with patch.object(verify_aws_secret_imports.subprocess, "run", side_effect=fake_run):
            findings = verify_aws_secret_imports.verify_secret_imports(
                [verify_aws_secret_imports.SecretImport("ENV", "SRC", "prefix", "runtime-import")],
                "us-east-1",
            )

        self.assertEqual(findings, [])
        self.assertEqual(commands[0][0:2], ["aws", "secretsmanager"])
        self.assertIn("describe-secret", commands[0])
        self.assertNotIn("get-secret-value", commands[0])

    def test_missing_secret_is_reported(self) -> None:
        def fake_run(command, text, capture_output):
            return subprocess.CompletedProcess(
                command,
                254,
                stdout="",
                stderr="ResourceNotFoundException: not found",
            )

        with patch.object(verify_aws_secret_imports.subprocess, "run", side_effect=fake_run):
            findings = verify_aws_secret_imports.verify_secret_imports(
                [verify_aws_secret_imports.SecretImport("ENV", "SRC", "prefix", "runtime-import")],
                "us-east-1",
            )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].reason, "missing")

    def test_main_output_omits_secret_names(self) -> None:
        with TemporaryDirectory() as tmp:
            stack = Path(tmp) / "Pulumi.go-prod.yaml"
            stack.write_text(
                """
config:
  cerebro:environment: go-production
  cerebro:apiAuthEnabled: false
  cerebro:sourceSecretKeys:
    - CEREBRO_SOURCE_PRIVATE_TOKEN
""",
                encoding="utf-8",
            )

            def fake_run(command, text, capture_output):
                if "get-caller-identity" in command:
                    return subprocess.CompletedProcess(command, 0, stdout='{"Account":"837279440628"}', stderr="")
                return subprocess.CompletedProcess(command, 254, stdout="", stderr="ResourceNotFoundException")

            with patch.object(verify_aws_secret_imports.subprocess, "run", side_effect=fake_run), patch("builtins.print") as mocked_print:
                exit_code = verify_aws_secret_imports.main(["--stack-file", str(stack)])

        self.assertEqual(exit_code, 1)
        output = "\n".join(str(call.args[0]) for call in mocked_print.call_args_list if call.args)
        self.assertNotIn("CEREBRO_SOURCE_PRIVATE_TOKEN", output)
        self.assertIn("fingerprint", output)


if __name__ == "__main__":
    unittest.main()
