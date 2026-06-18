import importlib.util
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import yaml


spec = importlib.util.spec_from_file_location(
    "provision_otel_collector_config",
    Path(__file__).resolve().parents[1] / "scripts" / "provision_otel_collector_config.py",
)
provision_otel_collector_config = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = provision_otel_collector_config
spec.loader.exec_module(provision_otel_collector_config)


class ProvisionOtelCollectorConfigTest(unittest.TestCase):
    def test_collector_secret_id_uses_infisical_prefix(self) -> None:
        secret_id = provision_otel_collector_config.collector_secret_id(
            {
                "environment": "go-production",
                "infisicalSecretsPrefix": "cerebro-go-production/aws-sync",
                "otelCollectorConfigSecretName": "CEREBRO_OTEL_COLLECTOR_CONFIG",
            },
            "go-prod",
        )

        self.assertEqual(secret_id, "cerebro-go-production/aws-sync/CEREBRO_OTEL_COLLECTOR_CONFIG")

    def test_rendered_config_has_healthcheck_and_aws_exporters(self) -> None:
        rendered = provision_otel_collector_config.render_collector_config("cerebro-sec-dev")
        config = yaml.safe_load(rendered)

        self.assertEqual(config["extensions"]["health_check"]["endpoint"], "127.0.0.1:13133")
        self.assertEqual(
            config["receivers"]["prometheus/internal"]["config"]["scrape_configs"][0]["static_configs"][0]["targets"],
            ["127.0.0.1:8888"],
        )
        self.assertEqual(config["receivers"]["otlp"]["protocols"]["http"]["endpoint"], "127.0.0.1:4318")
        self.assertIn("awsxray", config["exporters"])
        self.assertEqual(config["exporters"]["awsemf"]["namespace"], "Cerebro/OTEL")
        self.assertEqual(config["exporters"]["awsemf"]["log_group_name"], "/aws/otel/cerebro-sec-dev/metrics")
        self.assertEqual(config["service"]["telemetry"]["metrics"]["level"], "detailed")
        self.assertEqual(config["service"]["pipelines"]["traces"]["exporters"], ["awsxray"])
        self.assertEqual(config["service"]["pipelines"]["metrics"]["receivers"], ["otlp", "prometheus/internal"])
        self.assertEqual(config["service"]["pipelines"]["metrics"]["exporters"], ["awsemf"])

    def test_dry_run_prints_config_hash_without_calling_aws(self) -> None:
        with TemporaryDirectory() as tmp:
            stack = Path(tmp) / "Pulumi.sec-dev.yaml"
            stack.write_text(
                """
config:
  cerebro:environment: sec-dev
  cerebro:otelCollectorEnabled: true
  cerebro:otelCollectorConfigSecretName: CEREBRO_OTEL_COLLECTOR_CONFIG
""",
                encoding="utf-8",
            )

            with patch.object(provision_otel_collector_config.subprocess, "run") as mocked_run, patch("builtins.print") as mocked_print:
                exit_code = provision_otel_collector_config.main(["--stack-file", str(stack), "--dry-run"])

        self.assertEqual(exit_code, 0)
        mocked_run.assert_not_called()
        output = "\n".join(str(call.args[0]) for call in mocked_print.call_args_list if call.args)
        self.assertIn("dry-run: collector config ready config_sha256=", output)
        self.assertNotIn("collector_config_secret", output)
        self.assertNotIn("CEREBRO_OTEL_COLLECTOR_CONFIG", output)

    def test_skip_if_disabled_exits_without_calling_aws(self) -> None:
        with TemporaryDirectory() as tmp:
            stack = Path(tmp) / "Pulumi.sec-dev.yaml"
            stack.write_text(
                """
config:
  cerebro:environment: sec-dev
  cerebro:otelCollectorEnabled: false
""",
                encoding="utf-8",
            )

            with patch.object(provision_otel_collector_config.subprocess, "run") as mocked_run, patch("builtins.print") as mocked_print:
                exit_code = provision_otel_collector_config.main(["--stack-file", str(stack), "--skip-if-disabled"])

        self.assertEqual(exit_code, 0)
        mocked_run.assert_not_called()
        mocked_print.assert_called_once_with("skipped: otelCollectorEnabled is not true")

    def test_upsert_updates_existing_secret_from_temp_file(self) -> None:
        commands: list[list[str]] = []

        def fake_run(command, text, capture_output):
            commands.append(command)
            if "describe-secret" in command:
                return subprocess.CompletedProcess(command, 0, stdout="{}", stderr="")
            return subprocess.CompletedProcess(command, 0, stdout="{}", stderr="")

        with patch.object(provision_otel_collector_config.subprocess, "run", side_effect=fake_run):
            status = provision_otel_collector_config.upsert_secret(
                "prefix/CEREBRO_OTEL_COLLECTOR_CONFIG",
                "receivers: {}\n",
                "profile-name",
                "us-east-1",
                dry_run=False,
            )

        self.assertEqual(status, "updated")
        put_command = next(command for command in commands if "put-secret-value" in command)
        self.assertIn("--profile", put_command)
        self.assertIn("profile-name", put_command)
        secret_string_arg = put_command[put_command.index("--secret-string") + 1]
        self.assertTrue(secret_string_arg.startswith("file://"))
        self.assertNotIn("receivers", " ".join(put_command))


if __name__ == "__main__":
    unittest.main()
