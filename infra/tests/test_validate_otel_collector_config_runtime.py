import importlib.util
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "validate_otel_collector_config_runtime",
    Path(__file__).resolve().parents[1] / "scripts" / "validate_otel_collector_config_runtime.py",
)
validate_otel_collector_config_runtime = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = validate_otel_collector_config_runtime
spec.loader.exec_module(validate_otel_collector_config_runtime)


class ValidateOtelCollectorConfigRuntimeTest(unittest.TestCase):
    def test_disabled_stack_skips_without_docker(self) -> None:
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

            with patch.object(validate_otel_collector_config_runtime, "run_command") as run_command:
                result = validate_otel_collector_config_runtime.validate_stack_file(
                    stack,
                    docker_bin="docker",
                    region="us-east-1",
                    timeout_seconds=1,
                )

        self.assertIn("skipped:", result)
        run_command.assert_not_called()

    def test_boots_configured_image_with_rendered_config(self) -> None:
        commands: list[list[str]] = []

        def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
            commands.append(command)
            if command[:2] == ["docker", "run"]:
                return subprocess.CompletedProcess(command, 0, stdout="container-id\n", stderr="")
            if command[:2] == ["docker", "logs"]:
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout=f"{validate_otel_collector_config_runtime.READY_MARKER}\n",
                    stderr="",
                )
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        with TemporaryDirectory() as tmp:
            stack = Path(tmp) / "Pulumi.go-prod.yaml"
            stack.write_text(
                """
config:
  cerebro:environment: go-production
  cerebro:otelCollectorEnabled: true
  cerebro:otelCollectorImage: public.ecr.aws/aws-observability/aws-otel-collector:v0.48.0
""",
                encoding="utf-8",
            )

            with patch.object(validate_otel_collector_config_runtime, "run_command", side_effect=fake_run):
                result = validate_otel_collector_config_runtime.validate_stack_file(
                    stack,
                    docker_bin="docker",
                    region="us-east-1",
                    timeout_seconds=1,
                )

        self.assertIn("validated:", result)
        run_command = next(command for command in commands if command[:2] == ["docker", "run"])
        self.assertIn("public.ecr.aws/aws-observability/aws-otel-collector:v0.48.0", run_command)
        self.assertIn("AWS_REGION=us-east-1", run_command)
        self.assertIn("AWS_EC2_METADATA_DISABLED=true", run_command)
        config_env = next(arg for arg in run_command if arg.startswith("AOT_CONFIG_CONTENT="))
        self.assertIn("health_check:", config_env)
        self.assertIn("endpoint: 127.0.0.1:4318", config_env)
        self.assertTrue(any(command[:3] == ["docker", "rm", "-f"] for command in commands))

    def test_container_exit_before_ready_fails_with_logs(self) -> None:
        def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
            if command[:2] == ["docker", "run"]:
                return subprocess.CompletedProcess(command, 0, stdout="container-id\n", stderr="")
            if command[:2] == ["docker", "logs"]:
                return subprocess.CompletedProcess(command, 0, stdout="invalid keys: address\n", stderr="")
            if command[:2] == ["docker", "inspect"]:
                return subprocess.CompletedProcess(command, 0, stdout="false 1\n", stderr="")
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        with TemporaryDirectory() as tmp:
            stack = Path(tmp) / "Pulumi.sec-dev.yaml"
            stack.write_text(
                """
config:
  cerebro:environment: sec-dev
  cerebro:otelCollectorEnabled: true
  cerebro:otelCollectorImage: public.ecr.aws/aws-observability/aws-otel-collector:v0.48.0
""",
                encoding="utf-8",
            )

            with patch.object(validate_otel_collector_config_runtime, "run_command", side_effect=fake_run):
                with self.assertRaisesRegex(RuntimeError, "invalid keys: address"):
                    validate_otel_collector_config_runtime.validate_stack_file(
                        stack,
                        docker_bin="docker",
                        region="us-east-1",
                        timeout_seconds=1,
                    )


if __name__ == "__main__":
    unittest.main()
