from __future__ import annotations

import unittest
from pathlib import Path
import sys
from unittest.mock import patch

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import scripts.validate_stack_config as validator
from scripts.validate_stack_config import validate_cross_stack, validate_stack


TOKEN_SUFFIX = "TOK" + "EN"
SECRET_SUFFIX = "SEC" + "RET"
COSMO_TOKEN_KEY = "CEREBRO_SOURCE_COSMO_" + TOKEN_SUFFIX
COSMO_WEBHOOK_SECRET_KEY = "CEREBRO_SOURCE_COSMO_WEBHOOK_" + SECRET_SUFFIX
API_TOKEN_KEY = "API_" + TOKEN_SUFFIX
TOKEN_FIELD = "tok" + "en"
API_TOKEN_FIELD = "api_" + "token"
WEBHOOK_SECRET_FIELD = "webhook_" + "secret"

COSMO_SECRET_KEYS = f"""\
    - CEREBRO_SOURCE_COSMO_BASE_URL
    - CEREBRO_SOURCE_COSMO_EXPORT_{SECRET_SUFFIX}
    - {COSMO_TOKEN_KEY}
"""

COSMO_SCHEDULES = """\
    - name: cosmo-session
      scheduleExpression: cron(2,32 * * * ? *)
      taskCount: 1
      command:
        - orchestrator
        - run
        - runtime_id=writer-cosmo-session
    - name: cosmo-fact
      scheduleExpression: cron(12,42 * * * ? *)
      taskCount: 1
      command:
        - orchestrator
        - run
        - runtime_id=writer-cosmo-fact
    - name: cosmo-message
      scheduleExpression: cron(22,52 * * * ? *)
      taskCount: 1
      command:
        - orchestrator
        - run
        - runtime_id=writer-cosmo-message
    - name: cosmo-survey-feedback
      scheduleExpression: cron(7,37 * * * ? *)
      taskCount: 1
      command:
        - orchestrator
        - run
        - runtime_id=writer-cosmo-survey-feedback
"""

COSMO_RUNTIMES = f"""\
    - id: writer-cosmo-session
      sourceId: cosmo
      tenantId: writer
      config:
        base_url: env:CEREBRO_SOURCE_COSMO_BASE_URL
        family: session
        per_page: "100"
        tenant_id: writer
        {TOKEN_FIELD}: env:{COSMO_TOKEN_KEY}
    - id: writer-cosmo-fact
      sourceId: cosmo
      tenantId: writer
      config:
        base_url: env:CEREBRO_SOURCE_COSMO_BASE_URL
        family: fact
        per_page: "100"
        tenant_id: writer
        {TOKEN_FIELD}: env:{COSMO_TOKEN_KEY}
    - id: writer-cosmo-message
      sourceId: cosmo
      tenantId: writer
      config:
        base_url: env:CEREBRO_SOURCE_COSMO_BASE_URL
        client_id: cerebro-runtime
        event_types: "message,completion"
        export_secret: env:CEREBRO_SOURCE_COSMO_EXPORT_{SECRET_SUFFIX}
        family: message
        max_window_hours: "24"
        per_page: "100"
        since: "2026-01-01T00:00:00Z"
        tenant_id: writer
        {TOKEN_FIELD}: env:{COSMO_TOKEN_KEY}
    - id: writer-cosmo-survey-feedback
      sourceId: cosmo
      tenantId: writer
      config:
        base_url: env:CEREBRO_SOURCE_COSMO_BASE_URL
        family: survey_feedback
        per_page: "100"
        tenant_id: writer
        {TOKEN_FIELD}: env:{COSMO_TOKEN_KEY}
"""

BASE_STACK = f"""
config:
  cerebro:environment: go-production
  cerebro:ecrBaseUri: 123456789012.dkr.ecr.us-east-1.amazonaws.com/cerebro
  cerebro:imageTag: v2.1.36
  cerebro:apiMaxInstances: 2
  cerebro:natsCpu: 2048
  cerebro:natsMemory: 32768
  cerebro:jetstreamPublishMaxInFlight: 4
  cerebro:jetstreamPublishRetryMaxElapsed: 5m
  cerebro:natsEfsThroughputMode: elastic
  cerebro:postgresDeletionProtection: true
  cerebro:postgresBackupRetentionDays: 14
  cerebro:apiAuthEnabled: true
  cerebro:allowedTenants:
    - writer
  cerebro:alarmActionArns:
    - arn:aws:sns:us-east-1:123456789012:cerebro-alerts
  cerebro:sourceSecretKeys:
{COSMO_SECRET_KEYS.rstrip()}
    - {API_TOKEN_KEY}
    - CEREBRO_SOURCE_PANOPTICON_BASE_URL
    - CEREBRO_SOURCE_PANOPTICON_PRIVATE_ENDPOINT_ALLOWLIST
    - CEREBRO_SOURCE_PANOPTICON_TOKEN
  cerebro:sourceRuntimeObservability:
    - environment: go-production
      sourceSystem: evidence_cas
      sourceRuntimeId: writer-evidence-cas-cases
      runtimeClass: object
      enabled: false
      freshnessSlaMinutes: 120
      logGroupRef: runtime
      dashboardEnabled: false
      alarmEnabled: false
      alarmRoute: default
      observabilityStates:
        - success
        - failure
        - stale
        - disabled
        - unknown
        - not_configured
    - environment: go-production
      sourceSystem: panopticon
      sourceRuntimeId: writer-panopticon-alerts
      runtimeClass: alert
      enabled: true
      freshnessSlaMinutes: 30
      logGroupRef: runtime
      dashboardEnabled: true
      alarmEnabled: true
      alarmRoute: default
      observabilityStates:
        - success
        - failure
        - stale
        - disabled
        - unknown
        - not_configured
    - environment: go-production
      sourceSystem: panopticon
      sourceRuntimeId: writer-panopticon-cases
      runtimeClass: case
      enabled: true
      freshnessSlaMinutes: 30
      logGroupRef: runtime
      dashboardEnabled: true
      alarmEnabled: true
      alarmRoute: default
      observabilityStates:
        - success
        - failure
        - stale
        - disabled
        - unknown
        - not_configured
    - environment: go-production
      sourceSystem: panopticon
      sourceRuntimeId: writer-panopticon-iocs
      runtimeClass: ioc
      enabled: true
      freshnessSlaMinutes: 30
      logGroupRef: runtime
      dashboardEnabled: true
      alarmEnabled: true
      alarmRoute: default
      observabilityStates:
        - success
        - failure
        - stale
        - disabled
        - unknown
        - not_configured
  cerebro:orchestratorSchedules:
{COSMO_SCHEDULES.rstrip()}
    - name: okta-audit
      scheduleExpression: cron(0 * * * ? *)
      taskCount: 1
      command:
        - orchestrator
        - run
        - runtime_id=writer-okta-audit
    - name: panopticon-alerts-live
      scheduleExpression: rate(15 minutes)
      taskCount: 1
      command:
        - orchestrator
        - run
        - runtime_id=writer-panopticon-alerts
    - name: panopticon-cases-live
      scheduleExpression: rate(15 minutes)
      taskCount: 1
      command:
        - orchestrator
        - run
        - runtime_id=writer-panopticon-cases
    - name: panopticon-iocs-live
      scheduleExpression: rate(15 minutes)
      taskCount: 1
      command:
        - orchestrator
        - run
        - runtime_id=writer-panopticon-iocs
  cerebro:s3Sources: []
  cerebro:sourceRuntimes:
{COSMO_RUNTIMES.rstrip()}
    - id: writer-okta-audit
      sourceId: okta
      tenantId: writer
      config:
        {API_TOKEN_FIELD}: env:{API_TOKEN_KEY}
    - id: writer-panopticon-alerts
      sourceId: panopticon
      tenantId: writer
      config:
        base_url: env:CEREBRO_SOURCE_PANOPTICON_BASE_URL
        family: alert
        mode: api
        page_size: "100"
        private_endpoint_allowlist: env:CEREBRO_SOURCE_PANOPTICON_PRIVATE_ENDPOINT_ALLOWLIST
        runtime_id: writer-panopticon-alerts
        tenant_id: writer
        token: env:CEREBRO_SOURCE_PANOPTICON_TOKEN
    - id: writer-panopticon-cases
      sourceId: panopticon
      tenantId: writer
      config:
        base_url: env:CEREBRO_SOURCE_PANOPTICON_BASE_URL
        family: case
        mode: api
        page_size: "100"
        private_endpoint_allowlist: env:CEREBRO_SOURCE_PANOPTICON_PRIVATE_ENDPOINT_ALLOWLIST
        runtime_id: writer-panopticon-cases
        tenant_id: writer
        token: env:CEREBRO_SOURCE_PANOPTICON_TOKEN
    - id: writer-panopticon-iocs
      sourceId: panopticon
      tenantId: writer
      config:
        base_url: env:CEREBRO_SOURCE_PANOPTICON_BASE_URL
        family: ioc
        mode: api
        page_size: "100"
        private_endpoint_allowlist: env:CEREBRO_SOURCE_PANOPTICON_PRIVATE_ENDPOINT_ALLOWLIST
        runtime_id: writer-panopticon-iocs
        tenant_id: writer
        token: env:CEREBRO_SOURCE_PANOPTICON_TOKEN
"""


class ValidateStackConfigTest(unittest.TestCase):
    def _config(self, content: str) -> dict:
        loaded = yaml.safe_load(content) or {}
        return {
            key.removeprefix("cerebro:"): value
            for key, value in loaded["config"].items()
            if isinstance(key, str) and key.startswith("cerebro:")
        }

    def _validate(self, content: str, name: str = "Pulumi.go-prod.yaml"):
        with patch.object(validator, "_load_config", return_value=self._config(content)):
            return validate_stack(Path(name))

    def _messages(self, content: str) -> list[str]:
        return [finding.message for finding in self._validate(content)]

    def _repo_stack_content(self, name: str) -> str:
        return (Path(__file__).resolve().parents[1] / "aws" / name).read_text(encoding="utf-8")

    def _panopticon_error_messages(self, content: str, name: str) -> list[str]:
        return [
            finding.message
            for finding in self._validate(content, name=name)
            if finding.severity == "error" and "Panopticon" in finding.message
        ]

    def _without_orchestrator_schedules(self, content: str) -> str:
        start = "  cerebro:orchestratorSchedules:\n"
        begin = content.index(start)
        end = content.index("  cerebro:sourceRuntimes:\n", begin)
        return content[:begin] + content[end:]

    def test_valid_stack_has_no_errors(self) -> None:
        findings = self._validate(BASE_STACK)
        self.assertEqual([finding for finding in findings if finding.severity == "error"], [])

    def test_orchestrator_schedule_rule_names_must_fit_eventbridge_limit(self) -> None:
        content = BASE_STACK.replace(
            "    - name: okta-audit\n",
            "    - name: gcp-prod-writer-iam-audit-inventory\n",
        )

        self.assertTrue(
            any(
                finding.severity == "error"
                and finding.path.endswith(".name")
                and "orchestrator schedule resource name" in finding.message
                and "at most 64 characters" in finding.message
                for finding in self._validate(content)
            )
        )

    def test_go_prod_orchestrator_schedule_count_must_fit_eventbridge_quota(self) -> None:
        schedules = "  cerebro:orchestratorSchedules:\n" + "".join(
            f"""    - name: bulk-{index}
      scheduleExpression: rate(1 hour)
      taskCount: 1
      command:
        - orchestrator
        - run
        - runtime_id=writer-okta-audit
"""
            for index in range(295)
        )
        content = self._without_orchestrator_schedules(BASE_STACK).replace(
            "  cerebro:sourceRuntimes:\n",
            schedules + "  cerebro:sourceRuntimes:\n",
        )

        self.assertTrue(
            any(
                finding.severity == "error"
                and finding.path == "cerebro:orchestratorSchedules"
                and "exceeds EventBridge rule capacity" in finding.message
                for finding in self._validate(content)
            )
        )

    def test_service_bootstrap_ids_must_reference_source_runtimes(self) -> None:
        content = BASE_STACK.replace(
            "  cerebro:orchestratorSchedules:",
            "  cerebro:sourceRuntimeServiceBootstrapIds:\n    - writer-missing-runtime\n  cerebro:orchestratorSchedules:",
        )

        self.assertTrue(any("unknown runtime id 'writer-missing-runtime'" in message for message in self._messages(content)))

    def test_service_bootstrap_ids_must_be_a_list(self) -> None:
        content = BASE_STACK.replace(
            "  cerebro:orchestratorSchedules:",
            "  cerebro:sourceRuntimeServiceBootstrapIds: writer-okta-audit\n  cerebro:orchestratorSchedules:",
        )

        self.assertTrue(any("sourceRuntimeServiceBootstrapIds" in finding.path and "must be a list" in finding.message for finding in self._validate(content)))

    def test_actual_source_runtime_observability_has_no_errors(self) -> None:
        for stack_file in ("Pulumi.sec-dev.yaml", "Pulumi.go-prod.yaml"):
            with self.subTest(stack_file=stack_file):
                findings = validate_stack(Path(__file__).resolve().parents[1] / "aws" / stack_file)
                self.assertFalse(
                    any(
                        finding.severity == "error" and "observability" in finding.message.lower()
                        for finding in findings
                    )
                )

    def test_actual_okta_source_runtime_observability_is_required(self) -> None:
        for stack_file in ("Pulumi.sec-dev.yaml", "Pulumi.go-prod.yaml"):
            with self.subTest(stack_file=stack_file):
                content = self._repo_stack_content(stack_file).replace(
                    "      sourceRuntimeId: writer-okta-user\n",
                    "      sourceRuntimeId: writer-okta-user-missing\n",
                    1,
                )
                findings = self._validate(content, name=stack_file)

                self.assertTrue(
                    any(
                        finding.severity == "error"
                        and "source runtime observability entry for okta/user (writer-okta-user) is missing" in finding.message
                        for finding in findings
                    )
                )

    def test_source_runtime_observability_missing_required_field_is_error(self) -> None:
        content = BASE_STACK.replace("      logGroupRef: runtime\n", "", 1)
        findings = self._validate(content, name="Pulumi.go-prod.yaml")

        self.assertTrue(
            any(
                finding.severity == "error"
                and finding.path.endswith(".logGroupRef")
                and "source runtime observability" in finding.message
                for finding in findings
            )
        )

    def test_source_runtime_observability_enabled_runtime_must_exist(self) -> None:
        content = BASE_STACK.replace("sourceRuntimeId: writer-panopticon-alerts", "sourceRuntimeId: writer-panopticon-missing", 1)
        findings = self._validate(content, name="Pulumi.go-prod.yaml")

        self.assertTrue(
            any(
                finding.severity == "error"
                and "must reference a configured source runtime when enabled" in finding.message
                for finding in findings
            )
        )

    def test_source_runtime_observability_state_model_is_consistent(self) -> None:
        content = BASE_STACK.replace("        - not_configured\n", "        - unexpected\n", 1)
        findings = self._validate(content, name="Pulumi.go-prod.yaml")

        self.assertTrue(
            any(
                finding.severity == "error"
                and "must use the shared contract probe status model" in finding.message
                for finding in findings
            )
        )

    def test_actual_panopticon_wiring_has_no_errors(self) -> None:
        for stack_file in ("Pulumi.sec-dev.yaml", "Pulumi.go-prod.yaml"):
            with self.subTest(stack_file=stack_file):
                content = self._repo_stack_content(stack_file)
                self.assertEqual(self._panopticon_error_messages(content, stack_file), [])

    def test_panopticon_s3_source_is_error(self) -> None:
        content = self._repo_stack_content("Pulumi.sec-dev.yaml").replace(
            "  cerebro:s3Sources:\n",
            "  cerebro:s3Sources:\n"
            "    - name: panopticon\n"
            "      bucket: panopticon-dev-944130631940-cerebro-export\n"
            "      region: us-east-1\n"
            "      prefixes:\n"
            "        - exports/alerts/\n",
            1,
        )

        messages = self._panopticon_error_messages(content, "Pulumi.sec-dev.yaml")

        self.assertTrue(any("must not declare an s3Sources entry named 'panopticon'" in message for message in messages))

    def test_panopticon_source_runtime_is_required(self) -> None:
        content = self._repo_stack_content("Pulumi.go-prod.yaml").replace(
            "    - id: writer-panopticon-alerts\n",
            "    - id: writer-panopticon-alerts-disabled\n",
            1,
        )

        messages = self._panopticon_error_messages(content, "Pulumi.go-prod.yaml")

        self.assertIn("required Panopticon runtime 'writer-panopticon-alerts' is missing", messages)

    def test_panopticon_api_env_refs_are_exact(self) -> None:
        content = self._repo_stack_content("Pulumi.sec-dev.yaml").replace(
            "        base_url: env:CEREBRO_SOURCE_PANOPTICON_BASE_URL\n",
            "        base_url: https://panopticon.example.com\n",
            1,
        )

        messages = self._panopticon_error_messages(content, "Pulumi.sec-dev.yaml")

        self.assertTrue(any("base_url must be 'env:CEREBRO_SOURCE_PANOPTICON_BASE_URL'" in message for message in messages))

    def test_panopticon_runtime_family_must_match_id(self) -> None:
        content = self._repo_stack_content("Pulumi.sec-dev.yaml").replace(
            "        family: alert\n",
            "        family: case\n",
            1,
        )

        messages = self._panopticon_error_messages(content, "Pulumi.sec-dev.yaml")

        self.assertTrue(any("Panopticon alert API runtime family must be 'alert'" in message for message in messages))

    def test_panopticon_schedule_task_count_must_be_one(self) -> None:
        content = self._repo_stack_content("Pulumi.go-prod.yaml").replace(
            "    - name: panopticon-alerts-live\n      scheduleExpression: rate(15 minutes)\n      taskCount: 1\n",
            "    - name: panopticon-alerts-live\n      scheduleExpression: rate(15 minutes)\n      taskCount: 2\n",
            1,
        )

        messages = self._panopticon_error_messages(content, "Pulumi.go-prod.yaml")

        self.assertTrue(any("Panopticon schedules must set taskCount: 1" in message for message in messages))

    def test_panopticon_duplicate_schedule_is_error(self) -> None:
        schedule = """\
    - name: panopticon-alerts-live
      scheduleExpression: rate(15 minutes)
      taskCount: 1
      command:
        - orchestrator
        - run
        - runtime_id=writer-panopticon-alerts
"""
        duplicate_schedule = schedule + schedule.replace("panopticon-alerts-live", "panopticon-alerts-shadow", 1)
        content = self._repo_stack_content("Pulumi.go-prod.yaml").replace(schedule, duplicate_schedule, 1)

        messages = self._panopticon_error_messages(content, "Pulumi.go-prod.yaml")

        self.assertIn("Panopticon runtime 'writer-panopticon-alerts' must have exactly one schedule", messages)

    def test_panopticon_rejects_secrets_and_evidence_bytes_in_runtime_config(self) -> None:
        content = self._repo_stack_content("Pulumi.sec-dev.yaml").replace(
            "        tenant_id: writer\n        token: env:CEREBRO_SOURCE_PANOPTICON_TOKEN\n    - id: writer-panopticon-cases\n",
            "        tenant_id: writer\n        evidence_bytes: inline-forbidden\n        token: env:CEREBRO_SOURCE_PANOPTICON_TOKEN\n    - id: writer-panopticon-cases\n",
            1,
        )

        messages = self._panopticon_error_messages(content, "Pulumi.sec-dev.yaml")

        self.assertTrue(any("unsupported keys ['evidence_bytes']" in message for message in messages))
        self.assertTrue(any("must not include secrets, tokens, or evidence bytes" in message for message in messages))

    def test_latency_alarm_thresholds_must_be_non_negative(self) -> None:
        content = BASE_STACK + "  cerebro:dashboardLatencyP95AlarmThresholdMs: -1\n"
        self.assertTrue(any("must be a non-negative integer" in message for message in self._messages(content)))

    def test_service_quota_alarm_threshold_must_be_non_negative(self) -> None:
        content = BASE_STACK + "  cerebro:awsServiceQuotaAlarmThresholdPercent: -1\n"
        self.assertTrue(any("awsServiceQuotaAlarmThresholdPercent" in finding.path for finding in self._validate(content)))

    def test_monthly_cost_budget_must_be_non_negative(self) -> None:
        content = BASE_STACK + "  cerebro:monthlyCostBudgetLimitUsd: -1\n"
        self.assertTrue(any("monthlyCostBudgetLimitUsd" in finding.path for finding in self._validate(content)))

    def test_otel_enabled_requires_exporter_endpoint(self) -> None:
        content = BASE_STACK + "  cerebro:otelEnabled: true\n"
        self.assertTrue(any("otelEnabled requires an OTLP endpoint" in message for message in self._messages(content)))

    def test_otel_rejects_inline_headers_and_bad_sample_rate(self) -> None:
        content = BASE_STACK + (
            "  cerebro:otelExporterOtlpProtocol: zipkin\n"
            "  cerebro:otelTracesSampleRate: 1.5\n"
            "  cerebro:otelExporterOtlpHeadersSecretName: api-key=secret\n"
            "  cerebro:otelExporterOtlpHeaders: api-key=secret\n"
        )
        messages = self._messages(content)
        self.assertTrue(any("OTLP protocol must be http/protobuf or grpc" in message for message in messages))
        self.assertTrue(any("sample rate must be a number from 0 to 1" in message for message in messages))
        self.assertTrue(any("provided by secret name" in message for message in messages))
        self.assertTrue(any("plain OTLP header config is forbidden" in message for message in messages))

    def test_otel_accepts_endpoint_secret_and_fractional_sample_rate(self) -> None:
        content = BASE_STACK + (
            "  cerebro:otelEnabled: true\n"
            "  cerebro:otelExporterOtlpProtocol: http/protobuf\n"
            "  cerebro:otelExporterOtlpEndpoint: https://otel-collector.example.test\n"
            "  cerebro:otelExporterOtlpHeadersSecretName: CEREBRO_OTEL_EXPORTER_OTLP_HEADERS\n"
            "  cerebro:otelTracesSampleRate: 0.25\n"
        )
        self.assertFalse(any("otel" in finding.path and finding.severity == "error" for finding in self._validate(content)))

    def test_otel_rejects_plain_http_remote_endpoint(self) -> None:
        content = BASE_STACK + (
            "  cerebro:otelEnabled: true\n"
            "  cerebro:otelExporterOtlpProtocol: http/protobuf\n"
            "  cerebro:otelExporterOtlpEndpoint: http://otel-collector.example.test:4318\n"
            "  cerebro:otelExporterOtlpInsecure: true\n"
        )
        self.assertTrue(any("plain HTTP OTLP endpoints are only allowed for loopback collectors" in message for message in self._messages(content)))

    def test_otel_accepts_loopback_http_endpoint_with_insecure(self) -> None:
        content = BASE_STACK + (
            "  cerebro:otelEnabled: true\n"
            "  cerebro:otelExporterOtlpProtocol: http/protobuf\n"
            "  cerebro:otelExporterOtlpEndpoint: http://127.0.0.1:4318\n"
            "  cerebro:otelExporterOtlpInsecure: true\n"
        )
        self.assertFalse(any("otel" in finding.path and finding.severity == "error" for finding in self._validate(content)))

    def test_otel_collector_requires_image_and_config_secret(self) -> None:
        content = BASE_STACK + "  cerebro:otelCollectorEnabled: true\n"
        messages = self._messages(content)
        self.assertTrue(any("otelCollectorImage is required" in message for message in messages))
        self.assertTrue(any("otelCollectorConfigSecretName is required" in message for message in messages))
        self.assertFalse(any("otelEnabled requires an OTLP endpoint" in message for message in messages))

    def test_otel_collector_accepts_sidecar_config(self) -> None:
        content = BASE_STACK + (
            "  cerebro:otelCollectorEnabled: true\n"
            "  cerebro:otelCollectorImage: public.ecr.aws/aws-observability/aws-otel-collector:v0.48.0\n"
            "  cerebro:otelCollectorConfigSecretName: CEREBRO_OTEL_COLLECTOR_CONFIG\n"
        )
        self.assertFalse(any("otel" in finding.path and finding.severity == "error" for finding in self._validate(content)))

    def test_otel_collector_rejects_app_headers_secret(self) -> None:
        content = BASE_STACK + (
            "  cerebro:otelCollectorEnabled: true\n"
            "  cerebro:otelCollectorImage: public.ecr.aws/aws-observability/aws-otel-collector:v0.48.0\n"
            "  cerebro:otelCollectorConfigSecretName: CEREBRO_OTEL_COLLECTOR_CONFIG\n"
            "  cerebro:otelExporterOtlpHeadersSecretName: CEREBRO_OTEL_EXPORTER_OTLP_HEADERS\n"
        )
        self.assertTrue(any("ignored when otelCollectorEnabled is true" in message for message in self._messages(content)))

    def test_otel_accepts_string_sample_rate_from_pulumi_config(self) -> None:
        content = BASE_STACK + '  cerebro:otelTracesSampleRate: "0.25"\n'
        self.assertFalse(any("otelTracesSampleRate" in finding.path for finding in self._validate(content)))

    def test_orchestrator_buffer_requires_step_functions(self) -> None:
        content = BASE_STACK + "  cerebro:orchestratorSqsBufferEnabled: true\n"
        self.assertTrue(any("requires orchestratorStepFunctionsEnabled" in message for message in self._messages(content)))

    def test_orchestrator_buffer_requires_enabled_orchestrator(self) -> None:
        content = BASE_STACK + (
            "  cerebro:orchestratorStepFunctionsEnabled: true\n"
            "  cerebro:orchestratorSqsBufferEnabled: true\n"
        )
        self.assertTrue(any("requires orchestratorEnabled" in message for message in self._messages(content)))

    def test_orchestrator_buffer_pipe_state_must_be_known(self) -> None:
        content = BASE_STACK + "  cerebro:orchestratorSqsBufferPipeState: PAUSED\n"
        self.assertTrue(any("must be RUNNING or STOPPED" in message for message in self._messages(content)))

    def test_orchestrator_buffer_pipe_state_must_be_canonical(self) -> None:
        content = BASE_STACK + "  cerebro:orchestratorSqsBufferPipeState: running\n"
        self.assertTrue(any("must be RUNNING or STOPPED" in message for message in self._messages(content)))

    def test_synthetics_canary_start_requires_enabled_canary(self) -> None:
        content = BASE_STACK + "  cerebro:syntheticsCanaryStart: true\n"
        self.assertTrue(any("requires syntheticsCanaryEnabled" in message for message in self._messages(content)))

    def test_cloudtrail_log_group_rejects_whitespace(self) -> None:
        content = BASE_STACK + "  cerebro:cloudTrailAuditLogGroupName: invalid log group\n"
        self.assertTrue(any("cloudTrailAuditLogGroupName" in finding.path for finding in self._validate(content)))

    def test_orchestrator_schedule_state_must_be_known(self) -> None:
        content = BASE_STACK.replace(
            "    - name: cosmo-session\n",
            "    - name: cosmo-session\n      state: PAUSED\n",
            1,
        )
        self.assertTrue(any("schedule state must be ENABLED or DISABLED" in message for message in self._messages(content)))

    def test_openrouter_provider_requires_explicit_model(self) -> None:
        content = BASE_STACK + "  cerebro:graphAgentLlmProvider: openrouter\n"
        self.assertTrue(any("OpenRouter provider must set an explicit OpenRouter model id" in message for message in self._messages(content)))
        self.assertTrue(any("OpenRouter provider must declare the API key secret import" in message for message in self._messages(content)))

    def test_openrouter_provider_rejects_anthropic_dated_model_id(self) -> None:
        content = BASE_STACK + (
            "  cerebro:graphAgentLlmProvider: openrouter\n"
            "  cerebro:graphAgentLlmModel: anthropic/claude-sonnet-4-20250514\n"
        )
        self.assertTrue(any("not an Anthropic dated model id" in message for message in self._messages(content)))

    def test_openrouter_provider_accepts_openrouter_slug(self) -> None:
        content = BASE_STACK + (
            "  cerebro:graphAgentLlmProvider: openrouter\n"
            "  cerebro:graphAgentLlmModel: anthropic/claude-sonnet-4.6\n"
            "  cerebro:openrouterApiKeySecret: CEREBRO_OPENROUTER_API_KEY\n"
        )
        self.assertFalse(any("OpenRouter model" in message for message in self._messages(content)))
        self.assertFalse(any("OpenRouter provider must declare the API key secret import" in message for message in self._messages(content)))

    def test_bedrock_provider_requires_model_and_region(self) -> None:
        content = BASE_STACK + "  cerebro:graphAgentLlmProvider: bedrock\n"
        messages = self._messages(content)
        self.assertTrue(any("Bedrock provider must set an explicit Bedrock model" in message for message in messages))
        self.assertTrue(any("Bedrock provider must set the runtime AWS region" in message for message in messages))

    def test_bedrock_provider_rejects_openrouter_slug(self) -> None:
        content = BASE_STACK + (
            "  cerebro:graphAgentLlmProvider: bedrock\n"
            "  cerebro:graphAgentLlmModel: anthropic/claude-sonnet-4.6\n"
            "  cerebro:bedrockRegion: us-east-1\n"
        )
        self.assertTrue(any("not an OpenRouter slug" in message for message in self._messages(content)))

    def test_bedrock_provider_accepts_inference_profile(self) -> None:
        content = BASE_STACK + (
            "  cerebro:graphAgentLlmProvider: bedrock\n"
            "  cerebro:graphAgentLlmModel: us.anthropic.claude-sonnet-4-6\n"
            "  cerebro:bedrockRegion: us-east-1\n"
        )
        messages = self._messages(content)
        self.assertFalse(any("Bedrock provider" in message for message in messages))
        self.assertFalse(any("Bedrock model" in message for message in messages))

    def test_missing_source_secret_is_error(self) -> None:
        content = BASE_STACK.replace(f"    - {API_TOKEN_KEY}\n", "")
        self.assertTrue(any("not listed in cerebro:sourceSecretKeys" in message for message in self._messages(content)))

    def test_nested_source_secret_ref_must_be_declared(self) -> None:
        content = BASE_STACK.replace(
            f"        {API_TOKEN_FIELD}: env:{API_TOKEN_KEY}",
            "        auth:\n          token: env:MISSING_NESTED_TOKEN",
        )

        self.assertTrue(any("not listed in cerebro:sourceSecretKeys" in message for message in self._messages(content)))

    def test_nested_plaintext_secret_like_runtime_config_is_error(self) -> None:
        content = BASE_STACK.replace(
            f"        {API_TOKEN_FIELD}: env:{API_TOKEN_KEY}",
            "        auth:\n          token: inline-private-value",
        )

        findings = self._validate(content)

        self.assertTrue(
            any(
                finding.severity == "error"
                and finding.path.endswith(".config.auth.token")
                and "secret-like runtime config values" in finding.message
                for finding in findings
            )
        )

    def test_s3_source_child_prefix_requires_configured_role(self) -> None:
        content = BASE_STACK.replace(
            "  cerebro:s3Sources: []",
            """  cerebro:s3Sources:
    - name: objectlogs
      bucket: writer-object-logs
      region: us-east-1
      roleArn: arn:aws:iam::837279440628:role/objectlogs-reader
      prefixes:
        - logs/""",
            1,
        ).replace(
            "  cerebro:sourceRuntimes:\n",
            """  cerebro:sourceRuntimes:
    - id: writer-objectlogs
      sourceId: s3ndjson
      tenantId: writer
      config:
        bucket: writer-object-logs
        prefix: logs/daily/
        role_arn: arn:aws:iam::837279440628:role/other-reader
        tenant_id: writer
""",
            1,
        )

        self.assertTrue(any("must set role_arn to the configured s3Sources roleArn" in message for message in self._messages(content)))

    def test_source_runtime_lifecycle_state_is_typed(self) -> None:
        content = BASE_STACK.replace("      sourceId: okta", "      lifecycleState: paused\n      sourceId: okta", 1)

        self.assertTrue(any("lifecycleState must be one of" in message for message in self._messages(content)))

    def test_quarantined_lifecycle_state_cannot_be_active_runtime(self) -> None:
        content = BASE_STACK.replace("      sourceId: okta", "      lifecycleState: quarantined\n      sourceId: okta", 1)

        self.assertTrue(any("quarantined runtimes must be removed" in message for message in self._messages(content)))

    def test_temporary_runtime_metadata_lifecycle_state_must_be_quarantined(self) -> None:
        content = BASE_STACK.replace(
            "  cerebro:sourceRuntimeObservability:",
            """  cerebro:temporarilyDisabledSourceRuntimes:
    - runtimeId: writer-cosmo-session
      owner: cerebro-platform
      reason: invalid_credentials
      disabledDate: "2026-06-10"
      reviewDeadline: "2026-07-10"
      reenableCriteria: "Rotate token and pass live verification."
      lifecycleState: active
  cerebro:sourceRuntimeObservability:""",
            1,
        )

        self.assertTrue(any("temporary runtime metadata must use lifecycleState quarantined" in message for message in self._messages(content)))

    def test_aws_role_arn_account_must_match_runtime_account(self) -> None:
        aws_stack = BASE_STACK.replace("sourceId: okta", "sourceId: aws").replace(
            f"        {API_TOKEN_FIELD}: env:{API_TOKEN_KEY}",
            "        account_id: \"123456789012\"\n        role_arn: arn:aws:iam::210987654321:role/cerebro-org-scan-role",
        )
        self.assertTrue(any("account must match account_id" in message for message in self._messages(aws_stack)))

    def test_unknown_scheduled_runtime_is_error(self) -> None:
        content = BASE_STACK.replace("runtime_id=writer-okta-audit", "runtime_id=writer-missing")
        self.assertTrue(any("unknown runtime id" in message for message in self._messages(content)))

    def test_unscheduled_source_runtime_is_error(self) -> None:
        content = (
            BASE_STACK
            + """    - id: writer-okta-user
      sourceId: okta
      tenantId: writer
      config:
        api_token: env:API_TOKEN
"""
        )
        self.assertTrue(
            any("is not referenced by cerebro:orchestratorCommand" in message for message in self._messages(content))
        )

    def test_global_orchestrator_command_covers_source_runtimes(self) -> None:
        content = (
            self._without_orchestrator_schedules(BASE_STACK).replace(
                "  cerebro:sourceRuntimes:",
                "  cerebro:orchestratorCommand:\n    - orchestrator\n    - run\n  cerebro:sourceRuntimes:",
            )
            + """    - id: writer-okta-user
      sourceId: okta
      tenantId: writer
      config:
        api_token: env:API_TOKEN
"""
        )
        messages = self._messages(content)
        self.assertFalse(
            any("is not referenced by cerebro:orchestratorCommand" in message for message in messages)
        )

    def test_global_orchestrator_command_does_not_cover_custom_schedules(self) -> None:
        content = (
            BASE_STACK.replace(
                "  cerebro:orchestratorSchedules:",
                "  cerebro:orchestratorCommand:\n    - orchestrator\n    - run\n  cerebro:orchestratorSchedules:",
            )
            + """    - id: writer-okta-user
      sourceId: okta
      tenantId: writer
      config:
        api_token: env:API_TOKEN
"""
        )
        messages = self._messages(content)
        self.assertTrue(
            any("source runtime 'writer-okta-user' is not referenced" in message for message in messages)
        )

    def test_unknown_top_level_orchestrator_runtime_is_error(self) -> None:
        content = BASE_STACK.replace(
            "  cerebro:orchestratorSchedules:",
            "  cerebro:orchestratorCommand:\n    - orchestrator\n    - run\n    - runtime_id=writer-missing\n  cerebro:orchestratorSchedules:",
        )
        self.assertTrue(any("unknown runtime id" in message for message in self._messages(content)))

    def test_sec_dev_high_contention_schedule_graph_page_limit_is_bounded(self) -> None:
        content = BASE_STACK.replace(
            "        - runtime_id=writer-okta-audit\n",
            "        - runtime_id=writer-okta-audit\n        - graph_page_limit=100\n",
        )
        findings = self._validate(content, name="Pulumi.sec-dev.yaml")
        self.assertTrue(any(finding.severity == "error" and "graph_page_limit <= 5" in finding.message for finding in findings))

    def test_sec_dev_high_contention_schedule_page_limit_is_bounded(self) -> None:
        content = BASE_STACK.replace(
            "        - runtime_id=writer-okta-audit\n",
            "        - runtime_id=writer-okta-audit\n        - page_limit=20\n",
        )
        findings = self._validate(content, name="Pulumi.sec-dev.yaml")
        self.assertTrue(any(finding.severity == "error" and "page_limit <= 5" in finding.message for finding in findings))

    def test_sec_dev_aurelius_findings_schedule_graph_budget_is_bounded(self) -> None:
        content = BASE_STACK.replace(
            "        - runtime_id=writer-okta-audit\n",
            "        - runtime_id=writer-aurelius-findings\n        - page_limit=2\n        - graph_page_limit=2\n",
        ).replace(
            "    - id: writer-okta-audit\n      sourceId: okta\n",
            "    - id: writer-aurelius-findings\n      sourceId: aurelius\n",
        )
        findings = self._validate(content, name="Pulumi.sec-dev.yaml")
        self.assertTrue(any(finding.severity == "error" and "page_limit <= 1" in finding.message for finding in findings))
        self.assertTrue(any(finding.severity == "error" and "graph_page_limit <= 1" in finding.message for finding in findings))

    def test_sec_dev_global_graph_page_limit_is_bounded_for_high_contention_runtimes(self) -> None:
        content = self._without_orchestrator_schedules(BASE_STACK).replace(
            "  cerebro:sourceRuntimes:",
            "  cerebro:orchestratorCommand:\n    - orchestrator\n    - run\n    - graph_page_limit=100\n  cerebro:sourceRuntimes:",
        )
        findings = self._validate(content, name="Pulumi.sec-dev.yaml")
        self.assertTrue(any(finding.severity == "error" and "graph_page_limit <= 5" in finding.message for finding in findings))

    def test_sec_dev_global_page_limit_is_bounded_for_high_contention_runtimes(self) -> None:
        content = self._without_orchestrator_schedules(BASE_STACK).replace(
            "  cerebro:sourceRuntimes:",
            "  cerebro:orchestratorCommand:\n    - orchestrator\n    - run\n    - page_limit=20\n  cerebro:sourceRuntimes:",
        )
        findings = self._validate(content, name="Pulumi.sec-dev.yaml")
        self.assertTrue(any(finding.severity == "error" and "page_limit <= 5" in finding.message for finding in findings))

    def test_sec_dev_postgres_requires_gp3_sized_storage_and_non_micro_class(self) -> None:
        content = BASE_STACK.replace(
            "  cerebro:apiMaxInstances: 2\n",
            "  cerebro:apiMaxInstances: 2\n"
            "  cerebro:postgresInstanceClass: db.t4g.micro\n"
            "  cerebro:postgresAllocatedStorage: 20\n"
            "  cerebro:postgresStorageType: gp2\n",
        )
        findings = self._validate(content, name="Pulumi.sec-dev.yaml")

        self.assertTrue(any(finding.path == "cerebro:postgresInstanceClass" for finding in findings))
        self.assertTrue(any(finding.path == "cerebro:postgresAllocatedStorage" for finding in findings))
        self.assertTrue(any(finding.path == "cerebro:postgresStorageType" for finding in findings))

    def test_sec_dev_postgres_accepts_gp3_sized_storage(self) -> None:
        content = BASE_STACK.replace(
            "  cerebro:apiMaxInstances: 2\n",
            "  cerebro:apiMaxInstances: 2\n"
            "  cerebro:postgresInstanceClass: db.t4g.small\n"
            "  cerebro:postgresAllocatedStorage: 100\n"
            "  cerebro:postgresMaxAllocatedStorage: 200\n"
            "  cerebro:postgresStorageType: gp3\n",
        )
        findings = self._validate(content, name="Pulumi.sec-dev.yaml")

        self.assertFalse(
            any(finding.severity == "error" and finding.path.startswith("cerebro:postgres") for finding in findings)
        )

    def test_sec_dev_postgres_max_storage_must_cover_allocated_storage(self) -> None:
        content = BASE_STACK.replace(
            "  cerebro:apiMaxInstances: 2\n",
            "  cerebro:apiMaxInstances: 2\n"
            "  cerebro:postgresInstanceClass: db.t4g.small\n"
            "  cerebro:postgresAllocatedStorage: 100\n"
            "  cerebro:postgresMaxAllocatedStorage: 50\n"
            "  cerebro:postgresStorageType: gp3\n",
        )
        findings = self._validate(content, name="Pulumi.sec-dev.yaml")

        self.assertTrue(any(finding.path == "cerebro:postgresMaxAllocatedStorage" for finding in findings))

    def test_prod_high_contention_graph_budgets_are_bounded(self) -> None:
        content = BASE_STACK.replace(
            "        - runtime_id=writer-okta-audit\n",
            "        - runtime_id=writer-vulnview-vulnerability\n        - page_limit=2\n        - graph_page_limit=2\n",
        ).replace(
            "    - id: writer-okta-audit\n      sourceId: okta\n",
            "    - id: writer-vulnview-vulnerability\n      sourceId: vulnview\n",
        )
        findings = self._validate(content, name="Pulumi.go-prod.yaml")
        self.assertTrue(any(finding.severity == "error" and "page_limit <= 1" in finding.message for finding in findings))
        self.assertTrue(any(finding.severity == "error" and "graph_page_limit <= 1" in finding.message for finding in findings))

    def test_prod_guardrails_are_errors(self) -> None:
        content = BASE_STACK.replace("  cerebro:postgresDeletionProtection: true", "  cerebro:postgresDeletionProtection: false")
        self.assertTrue(any("deletion protection" in message for message in self._messages(content)))

    def test_prod_rejects_immediate_postgres_apply(self) -> None:
        content = BASE_STACK.replace(
            "  cerebro:postgresBackupRetentionDays: 14\n",
            "  cerebro:postgresBackupRetentionDays: 14\n  cerebro:postgresApplyImmediately: true\n",
        )
        self.assertTrue(any("maintenance window" in message for message in self._messages(content)))

    def test_active_environments_require_api_headroom(self) -> None:
        content = BASE_STACK.replace("  cerebro:apiMaxInstances: 2", "  cerebro:apiMaxInstances: 1")
        self.assertTrue(any("at least two API tasks" in message for message in self._messages(content)))

    def test_active_environments_require_nats_headroom(self) -> None:
        content = BASE_STACK.replace("  cerebro:natsCpu: 2048", "  cerebro:natsCpu: 1024").replace(
            "  cerebro:natsMemory: 32768",
            "  cerebro:natsMemory: 2048",
        )
        messages = self._messages(content)
        self.assertTrue(any("at least 2048 CPU units" in message for message in messages))
        self.assertTrue(any("at least 32768 MiB" in message for message in messages))

    def test_active_environments_require_jetstream_publish_restore_headroom(self) -> None:
        content = BASE_STACK.replace("  cerebro:jetstreamPublishMaxInFlight: 4", "  cerebro:jetstreamPublishMaxInFlight: 2").replace(
            "  cerebro:jetstreamPublishRetryMaxElapsed: 5m",
            "  cerebro:jetstreamPublishRetryMaxElapsed: 90s",
        )
        messages = self._messages(content)
        self.assertTrue(any("publish max-in-flight" in message for message in messages))
        self.assertTrue(any("retry max elapsed at least 5m" in message for message in messages))

    def test_active_environments_require_nats_efs_throughput_headroom(self) -> None:
        content = BASE_STACK.replace("  cerebro:natsEfsThroughputMode: elastic", "  cerebro:natsEfsThroughputMode: bursting")
        self.assertTrue(any("elastic or provisioned EFS throughput" in message for message in self._messages(content)))

    def test_provisioned_nats_efs_throughput_requires_value(self) -> None:
        content = BASE_STACK.replace("  cerebro:natsEfsThroughputMode: elastic", "  cerebro:natsEfsThroughputMode: provisioned")
        self.assertTrue(any("positive MiB/s value" in message for message in self._messages(content)))

    def test_nats_efs_provisioned_value_requires_provisioned_mode(self) -> None:
        content = BASE_STACK.replace(
            "  cerebro:natsEfsThroughputMode: elastic",
            "  cerebro:natsEfsThroughputMode: elastic\n  cerebro:natsEfsProvisionedThroughputMibps: 128",
        )
        self.assertTrue(any("only valid when" in message for message in self._messages(content)))

    def test_device_auth_enabled_exempts_api_headroom_rule(self) -> None:
        # When deviceAuthEnabled=true the in-process DPoP replay cache forces
        # apiMaxInstances=1; the latency-headroom rule must NOT fire because
        # raising replicas would silently break replay protection.
        content = BASE_STACK.replace(
            "  cerebro:apiMaxInstances: 2",
            "  cerebro:apiMaxInstances: 1\n  cerebro:deviceAuthEnabled: true",
        )
        messages = self._messages(content)
        self.assertFalse(
            any("at least two API tasks" in message for message in messages),
            f"latency-headroom rule fired despite deviceAuthEnabled=true: {messages!r}",
        )

    def test_device_auth_enabled_forbids_multi_replica(self) -> None:
        # Conversely: deviceAuthEnabled=true with apiMaxInstances>1 must be
        # rejected, because the in-process replay cache cannot protect a
        # multi-replica deployment.
        content = BASE_STACK.replace(
            "  cerebro:apiMaxInstances: 2",
            "  cerebro:apiMaxInstances: 2\n  cerebro:deviceAuthEnabled: true",
        )
        self.assertTrue(
            any("requires apiMaxInstances=1" in message for message in self._messages(content)),
            "deviceAuthEnabled=true with apiMaxInstances>1 should fail validation",
        )

    def test_enabled_web_console_requires_headroom(self) -> None:
        content = BASE_STACK.replace(
            "  cerebro:apiMaxInstances: 2\n",
            "  cerebro:apiMaxInstances: 2\n  cerebro:webEnabled: true\n  cerebro:webMaxInstances: 1\n",
        )
        self.assertTrue(any("at least two tasks" in message for message in self._messages(content)))

    def test_legacy_jobs_transition_flag_warns(self) -> None:
        content = BASE_STACK.replace(
            "  cerebro:postgresDeletionProtection: true\n",
            "  cerebro:postgresDeletionProtection: true\n  cerebro:retainLegacyJobsTableForDeletionProtectionTransition: true\n",
        )
        findings = self._validate(content)
        self.assertTrue(
            any(
                finding.severity == "warning" and "legacy jobs table transition flag" in finding.message
                for finding in findings
            )
        )

    def test_prod_postgres_must_not_use_gp2_storage(self) -> None:
        content = BASE_STACK.replace(
            "  cerebro:postgresBackupRetentionDays: 14\n",
            "  cerebro:postgresBackupRetentionDays: 14\n  cerebro:postgresStorageType: gp2\n",
        )
        self.assertTrue(any("must not use burst-credit-limited gp2" in message for message in self._messages(content)))

    def test_sec_dev_postgres_capacity_guardrails(self) -> None:
        content = BASE_STACK.replace(
            "  cerebro:environment: go-production\n",
            "  cerebro:environment: sec-dev\n  cerebro:postgresInstanceClass: db.t4g.micro\n  cerebro:postgresAllocatedStorage: 20\n  cerebro:postgresStorageType: gp2\n",
        )
        messages = self._messages(content)

        self.assertTrue(any("must not use burst-credit-limited gp2" in message for message in messages))
        self.assertTrue(any("sec-dev Postgres must not use db.t4g.micro" in message for message in messages))
        self.assertTrue(any("sec-dev Postgres storage must be at least 100 GB" in message for message in messages))

    def test_small_gp3_storage_rejects_iops_and_throughput_overrides(self) -> None:
        content = BASE_STACK.replace(
            "  cerebro:postgresBackupRetentionDays: 14\n",
            "  cerebro:postgresBackupRetentionDays: 14\n  cerebro:postgresStorageType: gp3\n  cerebro:postgresAllocatedStorage: 100\n  cerebro:postgresIops: 3000\n",
        )
        self.assertTrue(any("require at least 400 GB allocated storage" in message for message in self._messages(content)))

    def test_backfill_without_retirement_metadata_is_warning(self) -> None:
        content = BASE_STACK.replace("name: okta-audit", "name: okta-audit-backfill")
        findings = self._validate(content)
        self.assertTrue(any(finding.severity == "warning" and "backfill schedules" in finding.message for finding in findings))

    def test_backfill_retirement_metadata_clears_warning(self) -> None:
        content = BASE_STACK.replace("name: okta-audit", 'name: okta-audit-backfill\n      removeAfter: "2099-01-01"')
        findings = self._validate(content)
        self.assertFalse(any(finding.severity == "warning" and "backfill schedules" in finding.message for finding in findings))

    def test_backfill_retirement_metadata_rejects_past_date(self) -> None:
        content = BASE_STACK.replace("name: okta-audit", 'name: okta-audit-backfill\n      removeAfter: "2000-01-01"')
        findings = self._validate(content)
        self.assertTrue(any(finding.severity == "error" and "past" in finding.message for finding in findings))

    def test_prod_requires_alarm_route(self) -> None:
        content = BASE_STACK.replace(
            "  cerebro:alarmActionArns:\n    - arn:aws:sns:us-east-1:123456789012:cerebro-alerts\n",
            "",
        )
        findings = self._validate(content)
        self.assertTrue(any(finding.severity == "error" and "notification route" in finding.message for finding in findings))

    def test_alb_access_log_retention_must_be_positive(self) -> None:
        content = BASE_STACK.replace("  cerebro:apiMaxInstances: 2\n", "  cerebro:apiMaxInstances: 2\n  cerebro:albAccessLogsRetentionDays: 0\n")
        findings = self._validate(content)
        self.assertTrue(any(finding.severity == "error" and "albAccessLogsRetentionDays" in finding.path for finding in findings))

    def test_access_audit_alarm_thresholds_must_be_non_negative(self) -> None:
        content = BASE_STACK.replace(
            "  cerebro:apiMaxInstances: 2\n",
            "  cerebro:apiMaxInstances: 2\n  cerebro:accessAuditDeniedAlarmThreshold: -1\n",
        )
        findings = self._validate(content)
        self.assertTrue(any(finding.severity == "error" and "accessAuditDeniedAlarmThreshold" in finding.path for finding in findings))

    def test_sensitive_access_audit_alarm_thresholds_allow_minus_one_disable(self) -> None:
        content = BASE_STACK.replace(
            "  cerebro:apiMaxInstances: 2\n",
            "  cerebro:apiMaxInstances: 2\n  cerebro:accessAuditTenantMismatchAlarmThreshold: -1\n  cerebro:accessAuditSensitiveDeniedAlarmThreshold: -2\n",
        )
        findings = self._validate(content)
        self.assertFalse(any(finding.severity == "error" and "accessAuditTenantMismatchAlarmThreshold" in finding.path for finding in findings))
        self.assertTrue(any(finding.severity == "error" and "accessAuditSensitiveDeniedAlarmThreshold" in finding.path for finding in findings))

    def test_cross_stack_sec_dev_may_lead_go_prod_image_tag(self) -> None:
        prod = Path("Pulumi.go-prod.yaml")
        dev = Path("Pulumi.sec-dev.yaml")
        configs = {
            prod: self._config(BASE_STACK),
            dev: self._config(BASE_STACK.replace("v2.1.36", "v2.1.37", 1)),
        }
        with patch.object(validator, "_load_config", side_effect=lambda path: configs[path]):
            findings = validate_cross_stack([prod, dev])
        self.assertEqual([finding for finding in findings if finding.severity == "error"], [])

    def test_cross_stack_sec_dev_image_tag_must_not_lag_prod(self) -> None:
        prod = Path("Pulumi.go-prod.yaml")
        dev = Path("Pulumi.sec-dev.yaml")
        configs = {
            prod: self._config(BASE_STACK),
            dev: self._config(BASE_STACK.replace("v2.1.36", "v2.1.35", 1)),
        }
        with patch.object(validator, "_load_config", side_effect=lambda path: configs[path]):
            findings = validate_cross_stack([prod, dev])
        self.assertTrue(any(finding.severity == "error" and "must not lag go-prod" in finding.message for finding in findings))

    def test_sec_dev_aws_public_endpoint_requires_complete_aws_coverage(self) -> None:
        content = BASE_STACK.replace("  cerebro:imageTag: v2.1.36", "  cerebro:imageTag: v2.1.46").replace(
            "    - id: writer-okta-audit\n      sourceId: okta\n      tenantId: writer\n      config:\n        api_token: env:API_TOKEN\n",
            """    - id: writer-aws-sec-dev-us1-public-endpoint
      sourceId: aws
      tenantId: writer
      config:
        account_id: "944130631940"
        family: public_endpoint
        include_global: "true"
        per_page: "100"
        region: us-east-1
        role_arn: arn:aws:iam::944130631940:role/cerebro-org-scan-role
""",
        ).replace("runtime_id=writer-okta-audit", "runtime_id=writer-aws-sec-dev-us1-public-endpoint")
        findings = self._validate(content, name="Pulumi.sec-dev.yaml")
        self.assertTrue(any(finding.severity == "error" and "writer-aws-sec-dev-effective-permission" in finding.message for finding in findings))

    def test_sec_dev_aws_effective_permission_requires_runtime_release(self) -> None:
        content = BASE_STACK.replace(
            "    - id: writer-okta-audit\n      sourceId: okta\n      tenantId: writer\n      config:\n        api_token: env:API_TOKEN\n",
            """    - id: writer-aws-sec-dev-us1-public-endpoint
      sourceId: aws
      tenantId: writer
      config:
        account_id: "944130631940"
        family: public_endpoint
        include_global: "true"
        per_page: "100"
        region: us-east-1
        role_arn: arn:aws:iam::944130631940:role/cerebro-org-scan-role
""",
        ).replace("runtime_id=writer-okta-audit", "runtime_id=writer-aws-sec-dev-us1-public-endpoint")
        findings = self._validate(content, name="Pulumi.sec-dev.yaml")
        self.assertTrue(any(finding.severity == "error" and "effective_permission" in finding.message and "v2.1.46" in finding.message for finding in findings))

    def test_go_prod_aws_public_endpoint_requires_expanded_graph_coverage(self) -> None:
        content = BASE_STACK.replace(
            "    - id: writer-okta-audit\n      sourceId: okta\n      tenantId: writer\n      config:\n        api_token: env:API_TOKEN\n",
            """    - id: writer-aws-sec-prod-us1-public-endpoint
      sourceId: aws
      tenantId: writer
      config:
        account_id: "837279440628"
        family: public_endpoint
        include_global: "true"
        per_page: "100"
        region: us-east-1
        role_arn: arn:aws:iam::837279440628:role/cerebro-org-scan-role
""",
        ).replace("runtime_id=writer-okta-audit", "runtime_id=writer-aws-sec-prod-us1-public-endpoint")

        findings = self._validate(content, name="Pulumi.go-prod.yaml")

        self.assertTrue(any(finding.severity == "error" and "writer-aws-prod-effective-permission" in finding.message for finding in findings))
        self.assertTrue(any(finding.severity == "error" and "writer-aws-sec-prod-us1-resource-exposure" in finding.message for finding in findings))

    def test_go_prod_actual_aws_graph_coverage_is_expanded(self) -> None:
        config = validator.apply_source_runtime_rollouts(
            validator._load_config(Path(__file__).resolve().parents[1] / "aws/Pulumi.go-prod.yaml")
        )
        aws_runtimes = [runtime for runtime in config["sourceRuntimes"] if runtime.get("sourceId") == "aws"]
        aws_scheduled_runtime_ids = {
            validator._runtime_id_from_command(schedule.get("command"))
            for schedule in config["orchestratorSchedules"]
            if isinstance(schedule, dict)
        }

        findings = validate_stack(Path(__file__).resolve().parents[1] / "aws/Pulumi.go-prod.yaml")

        self.assertEqual(len(aws_runtimes), 280)
        self.assertTrue(all(runtime["id"] in aws_scheduled_runtime_ids for runtime in aws_runtimes))
        self.assertEqual(
            {
                str(runtime.get("config", {}).get("family", ""))
                for runtime in aws_runtimes
            },
            {
                "access_key",
                "asset_metadata",
                "cloudfront_distribution",
                "ec2_instance",
                "ecs_service",
                "ecs_task",
                "ecs_task_definition",
                "elbv2_load_balancer",
                "eks_cluster",
                "eks_fargate_profile",
                "eks_nodegroup",
                "eks_pod_identity_association",
                "effective_permission",
                "globalaccelerator_accelerator",
                "globalaccelerator_endpoint_group",
                "globalaccelerator_listener",
                "guardduty_finding",
                "iam_group",
                "iam_group_membership",
                "iam_role",
                "iam_role_assignment",
                "iam_role_trust",
                "iam_user",
                "inspector2_finding",
                "kms_key",
                "lambda_function",
                "organizations_account",
                "organizations_policy",
                "public_endpoint",
                "rds_instance",
                "resource_exposure",
                "route_table",
                "s3_bucket",
                "secret",
                "security_group",
                "securityhub_finding",
                "subnet",
                "vpc",
                "vpc_endpoint",
                "vpclattice_listener",
                "vpclattice_service",
                "vpclattice_target_group",
            },
        )
        self.assertFalse(
            any(finding.severity == "error" and "go-prod AWS coverage" in finding.message for finding in findings)
        )

    def test_sec_dev_actual_aws_graph_coverage_is_expanded(self) -> None:
        config = validator.apply_source_runtime_rollouts(
            validator._load_config(Path(__file__).resolve().parents[1] / "aws/Pulumi.sec-dev.yaml")
        )
        aws_runtimes = [runtime for runtime in config["sourceRuntimes"] if runtime.get("sourceId") == "aws"]
        aws_scheduled_runtime_ids = {
            validator._runtime_id_from_command(schedule.get("command"))
            for schedule in config["orchestratorSchedules"]
            if isinstance(schedule, dict)
        }

        findings = validate_stack(Path(__file__).resolve().parents[1] / "aws/Pulumi.sec-dev.yaml")

        self.assertEqual(len(aws_runtimes), 72)
        self.assertTrue(all(runtime["id"] in aws_scheduled_runtime_ids for runtime in aws_runtimes))
        self.assertTrue(
            {
                "cloudfront_distribution",
                "elbv2_load_balancer",
                "globalaccelerator_accelerator",
                "globalaccelerator_endpoint_group",
                "globalaccelerator_listener",
                "guardduty_finding",
                "inspector2_finding",
                "kms_key",
                "organizations_account",
                "organizations_policy",
                "rds_instance",
                "route_table",
                "s3_bucket",
                "secret",
                "security_group",
                "securityhub_finding",
                "subnet",
                "vpc",
                "vpc_endpoint",
                "vpclattice_listener",
                "vpclattice_service",
                "vpclattice_target_group",
            }.issubset({str(runtime.get("config", {}).get("family", "")) for runtime in aws_runtimes})
        )
        self.assertFalse(
            any(finding.severity == "error" and "sec-dev AWS coverage" in finding.message for finding in findings)
        )

    def test_actual_gcp_runtimes_use_wif_without_token_secrets(self) -> None:
        for stack_name, expected_count, service_account in [
            ("Pulumi.sec-dev.yaml", 68, "cerebro-scanner-dev@writer-iam.iam.gserviceaccount.com"),
            ("Pulumi.go-prod.yaml", 102, "cerebro-scanner-prod@writer-iam.iam.gserviceaccount.com"),
        ]:
            with self.subTest(stack=stack_name):
                config = validator.apply_source_runtime_rollouts(
                    validator._load_config(Path(__file__).resolve().parents[1] / f"aws/{stack_name}")
                )
                gcp_runtimes = [runtime for runtime in config["sourceRuntimes"] if runtime.get("sourceId") == "gcp"]
                gcp_scheduled_runtime_ids = {
                    validator._runtime_id_from_command(schedule.get("command"))
                    for schedule in config["orchestratorSchedules"]
                    if isinstance(schedule, dict)
                }

                self.assertEqual(len(gcp_runtimes), expected_count)
                self.assertTrue(all(runtime["id"] in gcp_scheduled_runtime_ids for runtime in gcp_runtimes))
                gcp_runtime_ids = {runtime["id"] for runtime in gcp_runtimes}
                for schedule in config["orchestratorSchedules"]:
                    if validator._runtime_id_from_command(schedule.get("command")) in gcp_runtime_ids:
                        self.assertLessEqual(
                            len(validator._orchestrator_rule_name(config["environment"], schedule["name"])),
                            64,
                        )
                for runtime in gcp_runtimes:
                    runtime_config = runtime.get("config", {})
                    self.assertNotIn("token", runtime_config)
                    self.assertEqual(runtime_config.get("wif_service_account_email"), service_account)
                    self.assertIn("workloadIdentityPools", runtime_config.get("wif_audience", ""))

    def test_go_prod_gcp_rollouts_use_scheduler_backend(self) -> None:
        config = validator.apply_source_runtime_rollouts(
            validator._load_config(Path(__file__).resolve().parents[1] / "aws/Pulumi.go-prod.yaml")
        )
        findings = validate_stack(Path(__file__).resolve().parents[1] / "aws/Pulumi.go-prod.yaml")
        gcp_runtime_ids = {
            runtime["id"]
            for runtime in config["sourceRuntimes"]
            if runtime.get("sourceId") == "gcp"
        }
        gcp_schedules = [
            schedule
            for schedule in config["orchestratorSchedules"]
            if validator._runtime_id_from_command(schedule.get("command")) in gcp_runtime_ids
        ]
        eventbridge_schedules = [
            schedule
            for schedule in config["orchestratorSchedules"]
            if validator._schedule_backend(schedule) == "eventbridge"
        ]

        self.assertEqual(len(gcp_runtime_ids), 102)
        self.assertTrue(gcp_schedules)
        self.assertTrue(all(validator._schedule_backend(schedule) == "scheduler" for schedule in gcp_schedules))
        self.assertLessEqual(len(eventbridge_schedules), 294)
        self.assertFalse(any("exceeds EventBridge rule capacity" in finding.message for finding in findings))

    def test_sec_dev_evidencecas_runtime_wires_private_endpoint_allowlist(self) -> None:
        config = validator._load_config(Path(__file__).resolve().parents[1] / "aws/Pulumi.sec-dev.yaml")
        secret_keys = set(config["sourceSecretKeys"])
        runtime = next(
            runtime
            for runtime in config["sourceRuntimes"]
            if runtime.get("id") == "writer-evidence-cas-cases"
        )

        self.assertIn("EVIDENCE_CAS_BASE_URL", secret_keys)
        self.assertEqual(
            runtime["config"].get("private_endpoint_allowlist"),
            "env:EVIDENCE_CAS_BASE_URL",
        )

    def test_partial_neo4j_secret_import_map_requires_runtime_credentials_import(self) -> None:
        content = BASE_STACK + """
  cerebro:neo4jSecretImportArns:
    CEREBRO_API_KEYS: arn:aws:secretsmanager:us-east-1:123456789012:secret:example/api-keys
    CEREBRO_NEO4J_PASSWORD: arn:aws:secretsmanager:us-east-1:123456789012:secret:example/password
    CEREBRO_NEO4J_URI: arn:aws:secretsmanager:us-east-1:123456789012:secret:example/uri
    CEREBRO_NEO4J_USERNAME: arn:aws:secretsmanager:us-east-1:123456789012:secret:example/username
"""

        findings = self._validate(content)

        self.assertTrue(
            any(
                finding.severity == "error"
                and "CEREBRO_API_CREDENTIALS_JSON" in finding.path
                and "Pulumi-managed runtime credential secret" in finding.message
                for finding in findings
            )
        )

    def test_actual_sec_dev_imports_all_pulumi_managed_runtime_credentials(self) -> None:
        findings = validate_stack(Path(__file__).resolve().parents[1] / "aws/Pulumi.sec-dev.yaml")

        self.assertFalse(
            any(
                finding.severity == "error"
                and finding.path.startswith("cerebro:neo4jSecretImportArns")
                for finding in findings
            )
        )

    def test_cosmo_requires_token_auth_release(self) -> None:
        content = BASE_STACK.replace("  cerebro:imageTag: v2.1.36", "  cerebro:imageTag: v2.1.35")
        findings = self._validate(content)
        self.assertTrue(any(finding.severity == "error" and "Cosmo survey feedback token auth" in finding.message for finding in findings))

    def test_cosmo_runtime_is_required_for_managed_stacks(self) -> None:
        content = BASE_STACK.replace("    - id: writer-cosmo-survey-feedback", "    - id: writer-cosmo-survey-feedback-disabled", 1)
        findings = self._validate(content)
        self.assertTrue(any(finding.severity == "error" and "required Cosmo runtime 'writer-cosmo-survey-feedback' is missing" in finding.message for finding in findings))

    def test_cosmo_schedule_is_required_for_managed_stacks(self) -> None:
        content = BASE_STACK.replace("runtime_id=writer-cosmo-fact", "runtime_id=writer-cosmo-fact-disabled", 1)
        findings = self._validate(content)
        self.assertTrue(any(finding.severity == "error" and "required Cosmo schedule for 'writer-cosmo-fact' is missing" in finding.message for finding in findings))

    def test_temporarily_disabled_cosmo_runtime_bypasses_requirement(self) -> None:
        content = BASE_STACK.replace(
            "  cerebro:sourceRuntimeObservability:",
            "  cerebro:temporarilyDisabledSourceRuntimes:\n"
            "    - runtimeId: writer-cosmo-survey-feedback\n"
            "      owner: cerebro-platform\n"
            "      reason: invalid_credentials\n"
            "      disabledDate: \"2026-06-10\"\n"
            "      reviewDeadline: \"2999-01-01\"\n"
            "      reenableCriteria: \"Rotate token and pass live source runtime verification.\"\n"
            "  cerebro:sourceRuntimeObservability:",
        ).replace("    - id: writer-cosmo-survey-feedback", "    - id: writer-cosmo-survey-feedback-disabled", 1)
        findings = self._validate(content)
        self.assertFalse(any("required Cosmo runtime 'writer-cosmo-survey-feedback' is missing" in finding.message for finding in findings))

    def test_unknown_temporary_runtime_bypass_is_rejected(self) -> None:
        content = BASE_STACK.replace(
            "  cerebro:sourceRuntimeObservability:",
            "  cerebro:temporarilyDisabledSourceRuntimes:\n"
            "    - runtimeId: writer-unknown-runtime\n"
            "      owner: cerebro-platform\n"
            "      reason: invalid_credentials\n"
            "      disabledDate: \"2026-06-10\"\n"
            "      reviewDeadline: \"2999-01-01\"\n"
            "      reenableCriteria: \"Rotate token and pass live source runtime verification.\"\n"
            "  cerebro:sourceRuntimeObservability:",
        )
        findings = self._validate(content)
        self.assertTrue(any(finding.severity == "error" and "unsupported temporary runtime bypasses: writer-unknown-runtime" in finding.message for finding in findings))

    def test_temporary_runtime_bypass_requires_structured_metadata(self) -> None:
        content = BASE_STACK.replace(
            "  cerebro:sourceRuntimeObservability:",
            "  cerebro:temporarilyDisabledSourceRuntimes:\n"
            "    - writer-cosmo-survey-feedback\n"
            "  cerebro:sourceRuntimeObservability:",
        )
        findings = self._validate(content)
        self.assertTrue(
            any(finding.severity == "error" and "quarantined runtime entry must be an object with metadata" in finding.message for finding in findings)
        )

    def test_temporary_runtime_bypass_reason_is_enum_checked(self) -> None:
        content = BASE_STACK.replace(
            "  cerebro:sourceRuntimeObservability:",
            "  cerebro:temporarilyDisabledSourceRuntimes:\n"
            "    - runtimeId: writer-cosmo-survey-feedback\n"
            "      owner: cerebro-platform\n"
            "      reason: typo_reason\n"
            "      disabledDate: \"2026-06-10\"\n"
            "      reviewDeadline: \"2999-01-01\"\n"
            "      reenableCriteria: \"Rotate token and pass live source runtime verification.\"\n"
            "  cerebro:sourceRuntimeObservability:",
        )
        findings = self._validate(content)
        self.assertTrue(any(finding.severity == "error" and "reason must be one of" in finding.message for finding in findings))

    def test_quarantined_runtime_cannot_remain_active_or_scheduled(self) -> None:
        content = BASE_STACK.replace(
            "  cerebro:sourceRuntimeObservability:",
            "  cerebro:temporarilyDisabledSourceRuntimes:\n"
            "    - runtimeId: writer-cosmo-survey-feedback\n"
            "      owner: cerebro-platform\n"
            "      reason: invalid_credentials\n"
            "      disabledDate: \"2026-06-10\"\n"
            "      reviewDeadline: \"2999-01-01\"\n"
            "      reenableCriteria: \"Rotate token and pass live source runtime verification.\"\n"
            "  cerebro:sourceRuntimeObservability:",
        )
        findings = self._validate(content)
        self.assertTrue(
            any(
                finding.severity == "error"
                and "quarantined runtime 'writer-cosmo-survey-feedback' must not be declared in active sourceRuntimes" in finding.message
                for finding in findings
            )
        )
        self.assertTrue(
            any(
                finding.severity == "error"
                and "quarantined runtime 'writer-cosmo-survey-feedback' must not be referenced by cerebro:orchestratorSchedules" in finding.message
                for finding in findings
            )
        )

    def test_sec_dev_cosmo_graph_budgets_are_bounded(self) -> None:
        content = BASE_STACK.replace(
            "        - runtime_id=writer-cosmo-session\n",
            "        - runtime_id=writer-cosmo-session\n"
            "        - page_limit=20\n"
            "        - graph_page_limit=100\n"
            "        - event_limit=1000\n",
            1,
        )
        findings = self._validate(content, name="Pulumi.sec-dev.yaml")
        self.assertTrue(any(finding.severity == "error" and "page_limit <= 5" in finding.message for finding in findings))
        self.assertTrue(any(finding.severity == "error" and "graph_page_limit <= 5" in finding.message for finding in findings))
        self.assertTrue(any(finding.severity == "error" and "event_limit <= 500" in finding.message for finding in findings))

    def test_actual_sec_dev_cosmo_graph_budgets_are_capped(self) -> None:
        findings = validate_stack(Path(__file__).resolve().parents[1] / "aws/Pulumi.sec-dev.yaml")
        self.assertFalse(
            any(
                finding.severity == "error"
                and "writer-cosmo-" in finding.message
                and ("page_limit" in finding.message or "event_limit" in finding.message)
                for finding in findings
            )
        )

    def test_actual_sec_dev_declared_runtimes_are_scheduled(self) -> None:
        findings = validate_stack(Path(__file__).resolve().parents[1] / "aws/Pulumi.sec-dev.yaml")
        self.assertFalse(
            any(
                finding.severity == "error"
                and "is not referenced by cerebro:orchestratorCommand or cerebro:orchestratorSchedules" in finding.message
                for finding in findings
            )
        )

    def test_cosmo_must_use_dedicated_token_secret(self) -> None:
        content = BASE_STACK.replace(f"{TOKEN_FIELD}: env:{COSMO_TOKEN_KEY}", f"{TOKEN_FIELD}: env:GITHUB_{TOKEN_SUFFIX}", 1)
        findings = self._validate(content)
        self.assertTrue(any(finding.severity == "error" and COSMO_TOKEN_KEY in finding.message for finding in findings))

    def test_cosmo_legacy_webhook_secret_is_rejected(self) -> None:
        content = BASE_STACK.replace(
            f"        {TOKEN_FIELD}: env:{COSMO_TOKEN_KEY}\n    - id: writer-okta-audit",
            f"        {TOKEN_FIELD}: env:{COSMO_TOKEN_KEY}\n        {WEBHOOK_SECRET_FIELD}: env:{COSMO_WEBHOOK_SECRET_KEY}\n    - id: writer-okta-audit",
        )
        findings = self._validate(content)
        self.assertTrue(any(finding.severity == "error" and WEBHOOK_SECRET_FIELD in finding.path for finding in findings))

    def test_mcp_oauth_requires_api_auth_and_tenant_subset(self) -> None:
        content = BASE_STACK.replace(
            "  cerebro:apiAuthEnabled: true\n",
            "  cerebro:apiAuthEnabled: false\n"
            "  cerebro:mcpOauthEnabled: true\n"
            "  cerebro:mcpOauthUpstreamIssuer: https://writer.okta.com\n"
            "  cerebro:mcpOauthUpstreamRedirectUri: https://cerebro.example.com/oauth/callback\n"
            "  cerebro:mcpOauthUpstreamClientIdSecretName: CEREBRO_MCP_OAUTH_UPSTREAM_CLIENT_ID_GO_PROD\n"
            "  cerebro:mcpOauthUpstreamClientSecretName: CEREBRO_MCP_OAUTH_UPSTREAM_CLIENT_SECRET_GO_PROD\n"
            "  cerebro:mcpOauthSecurityGroups:\n"
            "    - DEPT - SECURITY\n"
            "  cerebro:mcpOauthTenantId: unknown\n"
            "  cerebro:mcpOauthAllowedTenants:\n"
            "    - unknown\n",
        )
        findings = self._validate(content)

        self.assertTrue(any(finding.severity == "error" and "MCP OAuth requires API auth" in finding.message for finding in findings))
        self.assertTrue(any(finding.severity == "error" and "subset of allowedTenants" in finding.message for finding in findings))

    def test_actual_go_prod_mcp_oauth_contract_is_valid(self) -> None:
        findings = validate_stack(Path(__file__).resolve().parents[1] / "aws/Pulumi.go-prod.yaml")
        self.assertFalse(
            any(
                finding.severity == "error"
                and (finding.path.startswith("cerebro:mcpOauth") or finding.path == "cerebro:apiAuthEnabled")
                for finding in findings
            )
        )


if __name__ == "__main__":
    unittest.main()
