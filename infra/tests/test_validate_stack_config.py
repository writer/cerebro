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
  cerebro:s3Sources:
    - name: panopticon
      bucket: panopticon-prod-837279440628-cerebro-export
      bucketArn: arn:aws:s3:::panopticon-prod-837279440628-cerebro-export
      region: us-east-1
      roleArn: arn:aws:iam::837279440628:role/panopticon-prod-cerebro-export-reader
      prefixes:
        - "exports/alerts/"
        - "exports/cases/"
        - "exports/iocs/"
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
        bucket: panopticon-prod-837279440628-cerebro-export
        family: alert
        page_size: "100"
        prefix: exports/alerts/
        region: us-east-1
        role_arn: arn:aws:iam::837279440628:role/panopticon-prod-cerebro-export-reader
        tenant_id: writer
    - id: writer-panopticon-cases
      sourceId: panopticon
      tenantId: writer
      config:
        bucket: panopticon-prod-837279440628-cerebro-export
        family: case
        page_size: "100"
        prefix: exports/cases/
        region: us-east-1
        role_arn: arn:aws:iam::837279440628:role/panopticon-prod-cerebro-export-reader
        tenant_id: writer
    - id: writer-panopticon-iocs
      sourceId: panopticon
      tenantId: writer
      config:
        bucket: panopticon-prod-837279440628-cerebro-export
        family: ioc
        page_size: "100"
        prefix: exports/iocs/
        region: us-east-1
        role_arn: arn:aws:iam::837279440628:role/panopticon-prod-cerebro-export-reader
        tenant_id: writer
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

    def test_panopticon_missing_s3_source_is_error(self) -> None:
        content = self._repo_stack_content("Pulumi.sec-dev.yaml").replace(
            "    - name: panopticon\n      bucket: panopticon-dev-944130631940-cerebro-export\n",
            "    - name: panopticon-disabled\n      bucket: panopticon-dev-944130631940-cerebro-export\n",
            1,
        )

        messages = self._panopticon_error_messages(content, "Pulumi.sec-dev.yaml")

        self.assertTrue(any("exactly one s3Sources entry named 'panopticon'" in message for message in messages))

    def test_panopticon_source_runtime_is_required(self) -> None:
        content = self._repo_stack_content("Pulumi.go-prod.yaml").replace(
            "    - id: writer-panopticon-alerts\n",
            "    - id: writer-panopticon-alerts-disabled\n",
            1,
        )

        messages = self._panopticon_error_messages(content, "Pulumi.go-prod.yaml")

        self.assertIn("required Panopticon runtime 'writer-panopticon-alerts' is missing", messages)

    def test_panopticon_env_account_isolation_is_exact(self) -> None:
        content = (
            self._repo_stack_content("Pulumi.sec-dev.yaml")
            .replace("panopticon-dev-944130631940-cerebro-export", "panopticon-prod-837279440628-cerebro-export")
            .replace(
                "arn:aws:iam::944130631940:role/panopticon-dev-cerebro-export-reader",
                "arn:aws:iam::837279440628:role/panopticon-prod-cerebro-export-reader",
            )
        )

        messages = self._panopticon_error_messages(content, "Pulumi.sec-dev.yaml")

        self.assertTrue(any("Panopticon bucket must be 'panopticon-dev-944130631940-cerebro-export'" in message for message in messages))
        self.assertTrue(any("Panopticon roleArn must be 'arn:aws:iam::944130631940:role/panopticon-dev-cerebro-export-reader'" in message for message in messages))

    def test_panopticon_runtime_prefix_must_match_family(self) -> None:
        content = self._repo_stack_content("Pulumi.sec-dev.yaml").replace(
            "        prefix: exports/alerts/\n",
            "        prefix: exports/cases/\n",
            1,
        )

        messages = self._panopticon_error_messages(content, "Pulumi.sec-dev.yaml")

        self.assertTrue(any("Panopticon alert runtime prefix must be 'exports/alerts/'" in message for message in messages))

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
            "        tenant_id: writer\n    - id: writer-panopticon-cases\n",
            "        tenant_id: writer\n        evidence_bytes: inline-forbidden\n    - id: writer-panopticon-cases\n",
            1,
        )

        messages = self._panopticon_error_messages(content, "Pulumi.sec-dev.yaml")

        self.assertTrue(any("unsupported keys ['evidence_bytes']" in message for message in messages))
        self.assertTrue(any("must not include secrets, tokens, or evidence bytes" in message for message in messages))

    def test_latency_alarm_thresholds_must_be_non_negative(self) -> None:
        content = BASE_STACK + "  cerebro:dashboardLatencyP95AlarmThresholdMs: -1\n"
        self.assertTrue(any("must be a non-negative integer" in message for message in self._messages(content)))

    def test_openrouter_provider_requires_explicit_model(self) -> None:
        content = BASE_STACK + "  cerebro:graphAgentLlmProvider: openrouter\n"
        self.assertTrue(any("OpenRouter provider must set an explicit OpenRouter model id" in message for message in self._messages(content)))

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
        )
        self.assertFalse(any("OpenRouter model" in message for message in self._messages(content)))

    def test_missing_source_secret_is_error(self) -> None:
        content = BASE_STACK.replace(f"    - {API_TOKEN_KEY}\n", "")
        self.assertTrue(any("not listed in cerebro:sourceSecretKeys" in message for message in self._messages(content)))

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
        config = validator._load_config(Path(__file__).resolve().parents[1] / "aws/Pulumi.go-prod.yaml")
        aws_runtimes = [runtime for runtime in config["sourceRuntimes"] if runtime.get("sourceId") == "aws"]
        aws_scheduled_runtime_ids = {
            validator._runtime_id_from_command(schedule.get("command"))
            for schedule in config["orchestratorSchedules"]
            if isinstance(schedule, dict)
        }

        findings = validate_stack(Path(__file__).resolve().parents[1] / "aws/Pulumi.go-prod.yaml")

        self.assertEqual(len(aws_runtimes), 128)
        self.assertTrue(all(runtime["id"] in aws_scheduled_runtime_ids for runtime in aws_runtimes))
        self.assertEqual(
            {
                str(runtime.get("config", {}).get("family", ""))
                for runtime in aws_runtimes
            },
            {
                "access_key",
                "asset_metadata",
                "ec2_instance",
                "ecs_service",
                "ecs_task",
                "ecs_task_definition",
                "eks_cluster",
                "eks_fargate_profile",
                "eks_nodegroup",
                "eks_pod_identity_association",
                "effective_permission",
                "iam_group",
                "iam_group_membership",
                "iam_role",
                "iam_role_assignment",
                "iam_role_trust",
                "iam_user",
                "lambda_function",
                "public_endpoint",
                "resource_exposure",
            },
        )
        self.assertFalse(
            any(finding.severity == "error" and "go-prod AWS coverage" in finding.message for finding in findings)
        )

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


if __name__ == "__main__":
    unittest.main()
