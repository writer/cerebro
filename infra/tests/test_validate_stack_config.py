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
  cerebro:orchestratorSchedules:
{COSMO_SCHEDULES.rstrip()}
    - name: okta-audit
      scheduleExpression: cron(0 * * * ? *)
      taskCount: 1
      command:
        - orchestrator
        - run
        - runtime_id=writer-okta-audit
  cerebro:sourceRuntimes:
{COSMO_RUNTIMES.rstrip()}
    - id: writer-okta-audit
      sourceId: okta
      tenantId: writer
      config:
        {API_TOKEN_FIELD}: env:{API_TOKEN_KEY}
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

    def test_valid_stack_has_no_errors(self) -> None:
        findings = self._validate(BASE_STACK)
        self.assertEqual([finding for finding in findings if finding.severity == "error"], [])

    def test_latency_alarm_thresholds_must_be_non_negative(self) -> None:
        content = BASE_STACK + "  cerebro:dashboardLatencyP95AlarmThresholdMs: -1\n"
        self.assertTrue(any("must be a non-negative integer" in message for message in self._messages(content)))

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
        self.assertFalse(
            any("is not referenced by cerebro:orchestratorCommand" in message for message in messages)
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

    def test_sec_dev_global_graph_page_limit_is_bounded_for_high_contention_runtimes(self) -> None:
        content = BASE_STACK.replace(
            "  cerebro:orchestratorSchedules:",
            "  cerebro:orchestratorCommand:\n    - orchestrator\n    - run\n    - graph_page_limit=100\n  cerebro:orchestratorSchedules:",
        )
        findings = self._validate(content, name="Pulumi.sec-dev.yaml")
        self.assertTrue(any(finding.severity == "error" and "graph_page_limit <= 5" in finding.message for finding in findings))

    def test_sec_dev_global_page_limit_is_bounded_for_high_contention_runtimes(self) -> None:
        content = BASE_STACK.replace(
            "  cerebro:orchestratorSchedules:",
            "  cerebro:orchestratorCommand:\n    - orchestrator\n    - run\n    - page_limit=20\n  cerebro:orchestratorSchedules:",
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

    def test_active_environments_require_api_headroom(self) -> None:
        content = BASE_STACK.replace("  cerebro:apiMaxInstances: 2", "  cerebro:apiMaxInstances: 1")
        self.assertTrue(any("at least two API tasks" in message for message in self._messages(content)))

    def test_enabled_web_console_requires_headroom(self) -> None:
        content = BASE_STACK.replace(
            "  cerebro:apiMaxInstances: 2\n",
            "  cerebro:apiMaxInstances: 2\n  cerebro:webEnabled: true\n  cerebro:webMaxInstances: 1\n",
        )
        self.assertTrue(any("at least two tasks" in message for message in self._messages(content)))

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
