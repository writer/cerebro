from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.validate_stack_config import validate_stack


BASE_STACK = """
config:
  cerebro:environment: go-production
  cerebro:ecrBaseUri: 123456789012.dkr.ecr.us-east-1.amazonaws.com/cerebro
  cerebro:imageTag: v2.1.29
  cerebro:apiMaxInstances: 1
  cerebro:postgresDeletionProtection: true
  cerebro:postgresBackupRetentionDays: 14
  cerebro:apiAuthEnabled: true
  cerebro:allowedTenants:
    - writer
  cerebro:sourceSecretKeys:
    - API_TOKEN
  cerebro:orchestratorSchedules:
    - name: okta-audit
      scheduleExpression: cron(0 * * * ? *)
      taskCount: 1
      command:
        - orchestrator
        - run
        - runtime_id=writer-okta-audit
  cerebro:sourceRuntimes:
    - id: writer-okta-audit
      sourceId: okta
      tenantId: writer
      config:
        api_token: env:API_TOKEN
"""


class ValidateStackConfigTest(unittest.TestCase):
    def _write_stack(self, content: str, name: str = "Pulumi.go-prod.yaml") -> Path:
        self.tmpdir = tempfile.TemporaryDirectory()
        path = Path(self.tmpdir.name) / name
        path.write_text(content, encoding="utf-8")
        return path

    def _messages(self, content: str) -> list[str]:
        return [finding.message for finding in validate_stack(self._write_stack(content))]

    def tearDown(self) -> None:
        tmpdir = getattr(self, "tmpdir", None)
        if tmpdir is not None:
            tmpdir.cleanup()

    def test_valid_stack_has_no_errors(self) -> None:
        findings = validate_stack(self._write_stack(BASE_STACK))
        self.assertEqual([finding for finding in findings if finding.severity == "error"], [])

    def test_missing_source_secret_is_error(self) -> None:
        content = BASE_STACK.replace("    - API_TOKEN\n", "")
        self.assertTrue(any("not listed in cerebro:sourceSecretKeys" in message for message in self._messages(content)))

    def test_unknown_scheduled_runtime_is_error(self) -> None:
        content = BASE_STACK.replace("runtime_id=writer-okta-audit", "runtime_id=writer-missing")
        self.assertTrue(any("unknown runtime id" in message for message in self._messages(content)))

    def test_prod_guardrails_are_errors(self) -> None:
        content = BASE_STACK.replace("  cerebro:postgresDeletionProtection: true", "  cerebro:postgresDeletionProtection: false")
        self.assertTrue(any("deletion protection" in message for message in self._messages(content)))

    def test_backfill_without_retirement_metadata_is_warning(self) -> None:
        content = BASE_STACK.replace("name: okta-audit", "name: okta-audit-backfill")
        findings = validate_stack(self._write_stack(content))
        self.assertTrue(any(finding.severity == "warning" and "backfill schedules" in finding.message for finding in findings))

    def test_backfill_retirement_metadata_clears_warning(self) -> None:
        content = BASE_STACK.replace("name: okta-audit", 'name: okta-audit-backfill\n      removeAfter: "2099-01-01"')
        findings = validate_stack(self._write_stack(content))
        self.assertFalse(any(finding.severity == "warning" and "backfill schedules" in finding.message for finding in findings))

    def test_backfill_retirement_metadata_rejects_past_date(self) -> None:
        content = BASE_STACK.replace("name: okta-audit", 'name: okta-audit-backfill\n      removeAfter: "2000-01-01"')
        findings = validate_stack(self._write_stack(content))
        self.assertTrue(any(finding.severity == "error" and "past" in finding.message for finding in findings))


if __name__ == "__main__":
    unittest.main()
