from __future__ import annotations

from datetime import UTC, datetime
from io import BytesIO
import json
import sys
import tempfile
import unittest
from pathlib import Path
from urllib.error import HTTPError
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.source_runtime_coverage_report import (
    _load_actual,
    _normalize_api_url,
    build_report,
    format_json,
    format_markdown,
    format_tsv,
)


STACK_YAML = """
config:
  cerebro:domain: cerebro.adm.prod.writer.com
  cerebro:sourceRuntimes:
    - id: writer-okta-audit
      sourceId: okta
      tenantId: writer
      config:
        family: audit
        per_page: "200"
    - id: writer-aws-prod-us1-public-endpoint
      sourceId: aws
      tenantId: writer
      config:
        family: public_endpoint
        account: prod
        region: us-east-1
    - id: writer-okta-audit-backfill
      sourceId: okta
      tenantId: writer
      config:
        family: audit
        since: "2026-01-01T00:00:00Z"
  cerebro:orchestratorSchedules:
    - name: okta-audit
      scheduleExpression: rate(10 minutes)
      taskCount: 1
      command:
        - orchestrator
        - run
        - runtime_id=writer-okta-audit
        - page_limit=20
    - name: aws-public-endpoint
      scheduleExpression: rate(15 minutes)
      taskCount: 1
      command:
        - orchestrator
        - run
        - runtime_id=writer-aws-prod-us1-public-endpoint
    - name: okta-audit-backfill
      scheduleExpression: rate(5 minutes)
      taskCount: 1
      removeAfter: "2026-08-15T00:00:00Z"
      command:
        - orchestrator
        - run
        - runtime_id=writer-okta-audit-backfill
"""


class SourceRuntimeCoverageReportTest(unittest.TestCase):
    def _stack_file(self, text: str = STACK_YAML, name: str = "Pulumi.go-prod.yaml") -> Path:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / name
        path.write_text(text, encoding="utf-8")
        return path

    def test_build_report_from_stack_only_counts_runtime_coverage(self) -> None:
        report = build_report(self._stack_file(), now=datetime(2026, 6, 1, tzinfo=UTC))

        self.assertEqual(report.stack, "go-prod")
        self.assertEqual(report.declared_runtime_count, 3)
        self.assertEqual(report.scheduled_runtime_count, 3)
        self.assertEqual(report.schedule_count, 3)
        self.assertIsNone(report.live_runtime_count)
        self.assertEqual(report.backfill_schedule_count, 1)
        self.assertEqual(report.expired_backfill_count, 0)
        self.assertEqual(report.sources, {"aws": 1, "okta": 2})
        self.assertEqual(report.findings, [])
        self.assertEqual(report.rows[0].schedule_cadence_seconds, 900)
        self.assertEqual(report.rows[0].stale_after_seconds, 1800)

    def test_missing_schedule_is_error(self) -> None:
        stack = self._stack_file(STACK_YAML.replace("        - runtime_id=writer-okta-audit\n", "        - runtime_id=writer-okta-audit-missing\n", 1))

        report = build_report(stack, now=datetime(2026, 6, 1, tzinfo=UTC))

        self.assertTrue(any(f.severity == "error" and f.runtime_id == "writer-okta-audit" and f.check == "schedule" for f in report.findings))
        self.assertTrue(any(f.severity == "warning" and f.runtime_id == "writer-okta-audit-missing" for f in report.findings))

    def test_grouped_schedule_counts_each_runtime(self) -> None:
        grouped = STACK_YAML.replace(
            "        - runtime_id=writer-okta-audit\n",
            "        - runtime_ids=writer-okta-audit,writer-aws-prod-us1-public-endpoint\n",
            1,
        ).replace(
            """    - name: aws-public-endpoint
      scheduleExpression: rate(15 minutes)
      taskCount: 1
      command:
        - orchestrator
        - run
        - runtime_id=writer-aws-prod-us1-public-endpoint
""",
            "",
        )

        report = build_report(self._stack_file(grouped), now=datetime(2026, 6, 1, tzinfo=UTC))

        self.assertEqual(report.scheduled_runtime_count, 3)
        self.assertFalse(any(f.runtime_id == "writer-aws-prod-us1-public-endpoint" and f.check == "schedule" for f in report.findings))

    def test_duplicate_schedule_is_error(self) -> None:
        duplicate = """
    - name: okta-audit-duplicate
      scheduleExpression: rate(30 minutes)
      command:
        - orchestrator
        - run
        - runtime_id=writer-okta-audit
"""
        stack = self._stack_file(STACK_YAML + duplicate)

        report = build_report(stack, now=datetime(2026, 6, 1, tzinfo=UTC))

        self.assertTrue(any(f.severity == "error" and "multiple" in f.message for f in report.findings))

    def test_live_runtime_missing_is_error(self) -> None:
        actual = [{"id": "writer-okta-audit", "source_id": "okta", "last_sync_at": "2026-06-01T00:00:00Z"}]

        report = build_report(self._stack_file(), actual=actual, now=datetime(2026, 6, 1, tzinfo=UTC))

        self.assertEqual(report.live_runtime_count, 1)
        self.assertTrue(any(f.severity == "error" and f.check == "live" for f in report.findings))

    def test_live_stale_runtime_is_warning(self) -> None:
        actual = [
            {"id": "writer-okta-audit", "source_id": "okta", "status": "ok", "last_synced_at": "2026-05-30T00:00:00Z"},
            {"id": "writer-aws-prod-us1-public-endpoint", "source_id": "aws", "status": "ok", "last_synced_at": "2026-06-01T00:00:00Z"},
            {"id": "writer-okta-audit-backfill", "source_id": "okta", "status": "ok", "last_synced_at": "2026-06-01T00:00:00Z"},
        ]

        report = build_report(
            self._stack_file(),
            actual=actual,
            max_age_hours=24,
            now=datetime(2026, 6, 1, tzinfo=UTC),
        )

        self.assertEqual(report.stale_runtime_count, 1)
        self.assertEqual(report.healthy_runtime_count, 2)
        self.assertTrue(any(f.severity == "warning" and f.check == "freshness" for f in report.findings))

    def test_live_stale_runtime_defaults_to_schedule_sla(self) -> None:
        actual = [
            {"id": "writer-okta-audit", "source_id": "okta", "status": "ok", "last_synced_at": "2026-06-01T11:00:00Z"},
            {"id": "writer-aws-prod-us1-public-endpoint", "source_id": "aws", "status": "ok", "last_synced_at": "2026-06-01T12:00:00Z"},
            {"id": "writer-okta-audit-backfill", "source_id": "okta", "status": "ok", "last_synced_at": "2026-06-01T12:00:00Z"},
        ]

        report = build_report(
            self._stack_file(),
            actual=actual,
            now=datetime(2026, 6, 1, 12, 0, tzinfo=UTC),
        )

        row = next(row for row in report.rows if row.runtime_id == "writer-okta-audit")
        self.assertEqual(row.schedule_cadence_seconds, 600)
        self.assertEqual(row.stale_after_seconds, 1200)
        self.assertEqual(report.stale_runtime_count, 1)
        self.assertTrue(any("stale_after_seconds=1200" in f.message for f in report.findings))

    def test_unexpected_live_runtime_is_warning(self) -> None:
        actual = [
            {"id": "writer-okta-audit", "source_id": "okta"},
            {"id": "writer-aws-prod-us1-public-endpoint", "source_id": "aws"},
            {"id": "writer-okta-audit-backfill", "source_id": "okta"},
            {"id": "writer-extra-runtime", "source_id": "github"},
        ]

        report = build_report(self._stack_file(), actual=actual, now=datetime(2026, 6, 1, tzinfo=UTC))

        self.assertTrue(any(f.severity == "warning" and f.runtime_id == "writer-extra-runtime" for f in report.findings))

    def test_external_runtime_is_declared_without_schedule(self) -> None:
        stack = self._stack_file(
            STACK_YAML.replace(
                "  cerebro:orchestratorSchedules:",
                "  cerebro:externalSourceRuntimes:\n"
                "    - id: writer-slack-companion\n"
                "      sourceId: sdk\n"
                "      tenantId: writer\n"
                "      owner: cerebro-slack-companion\n"
                "      reason: External service runtime.\n"
                "  cerebro:orchestratorSchedules:",
                1,
            )
        )
        actual = [
            {"id": "writer-okta-audit", "source_id": "okta"},
            {"id": "writer-aws-prod-us1-public-endpoint", "source_id": "aws"},
            {"id": "writer-okta-audit-backfill", "source_id": "okta"},
            {"id": "writer-slack-companion", "source_id": "sdk"},
        ]

        report = build_report(stack, actual=actual, now=datetime(2026, 6, 1, tzinfo=UTC))

        self.assertEqual(report.declared_runtime_count, 4)
        self.assertEqual(report.sources, {"aws": 1, "okta": 2, "sdk": 1})
        self.assertFalse(any(f.runtime_id == "writer-slack-companion" for f in report.findings))
        companion = next(row for row in report.rows if row.runtime_id == "writer-slack-companion")
        self.assertEqual(companion.schedule_name, "external")

    def test_temporarily_disabled_runtime_is_expected_without_schedule(self) -> None:
        stack = self._stack_file(
            STACK_YAML.replace(
                "  cerebro:orchestratorSchedules:",
                "  cerebro:temporarilyDisabledSourceRuntimes:\n"
                "    - runtimeId: writer-slack-users\n"
                "      owner: cerebro-platform\n"
                "      reason: invalid_credentials\n"
                "      disabledDate: \"2026-07-03\"\n"
                "      reviewDeadline: \"2026-07-10\"\n"
                "      reenableCriteria: \"Rotate token and pass live source runtime verification.\"\n"
                "  cerebro:orchestratorSchedules:",
                1,
            )
        )
        actual = [
            {"id": "writer-okta-audit", "source_id": "okta"},
            {"id": "writer-aws-prod-us1-public-endpoint", "source_id": "aws"},
            {"id": "writer-okta-audit-backfill", "source_id": "okta"},
            {"id": "writer-slack-users", "source_id": "slack", "last_synced_at": "2026-05-01T00:00:00Z"},
        ]

        report = build_report(stack, actual=actual, max_age_hours=24, now=datetime(2026, 6, 1, tzinfo=UTC))

        self.assertEqual(report.declared_runtime_count, 4)
        self.assertFalse(any(f.runtime_id == "writer-slack-users" for f in report.findings))
        disabled = next(row for row in report.rows if row.runtime_id == "writer-slack-users")
        self.assertEqual(disabled.schedule_name, "disabled")
        self.assertIsNone(disabled.stale_after_seconds)
        self.assertEqual(report.healthy_runtime_count, 3)

    def test_temporarily_disabled_runtime_can_be_absent_from_live_api(self) -> None:
        stack = self._stack_file(
            STACK_YAML.replace(
                "  cerebro:orchestratorSchedules:",
                "  cerebro:temporarilyDisabledSourceRuntimes:\n"
                "    - runtimeId: writer-slack-users\n"
                "      owner: cerebro-platform\n"
                "      reason: invalid_credentials\n"
                "      disabledDate: \"2026-07-03\"\n"
                "      reviewDeadline: \"2026-07-10\"\n"
                "      reenableCriteria: \"Rotate token and pass live source runtime verification.\"\n"
                "  cerebro:orchestratorSchedules:",
                1,
            )
        )
        actual = [
            {"id": "writer-okta-audit", "source_id": "okta"},
            {"id": "writer-aws-prod-us1-public-endpoint", "source_id": "aws"},
            {"id": "writer-okta-audit-backfill", "source_id": "okta"},
        ]

        report = build_report(stack, actual=actual, now=datetime(2026, 6, 1, tzinfo=UTC))

        self.assertFalse(any(f.runtime_id == "writer-slack-users" for f in report.findings))
        disabled = next(row for row in report.rows if row.runtime_id == "writer-slack-users")
        self.assertFalse(disabled.live_present)

    def test_expired_backfill_is_warning(self) -> None:
        stack = self._stack_file(STACK_YAML.replace('removeAfter: "2026-08-15T00:00:00Z"', 'removeAfter: "2026-01-15T00:00:00Z"'))

        report = build_report(stack, now=datetime(2026, 6, 1, tzinfo=UTC))

        self.assertEqual(report.expired_backfill_count, 1)
        self.assertTrue(any(f.severity == "warning" and f.check == "backfill" for f in report.findings))

    def test_markdown_includes_metrics_findings_and_rows(self) -> None:
        report = build_report(self._stack_file(), now=datetime(2026, 6, 1, tzinfo=UTC))

        markdown = format_markdown(report)

        self.assertIn("Source Runtime Coverage", markdown)
        self.assertIn("Declared runtimes", markdown)
        self.assertIn("writer-okta-audit", markdown)
        self.assertIn("No source runtime coverage gaps detected.", markdown)

    def test_json_is_parseable(self) -> None:
        report = build_report(self._stack_file(), now=datetime(2026, 6, 1, tzinfo=UTC))

        payload = json.loads(format_json(report))

        self.assertEqual(payload["stack"], "go-prod")
        self.assertEqual(payload["declared_runtime_count"], 3)
        self.assertEqual(len(payload["rows"]), 3)
        self.assertIn("schedule_cadence_seconds", payload["rows"][0])
        self.assertIn("stale_after_seconds", payload["rows"][0])

    def test_tsv_has_runtime_rows(self) -> None:
        report = build_report(self._stack_file(), now=datetime(2026, 6, 1, tzinfo=UTC))

        tsv = format_tsv(report)

        self.assertIn("runtime_id", tsv.splitlines()[0])
        self.assertIn("writer-aws-prod-us1-public-endpoint", tsv)

    def test_load_actual_accepts_object_payload(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "actual.json"
        path.write_text(json.dumps({"runtimes": [{"id": "writer-okta-audit"}]}), encoding="utf-8")

        self.assertEqual(_load_actual(path, "", "", "writer", 20), [{"id": "writer-okta-audit"}])

    def test_load_actual_accepts_list_payload(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "actual.json"
        path.write_text(json.dumps([{"id": "writer-okta-audit"}]), encoding="utf-8")

        self.assertEqual(_load_actual(path, "", "", "writer", 20), [{"id": "writer-okta-audit"}])

    def test_load_actual_includes_http_error_body(self) -> None:
        error = HTTPError(
            url="https://cerebro.example/source-runtimes",
            code=400,
            msg="Bad Request",
            hdrs={},
            fp=BytesIO(b'{"error":"invalid tenant_id"}'),
        )
        with patch("scripts.source_runtime_coverage_report.urlopen", side_effect=error):
            with self.assertRaisesRegex(RuntimeError, "HTTP 400: .*invalid tenant_id"):
                _load_actual(None, "https://cerebro.example", "token", "writer", 20)

    def test_load_actual_uses_supported_live_api_limit(self) -> None:
        class Response(BytesIO):
            def __enter__(self) -> "Response":
                return self

            def __exit__(self, *_args: object) -> None:
                self.close()

        def fake_urlopen(request, timeout: int) -> Response:
            self.assertIn("tenant_id=writer", request.full_url)
            self.assertIn("limit=500", request.full_url)
            self.assertEqual(timeout, 20)
            return Response(b'{"runtimes":[{"id":"writer-okta-audit"}]}')

        with patch("scripts.source_runtime_coverage_report.urlopen", side_effect=fake_urlopen):
            self.assertEqual(
                _load_actual(None, "https://cerebro.example.com", "token", "writer", 20),
                [{"id": "writer-okta-audit"}],
            )

    def test_normalize_api_url_uses_stack_domain_for_alb(self) -> None:
        self.assertEqual(
            _normalize_api_url("internal-cerebro-go-production-alb-123.us-east-1.elb.amazonaws.com", self._stack_file()),
            "https://cerebro.adm.prod.writer.com",
        )

    def test_normalize_api_url_uses_stack_domain_when_missing(self) -> None:
        self.assertEqual(_normalize_api_url("", self._stack_file()), "https://cerebro.adm.prod.writer.com")


if __name__ == "__main__":
    unittest.main()
