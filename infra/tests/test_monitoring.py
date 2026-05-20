from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path
from types import SimpleNamespace


spec = importlib.util.spec_from_file_location("monitoring", Path(__file__).resolve().parents[1] / "aws" / "monitoring.py")
monitoring = importlib.util.module_from_spec(spec)
spec.loader.exec_module(monitoring)


class MonitoringRuntimeTest(unittest.TestCase):
    def test_source_runtime_ids_are_limited_to_scheduled_runtimes(self) -> None:
        runtimes = [
            {"id": "writer-cosmo-session", "sourceId": "cosmo"},
            {"id": "writer-okta-audit", "sourceId": "okta"},
            {"id": "writer-unscheduled", "sourceId": "aws"},
        ]

        self.assertEqual(
            monitoring._scheduled_source_runtime_ids(
                runtimes,
                {"writer-cosmo-session", "writer-okta-audit"},
            ),
            ["writer-cosmo-session", "writer-okta-audit"],
        )

    def test_source_runtime_ids_ignore_unscheduled_runtimes(self) -> None:
        runtimes = [
            {"id": "writer-cosmo-session", "sourceId": "cosmo"},
            {"id": "writer-okta-audit", "sourceId": "okta"},
        ]

        self.assertEqual(
            monitoring._scheduled_source_runtime_ids(runtimes, set()),
            [],
        )

    def test_runtime_heartbeat_period_follows_rate_schedule(self) -> None:
        schedule = {"scheduleExpression": "rate(30 minutes)"}
        self.assertEqual(monitoring._runtime_heartbeat_period_seconds(schedule, 28800), 5400)

    def test_runtime_heartbeat_period_follows_cron_hour_step(self) -> None:
        schedule = {"scheduleExpression": "cron(3 0/6 * * ? *)"}
        self.assertEqual(monitoring._runtime_heartbeat_period_seconds(schedule, 28800), 64800)

    def test_dashboard_includes_access_audit_metrics(self) -> None:
        original_get_region = monitoring.aws.get_region
        monitoring.aws.get_region = lambda: SimpleNamespace(region="us-east-1")
        try:
            body = json.loads(monitoring._dashboard_body("cerebro-test", "alb", "tg", "cluster", "service", "CEREBRO_EVENTS"))
        finally:
            monitoring.aws.get_region = original_get_region

        metric_names = {
            metric[1]
            for widget in body["widgets"]
            for metric in widget["properties"]["metrics"]
            if isinstance(metric, list) and len(metric) > 1
        }
        self.assertIn("AccessAuditEvents", metric_names)
        self.assertIn("AccessAuditAllowed", metric_names)
        self.assertIn("AccessAuditDenied", metric_names)
        self.assertIn("AccessAuditAuthFailures", metric_names)
        self.assertIn("AccessAuditUnauthorized", metric_names)
        self.assertIn("AccessAuditForbidden", metric_names)
        self.assertIn("AccessAuditRateLimited", metric_names)
        self.assertIn("AccessAuditClientErrors", metric_names)
        self.assertIn("AccessAuditServerErrors", metric_names)
        self.assertIn("AccessAuditTenantMismatch", metric_names)
        self.assertIn("AccessAuditSensitiveActions", metric_names)
        self.assertIn("AccessAuditSensitiveDenied", metric_names)
        self.assertIn("AccessAuditWriteActions", metric_names)
        self.assertIn("AccessAuditWriteDenied", metric_names)

    def test_access_audit_metric_filter_specs_are_low_cardinality(self) -> None:
        specs = monitoring._access_audit_metric_filter_specs()
        self.assertEqual(
            sorted(spec["metric_name"] for spec in specs.values()),
            [
                "AccessAuditAllowed",
                "AccessAuditAuthFailures",
                "AccessAuditClientErrors",
                "AccessAuditDenied",
                "AccessAuditEvents",
                "AccessAuditForbidden",
                "AccessAuditRateLimited",
                "AccessAuditSensitiveActions",
                "AccessAuditSensitiveDenied",
                "AccessAuditServerErrors",
                "AccessAuditTenantMismatch",
                "AccessAuditUnauthorized",
                "AccessAuditWriteActions",
                "AccessAuditWriteDenied",
            ],
        )
        for spec in specs.values():
            self.assertIn('$.name = "cerebro.api.access"', spec["pattern"])
            self.assertNotIn("principal", spec["pattern"])
            self.assertNotIn("tenant_id", spec["pattern"])
            self.assertNotIn("route", spec["pattern"])
            self.assertNotIn("dimensions", spec)

    def test_graph_ingest_failure_filter_matches_runtime_and_orchestrator_spans(self) -> None:
        pattern = monitoring._graph_ingest_failure_pattern()

        self.assertIn('$.kind = "span_end"', pattern)
        self.assertIn('$.status = "failed"', pattern)
        self.assertIn('$.name = "graph.ingest_runtime"', pattern)
        self.assertIn('$.name = "orchestrator.graph_ingest"', pattern)

    def test_dashboard_searches_dimensioned_watermark_lag_metric(self) -> None:
        class Region:
            region = "us-east-1"

        original_get_region = monitoring.aws.get_region
        monitoring.aws.get_region = lambda: Region()
        try:
            body = monitoring._dashboard_body("cerebro-test", "alb", "tg", "cluster", "service", "CEREBRO_EVENTS")
        finally:
            monitoring.aws.get_region = original_get_region

        self.assertIn("SourceRuntimeWatermarkLagSeconds", body)
        self.assertIn("RuntimeId", body)


if __name__ == "__main__":
    unittest.main()
