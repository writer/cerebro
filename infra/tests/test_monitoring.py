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

    def test_orchestrator_rule_alarm_resource_name_uses_schedule_name(self) -> None:
        self.assertEqual(
            monitoring._orchestrator_rule_alarm_resource_name(
                "cerebro-test",
                3,
                {"name": "aws-secdev-us2-res-exp"},
            ),
            "cerebro-test-orchestrator-rule-aws-secdev-us2-res-exp-failed-invocations",
        )

    def test_scheduler_alarm_specs_cover_dlq_and_target_failures(self) -> None:
        specs = monitoring._scheduler_alarm_specs(
            "cerebro-test",
            schedule_group_name="cerebro-test-orchestrator",
            dlq_queue_name="cerebro-test-orchestrator-scheduler-dlq",
        )

        by_metric = {spec["metric_name"]: spec for spec in specs}
        self.assertEqual(by_metric["TargetErrorCount"]["namespace"], "AWS/Scheduler")
        self.assertEqual(by_metric["TargetErrorCount"]["dimensions"], {"ScheduleGroup": "cerebro-test-orchestrator"})
        self.assertEqual(by_metric["InvocationDroppedCount"]["namespace"], "AWS/Scheduler")
        self.assertEqual(by_metric["ApproximateNumberOfMessagesVisible"]["namespace"], "AWS/SQS")
        self.assertEqual(
            by_metric["ApproximateNumberOfMessagesVisible"]["dimensions"],
            {"QueueName": "cerebro-test-orchestrator-scheduler-dlq"},
        )
        self.assertEqual(by_metric["ApproximateAgeOfOldestMessage"]["threshold"], 900)

    def test_service_quota_alarm_specs_stay_disabled_until_dimensions_are_verified(self) -> None:
        self.assertEqual(monitoring._service_quota_alarm_specs("cerebro-test", 80), [])

    def test_dashboard_includes_access_audit_metrics(self) -> None:
        original_get_region = monitoring.aws.get_region
        monitoring.aws.get_region = lambda: SimpleNamespace(region="us-east-1")
        try:
            body = json.loads(monitoring._dashboard_body("cerebro-test", "alb", "tg", "cluster", "service", None, "CEREBRO_EVENTS"))
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
            body = monitoring._dashboard_body("cerebro-test", "alb", "tg", "cluster", "service", None, "CEREBRO_EVENTS")
        finally:
            monitoring.aws.get_region = original_get_region

        self.assertIn("SourceRuntimeWatermarkLagSeconds", body)
        self.assertIn("RuntimeId", body)

    def test_dashboard_includes_postgres_metrics_when_identifier_is_set(self) -> None:
        original_get_region = monitoring.aws.get_region
        monitoring.aws.get_region = lambda: SimpleNamespace(region="us-east-1")
        try:
            body = monitoring._dashboard_body("cerebro-test", "alb", "tg", "cluster", "service", "cerebro-test-postgres", "CEREBRO_EVENTS")
        finally:
            monitoring.aws.get_region = original_get_region

        self.assertIn("Postgres Latency / Queue", body)
        self.assertIn("DiskQueueDepth", body)
        self.assertIn("ReadLatency", body)
        self.assertIn("WriteLatency", body)
        self.assertIn("DatabaseConnections", body)

    def test_dashboard_includes_saturation_and_grc_latency_metrics(self) -> None:
        original_get_region = monitoring.aws.get_region
        monitoring.aws.get_region = lambda: SimpleNamespace(region="us-east-1")
        try:
            body = monitoring._dashboard_body("cerebro-test", "alb", "tg", "cluster", "service", None, "CEREBRO_EVENTS")
        finally:
            monitoring.aws.get_region = original_get_region

        self.assertIn("RequestCountPerTarget", body)
        self.assertIn("GRCDashboardLatencyMs", body)
        self.assertIn('"stat": "p95"', body)

    def test_telemetry_metric_filters_include_grc_dashboard_latency(self) -> None:
        calls: list[dict] = []

        def fake_filter(*args, **kwargs):
            calls.append({"resource": args[0], **kwargs})
            return SimpleNamespace(name=kwargs.get("name"))

        def fake_args(**kwargs):
            return SimpleNamespace(**kwargs)

        original_filter = monitoring.aws.cloudwatch.LogMetricFilter
        original_args = monitoring.aws.cloudwatch.LogMetricFilterMetricTransformationArgs
        monitoring.aws.cloudwatch.LogMetricFilter = fake_filter
        monitoring.aws.cloudwatch.LogMetricFilterMetricTransformationArgs = fake_args
        try:
            monitoring._create_telemetry_metric_filters("cerebro-test", "logs")
        finally:
            monitoring.aws.cloudwatch.LogMetricFilter = original_filter
            monitoring.aws.cloudwatch.LogMetricFilterMetricTransformationArgs = original_args

        grc_call = next(call for call in calls if call["name"] == "cerebro-test-grc-dashboard-latency")
        self.assertIn('$.name = "grc.dashboard"', grc_call["pattern"])
        self.assertEqual(grc_call["metric_transformation"].name, "GRCDashboardLatencyMs")
        self.assertEqual(grc_call["metric_transformation"].value, "$.duration_ms")
        self.assertEqual(grc_call["metric_transformation"].dimensions, {"Dashboard": "$.dashboard"})

    def test_source_runtime_observability_filters_use_bounded_runtime_dimensions(self) -> None:
        calls: list[dict] = []

        def fake_filter(*args, **kwargs):
            calls.append({"resource": args[0], **kwargs})
            return SimpleNamespace(name=kwargs.get("name"))

        def fake_args(**kwargs):
            return SimpleNamespace(**kwargs)

        original_filter = monitoring.aws.cloudwatch.LogMetricFilter
        original_args = monitoring.aws.cloudwatch.LogMetricFilterMetricTransformationArgs
        monitoring.aws.cloudwatch.LogMetricFilter = fake_filter
        monitoring.aws.cloudwatch.LogMetricFilterMetricTransformationArgs = fake_args
        try:
            monitoring._create_telemetry_metric_filters(
                "cerebro-test",
                "logs",
                [
                    {
                        "environment": "sec-dev",
                        "sourceSystem": "panopticon",
                        "sourceRuntimeId": "writer-panopticon-alerts",
                        "runtimeClass": "alert",
                        "enabled": True,
                        "freshnessSlaMinutes": 30,
                        "dashboardEnabled": True,
                        "alarmEnabled": True,
                        "logGroupRef": "runtime",
                        "alarmRoute": "default",
                        "observabilityStates": ["success", "failure", "stale", "disabled", "unknown", "not_configured"],
                    }
                ],
            )
        finally:
            monitoring.aws.cloudwatch.LogMetricFilter = original_filter
            monitoring.aws.cloudwatch.LogMetricFilterMetricTransformationArgs = original_args

        runtime_calls = [
            call
            for call in calls
            if getattr(call["metric_transformation"], "dimensions", None) == {"RuntimeId": "$.runtime_id"}
            and call["metric_transformation"].name.startswith("SourceRuntime")
            and call["metric_transformation"].name
            not in {"SourceRuntimeEventsAppended", "SourceRuntimePagesRead", "SourceRuntimeWatermarkLagSeconds"}
        ]
        self.assertEqual(len(runtime_calls), 10)
        self.assertEqual(
            {call["metric_transformation"].name for call in runtime_calls},
            {
                "SourceRuntimeContractProbeFailure",
                "SourceRuntimeContractProbeSuccess",
                "SourceRuntimeIngestFailure",
                "SourceRuntimeIngestSuccess",
                "SourceRuntimeMissingCanonicalFields",
                "SourceRuntimeOrphanMissingLink",
                "SourceRuntimeProjectionFailure",
                "SourceRuntimeProjectionSuccess",
                "SourceRuntimeRecordsAccepted",
                "SourceRuntimeRecordsRejected",
            },
        )
        for call in runtime_calls:
            self.assertIn("sourceruntimepanopticonalert", call["name"])
            self.assertEqual(call["metric_transformation"].dimensions, {"RuntimeId": "$.runtime_id"})
            self.assertFalse(hasattr(call["metric_transformation"], "default_value"))

    def test_source_runtime_observability_specs_are_bounded_and_complete(self) -> None:
        specs = monitoring._source_runtime_observability_metric_specs(
            [
                {
                    "environment": "sec-dev",
                    "sourceSystem": "evidence_cas",
                    "sourceRuntimeId": "writer-evidence-cas-cases",
                    "runtimeClass": "object",
                    "enabled": True,
                    "freshnessSlaMinutes": 90,
                    "dashboardEnabled": True,
                    "alarmEnabled": True,
                    "logGroupRef": "runtime",
                    "alarmRoute": "default",
                    "observabilityStates": ["success", "failure", "stale", "disabled", "unknown", "not_configured"],
                },
                {
                    "environment": "sec-dev",
                    "sourceSystem": "panopticon",
                    "sourceRuntimeId": "writer-panopticon-alerts",
                    "runtimeClass": "alert",
                    "enabled": True,
                    "freshnessSlaMinutes": 30,
                    "dashboardEnabled": True,
                    "alarmEnabled": True,
                    "logGroupRef": "runtime",
                    "alarmRoute": "default",
                    "observabilityStates": ["success", "failure", "stale", "disabled", "unknown", "not_configured"],
                },
                {
                    "environment": "sec-dev",
                    "sourceSystem": "okta",
                    "sourceRuntimeId": "writer-okta-user",
                    "runtimeClass": "user",
                    "enabled": True,
                    "freshnessSlaMinutes": 90,
                    "dashboardEnabled": True,
                    "alarmEnabled": True,
                    "logGroupRef": "runtime",
                    "alarmRoute": "default",
                    "observabilityStates": ["success", "failure", "stale", "disabled", "unknown", "not_configured"],
                },
            ]
        )

        metric_names = [spec["metric_name"] for spec in specs]
        self.assertEqual(
            metric_names,
            [
                "SourceRuntimeIngestSuccess",
                "SourceRuntimeIngestFailure",
                "SourceRuntimeRecordsAccepted",
                "SourceRuntimeRecordsRejected",
                "SourceRuntimeProjectionSuccess",
                "SourceRuntimeProjectionFailure",
                "SourceRuntimeContractProbeSuccess",
                "SourceRuntimeContractProbeFailure",
                "SourceRuntimeMissingCanonicalFields",
                "SourceRuntimeOrphanMissingLink",
            ],
        )
        for spec in specs:
            self.assertTrue(spec["suffix"].startswith("sourceruntimeevidencecasobject-"))
            self.assertEqual(spec["dimensions"], {"RuntimeId": "$.runtime_id"})
            self.assertNotIn("tenant_id", spec["pattern"])
            self.assertNotIn("evidence_id", spec["pattern"])
            self.assertNotIn("resource_urn", spec["pattern"])
            self.assertNotIn("request_id", spec["pattern"])
            self.assertNotIn("trace_id", spec["pattern"])

    def test_dashboard_includes_source_runtime_observability_sections(self) -> None:
        original_get_region = monitoring.aws.get_region
        monitoring.aws.get_region = lambda: SimpleNamespace(region="us-east-1")
        try:
            body = monitoring._dashboard_body(
                "cerebro-test",
                "alb",
                "tg",
                "cluster",
                "service",
                None,
                "CEREBRO_EVENTS",
                [
                    {
                        "environment": "sec-dev",
                        "sourceSystem": "evidence_cas",
                        "sourceRuntimeId": "writer-evidence-cas-cases",
                        "runtimeClass": "object",
                        "enabled": True,
                        "freshnessSlaMinutes": 90,
                        "dashboardEnabled": True,
                        "alarmEnabled": True,
                        "logGroupRef": "runtime",
                        "alarmRoute": "default",
                        "observabilityStates": ["success", "failure", "stale", "disabled", "unknown", "not_configured"],
                    },
                    {
                        "environment": "sec-dev",
                        "sourceSystem": "panopticon",
                        "sourceRuntimeId": "writer-panopticon-alerts",
                        "runtimeClass": "alert",
                        "enabled": True,
                        "freshnessSlaMinutes": 30,
                        "dashboardEnabled": True,
                        "alarmEnabled": True,
                        "logGroupRef": "runtime",
                        "alarmRoute": "default",
                        "observabilityStates": ["success", "failure", "stale", "disabled", "unknown", "not_configured"],
                    },
                    {
                        "environment": "sec-dev",
                        "sourceSystem": "okta",
                        "sourceRuntimeId": "writer-okta-user",
                        "runtimeClass": "user",
                        "enabled": True,
                        "freshnessSlaMinutes": 90,
                        "dashboardEnabled": True,
                        "alarmEnabled": True,
                        "logGroupRef": "runtime",
                        "alarmRoute": "default",
                        "observabilityStates": ["success", "failure", "stale", "disabled", "unknown", "not_configured"],
                    },
                ],
            )
        finally:
            monitoring.aws.get_region = original_get_region

        self.assertIn("EvidenceCAS Source Runtime Health", body)
        self.assertIn("Panopticon Source Runtime Health", body)
        self.assertIn("Okta Source Runtime Health", body)
        self.assertIn("User sync successes", body)
        self.assertIn("Contract Probe Status", body)
        self.assertIn("Orphan / Missing Link Indicators", body)
        self.assertIn("writer-evidence-cas-cases", body)
        self.assertIn("writer-panopticon-alerts", body)
        self.assertIn("writer-okta-user", body)

    def test_source_runtime_observability_alarm_specs_are_actionable_and_redacted(self) -> None:
        specs = monitoring._source_runtime_observability_alarm_specs(
            "cerebro-test",
            [
                {
                    "environment": "sec-dev",
                    "sourceSystem": "panopticon",
                    "sourceRuntimeId": "writer-panopticon-alerts",
                    "runtimeClass": "alert",
                    "enabled": True,
                    "freshnessSlaMinutes": 30,
                    "dashboardEnabled": True,
                    "alarmEnabled": True,
                    "logGroupRef": "runtime",
                    "alarmRoute": "default",
                    "observabilityStates": ["success", "failure", "stale", "disabled", "unknown", "not_configured"],
                }
            ],
        )

        self.assertEqual(
            {spec["metric_name"] for spec in specs},
            {
                "SourceRuntimeContractProbeFailure",
                "SourceRuntimeIngestFailure",
                "SourceRuntimeIngestSuccess",
                "SourceRuntimeMissingCanonicalFields",
                "SourceRuntimeOrphanMissingLink",
                "SourceRuntimeProjectionFailure",
            },
        )
        self.assertTrue(any(spec["comparison_operator"] == "LessThanThreshold" for spec in specs))
        self.assertTrue(all("inspect" in spec["description"] or "check" in spec["description"] for spec in specs))
        for spec in specs:
            self.assertEqual(spec["dimensions"], {"RuntimeId": "writer-panopticon-alerts"})
            self.assertNotIn("writer-panopticon-alerts", spec["description"])
            self.assertNotIn("tenant_id", spec["description"])
            self.assertNotIn("resource_urn", spec["description"])
            self.assertNotIn("evidence_id", spec["description"])
            self.assertNotIn("arn:", spec["description"].lower())


if __name__ == "__main__":
    unittest.main()
