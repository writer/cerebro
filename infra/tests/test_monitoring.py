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

    def test_orchestrator_rule_alarm_schedules_skip_scheduler_backends(self) -> None:
        schedules = [
            {"name": "gcp-prod-audit", "backend": "scheduler"},
            {"name": "aws-secdev-us2-res-exp"},
            {"name": "gcp-prod-assets", "scheduleBackend": "scheduler"},
            {"name": "aws-prod-us1-subnet-inventory", "backend": "eventbridge"},
        ]

        alarm_schedules = monitoring._orchestrator_rule_alarm_schedules(schedules, 3)

        self.assertEqual(
            [schedule.get("name") if schedule else None for schedule in alarm_schedules],
            ["aws-secdev-us2-res-exp", "aws-prod-us1-subnet-inventory", None],
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

    def test_runtime_id_alarms_require_runtime_id_metrics(self) -> None:
        with self.assertRaisesRegex(ValueError, "runtime-id metrics"):
            monitoring.create_monitoring(
                name="cerebro-test",
                alb_arn_suffix="alb",
                target_group_arn_suffix="target",
                ecs_cluster_name="cluster",
                ecs_service_name="service",
                orchestrator_runtime_id_metrics_enabled=False,
                orchestrator_runtime_id_alarms_enabled=True,
            )

    def test_service_quota_alarm_specs_stay_disabled_until_dimensions_are_verified(self) -> None:
        self.assertEqual(monitoring._service_quota_alarm_specs("cerebro-test", 80), [])

    def test_cloudtrail_audit_specs_cover_control_plane_mutations(self) -> None:
        specs = monitoring._cloudtrail_audit_metric_filter_specs("cerebro-test")

        metrics = {spec["metric_name"]: spec["pattern"] for spec in specs}
        self.assertIn("AwsControlPlaneSchedulerMutations", metrics)
        self.assertIn("DeleteSchedule", metrics["AwsControlPlaneSchedulerMutations"])
        self.assertIn("AwsControlPlaneSqsDlqMutations", metrics)
        self.assertIn("PurgeQueue", metrics["AwsControlPlaneSqsDlqMutations"])
        self.assertIn("AwsControlPlaneAlarmMutations", metrics)
        self.assertIn("DisableAlarmActions", metrics["AwsControlPlaneAlarmMutations"])
        self.assertIn("AwsControlPlaneIamMutations", metrics)
        self.assertIn("UpdateAssumeRolePolicy", metrics["AwsControlPlaneIamMutations"])

    def test_nats_log_metric_filter_specs_cover_restore_failures(self) -> None:
        specs = monitoring._nats_log_metric_filter_specs()

        metrics = {spec["metric_name"]: spec["pattern"] for spec in specs.values()}
        self.assertEqual(
            set(metrics),
            {
                "NatsBootstrapErrors",
                "NatsCorruptStateRecoveries",
                "NatsHealthcheckFailures",
                "NatsRestoreCompletions",
            },
        )
        self.assertIn("Healthcheck failed", metrics["NatsHealthcheckFailures"])
        self.assertIn("nats: error", metrics["NatsBootstrapErrors"])
        self.assertIn("corrupt state file", metrics["NatsCorruptStateRecoveries"])
        self.assertIn("messages for stream", metrics["NatsRestoreCompletions"])

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
        self.assertIn("SourceId", body)

    def test_dashboard_includes_nats_jetstream_operations(self) -> None:
        original_get_region = monitoring.aws.get_region
        monitoring.aws.get_region = lambda: SimpleNamespace(region="us-east-1")
        try:
            body = monitoring._dashboard_body("cerebro-test", "alb", "tg", "cluster", "service", None, "CEREBRO_EVENTS")
        finally:
            monitoring.aws.get_region = original_get_region

        self.assertIn("NATS JetStream Operations", body)
        self.assertIn("NatsHealthcheckFailures", body)
        self.assertIn("NatsBootstrapErrors", body)
        self.assertIn("NatsCorruptStateRecoveries", body)
        self.assertIn("NatsRestoreCompletions", body)
        self.assertIn("JetStreamStreamBytes", body)
        self.assertIn("GraphRuleTimeouts", body)
        self.assertIn("GraphIngestDurationMs", body)
        self.assertIn("GraphRuleDurationMs", body)
        self.assertIn("Neo4jAuraInstanceUp", body)
        self.assertIn("Neo4jAuraMemoryGB", body)
        self.assertIn("App JetStream Reliability", body)
        self.assertIn("JetStreamAppErrors", body)
        self.assertIn("JetStreamJSErrors", body)
        self.assertIn("JetStreamAppendErrors", body)
        self.assertIn("JetStreamReplayErrors", body)
        self.assertIn("JetStreamPublishRetries", body)
        self.assertIn("JetStreamPublishRetryExhausted", body)
        self.assertIn("JetStreamCanaryFailures", body)
        self.assertIn("JetStreamCanaryLatencyMs", body)
        self.assertIn("JetStreamReplayLatencyMs", body)
        self.assertIn("JetStreamAppErrorsByKind", body)
        self.assertIn("Platform Job Lifecycle", body)
        self.assertIn("PlatformJobStarted", body)
        self.assertIn("PlatformJobCompleted", body)
        self.assertIn("PlatformJobFailed", body)
        self.assertIn("PlatformJobHeartbeats", body)
        self.assertIn("PlatformJobPhaseFailed", body)
        self.assertIn("PlatformJobRuntimeFailed", body)

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

    def test_dashboard_includes_otel_collector_visibility_when_enabled(self) -> None:
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
                otel_collector_enabled=True,
                otel_collector_log_group_name="/ecs/cerebro-test/otel-collector",
            )
        finally:
            monitoring.aws.get_region = original_get_region

        self.assertIn("OTEL Collector Container", body)
        self.assertIn("OTEL Collector Errors", body)
        self.assertIn("OTEL Collector Queue", body)
        self.assertIn("OTEL Collector Refused / Failed", body)
        self.assertIn("OTEL Collector Recent Logs", body)
        self.assertIn("OTEL Product Source Runtime", body)
        self.assertIn("OTEL Source Records / Freshness", body)
        self.assertIn("OTEL Projection Runs", body)
        self.assertIn("OTEL Projection Records", body)
        self.assertIn("OTEL Graph Rule Evaluations", body)
        self.assertIn("OTEL Graph Rule Records", body)
        self.assertIn("OTEL Orchestrator Phase SLO", body)
        self.assertIn("OTEL Neo4j Operations", body)
        self.assertIn("ECS/ContainerInsights", body)
        self.assertIn("OtelCollectorErrors", body)
        self.assertIn("otelcol_exporter_queue_size", body)
        self.assertIn("otelcol_exporter_send_failed_spans", body)
        self.assertIn("cerebro.source_runtime.sync.runs", body)
        self.assertIn("cerebro.source_runtime.records", body)
        self.assertIn("cerebro.source_runtime.watermark.lag", body)
        self.assertIn("cerebro.source_projection.records", body)
        self.assertIn("cerebro.graph_rule.evaluations", body)
        self.assertIn("cerebro.orchestrator.phase.duration", body)
        self.assertIn("cerebro.neo4j.operations", body)
        self.assertIn("/ecs/cerebro-test/otel-collector", body)

    def test_dashboard_includes_tenant_runtime_diagnostic_logs_when_app_log_group_is_set(self) -> None:
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
                app_log_group_name="/ecs/cerebro-test/api",
            )
        finally:
            monitoring.aws.get_region = original_get_region

        self.assertIn("Tenant Runtime Failures", body)
        self.assertIn("Tenant Runtime Failure Groups", body)
        self.assertIn("JetStream App Events", body)
        self.assertIn("JetStream App Event Groups", body)
        self.assertIn("Platform Job Events", body)
        self.assertIn("Platform Job Failure Groups", body)
        self.assertIn("/ecs/cerebro-test/api", body)
        self.assertIn('name = \\"jetstream.error\\"', body)
        self.assertIn('name = \\"jetstream.publish.retry_exhausted\\"', body)
        self.assertIn('name = \\"jetstream.canary.failed\\"', body)
        self.assertIn("messaging.jetstream.subject", body)
        self.assertIn("canary_duration_ms", body)
        self.assertIn("platform.job.phase.failed", body)
        self.assertIn("job_phase_key", body)
        self.assertIn('name = \\"source_runtime.sync\\"', body)
        self.assertIn('name = \\"source_projection.project\\"', body)
        self.assertIn("tenant_id", body)
        self.assertIn("source_id", body)
        self.assertIn("runtime_id", body)
        self.assertIn("stats count(*) as events by tenant_id, source_id, runtime_id, event_kind, error_kind", body)

    def test_dashboard_offsets_tenant_diagnostics_after_nats_operations(self) -> None:
        original_get_region = monitoring.aws.get_region
        monitoring.aws.get_region = lambda: SimpleNamespace(region="us-east-1")
        try:
            parsed = json.loads(
                monitoring._dashboard_body(
                    "cerebro-test",
                    "alb",
                    "tg",
                    "cluster",
                    "service",
                    None,
                    "CEREBRO_EVENTS",
                    app_log_group_name="/ecs/cerebro-test/api",
                )
            )
        finally:
            monitoring.aws.get_region = original_get_region

        by_title = {widget["properties"]["title"]: widget for widget in parsed["widgets"]}
        self.assertEqual(by_title["App JetStream Reliability"]["y"], 60)
        self.assertEqual(by_title["NATS JetStream Operations"]["y"], 60)
        self.assertEqual(by_title["JetStream App Events"]["y"], 66)
        self.assertEqual(by_title["JetStream App Event Groups"]["y"], 66)
        self.assertEqual(by_title["Tenant Runtime Failures"]["y"], 72)
        self.assertEqual(by_title["Tenant Runtime Failure Groups"]["y"], 72)
        self.assertEqual(by_title["Platform Job Events"]["y"], 78)
        self.assertEqual(by_title["Platform Job Failure Groups"]["y"], 78)

    def test_otel_product_metric_widgets_follow_collector_widgets(self) -> None:
        class Region:
            region = "us-east-1"

        original_get_region = monitoring.aws.get_region
        monitoring.aws.get_region = lambda: Region()
        try:
            widgets = monitoring._otel_product_metric_widgets(78)
        finally:
            monitoring.aws.get_region = original_get_region

        self.assertEqual([widget["properties"]["title"] for widget in widgets], [
            "OTEL Product Source Runtime",
            "OTEL Source Records / Freshness",
            "OTEL Projection Runs",
            "OTEL Projection Records",
            "OTEL Graph Rule Evaluations",
            "OTEL Graph Rule Records",
            "OTEL Orchestrator Phase SLO",
            "OTEL Neo4j Operations",
        ])
        self.assertEqual({widget["y"] for widget in widgets}, {78, 84, 90, 96})
        body = json.dumps({"widgets": widgets})
        self.assertIn("source_id,status,contract_configured", body)
        self.assertIn("source_id,status} MetricName=\\\"cerebro.source_projection.records", body)
        self.assertIn("source_id,status,truncated", body)
        self.assertIn("phase_key,source_id,status,timeout_exceeded", body)
        self.assertIn("operation,status,database_configured", body)
        self.assertNotIn("record.kind", body)
        self.assertNotIn("rule_id", body)
        self.assertNotIn("event_kind", body)
        self.assertNotIn("error_kind", body)
        self.assertNotIn("tenant_id", body)
        self.assertNotIn("runtime_id", body)
        self.assertNotIn("resource_urn", body)

    def test_otel_collector_metric_filters_roll_up_to_single_metric(self) -> None:
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
            filters = monitoring._create_otel_collector_metric_filters(
                "cerebro-test",
                "/ecs/cerebro-test/otel-collector",
                "Cerebro/cerebro-test",
            )
        finally:
            monitoring.aws.cloudwatch.LogMetricFilter = original_filter
            monitoring.aws.cloudwatch.LogMetricFilterMetricTransformationArgs = original_args

        self.assertEqual(
            set(filters),
            {
                "error",
                "error-uppercase",
                "failed",
                "dropped",
                "refused",
                "failed-detail",
                "dropped-detail",
                "refused-detail",
            },
        )
        self.assertTrue(all(call["log_group_name"] == "/ecs/cerebro-test/otel-collector" for call in calls))
        self.assertTrue(all(call["metric_transformation"].namespace == "Cerebro/cerebro-test" for call in calls))
        metric_names = {call["metric_transformation"].name for call in calls}
        self.assertIn("OtelCollectorErrors", metric_names)
        self.assertIn("OtelCollectorDropped", metric_names)
        self.assertIn("OtelCollectorRefused", metric_names)
        self.assertIn("OtelCollectorFailures", metric_names)

    def test_nats_log_metric_filters_roll_up_to_single_metrics(self) -> None:
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
            filters = monitoring._create_nats_log_metric_filters(
                "cerebro-test",
                "/ecs/cerebro-test/nats",
                "Cerebro/cerebro-test",
            )
        finally:
            monitoring.aws.cloudwatch.LogMetricFilter = original_filter
            monitoring.aws.cloudwatch.LogMetricFilterMetricTransformationArgs = original_args

        self.assertEqual(
            set(filters),
            {
                "nats_bootstrap_errors",
                "nats_corrupt_state_recoveries",
                "nats_healthcheck_failures",
                "nats_restore_completions",
            },
        )
        self.assertTrue(all(call["log_group_name"] == "/ecs/cerebro-test/nats" for call in calls))
        self.assertTrue(all(call["metric_transformation"].namespace == "Cerebro/cerebro-test" for call in calls))
        self.assertTrue(all(call["metric_transformation"].value == "1" for call in calls))
        self.assertTrue(all(call["metric_transformation"].default_value == 0 for call in calls))
        metric_names = {call["metric_transformation"].name for call in calls}
        self.assertEqual(
            metric_names,
            {
                "NatsBootstrapErrors",
                "NatsCorruptStateRecoveries",
                "NatsHealthcheckFailures",
                "NatsRestoreCompletions",
            },
        )

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

    def test_telemetry_metric_filters_include_graph_rule_and_neo4j_diagnostics(self) -> None:
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

        by_metric = {call["metric_transformation"].name: call for call in calls}
        for metric_name in {
            "GraphRuleFindingsEmittedBySource",
            "GraphRuleRowsReadBySource",
            "GraphRuleTimeouts",
            "GraphRuleTimeoutsBySource",
            "GraphIngestDurationMs",
            "GraphRuleDurationMs",
            "Neo4jConnectivityErrors",
            "Neo4jTransactionExecutionLimitErrors",
        }:
            self.assertIn(metric_name, by_metric)

        self.assertEqual(
            by_metric["GraphRuleFindingsEmittedBySource"]["metric_transformation"].dimensions,
            {"SourceId": "$.source_id"},
        )
        self.assertEqual(
            by_metric["GraphRuleTimeoutsBySource"]["metric_transformation"].dimensions,
            {"SourceId": "$.source_id"},
        )
        self.assertIn('$.name = "orchestrator.graph_rules"', by_metric["GraphRuleTimeouts"]["pattern"])
        self.assertIn("$.timeout_exceeded = true", by_metric["GraphRuleTimeouts"]["pattern"])
        self.assertEqual(by_metric["GraphIngestDurationMs"]["metric_transformation"].value, "$.duration_ms")
        self.assertEqual(by_metric["GraphRuleDurationMs"]["metric_transformation"].value, "$.duration_ms")
        self.assertIn("errorutil_connectivity_error", by_metric["Neo4jConnectivityErrors"]["pattern"])
        self.assertIn("errorutil_transaction_execution_limit", by_metric["Neo4jTransactionExecutionLimitErrors"]["pattern"])

    def test_telemetry_metric_filters_include_jetstream_canary_and_platform_jobs(self) -> None:
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

        by_metric = {call["metric_transformation"].name: call for call in calls}
        for metric_name in {
            "JetStreamCanaryCompleted",
            "JetStreamCanaryFailures",
            "JetStreamCanaryLatencyMs",
            "JetStreamAppendErrors",
            "JetStreamReplayErrors",
            "JetStreamReplayLatencyMs",
            "PlatformJobStarted",
            "PlatformJobCompleted",
            "PlatformJobFailed",
            "PlatformJobHeartbeats",
            "PlatformJobPhaseFailed",
            "PlatformJobPhaseFailedByPhase",
            "PlatformJobRuntimeFailed",
        }:
            self.assertIn(metric_name, by_metric)

        self.assertIn("OrchestratorRuntimeFailures", by_metric)
        self.assertNotIn("OrchestratorRuntimeCompletedByRuntime", by_metric)
        self.assertNotIn("OrchestratorRuntimeFailuresByRuntime", by_metric)
        self.assertIn('$.name = "jetstream.canary.completed"', by_metric["JetStreamCanaryCompleted"]["pattern"])
        self.assertEqual(by_metric["JetStreamCanaryLatencyMs"]["metric_transformation"].value, "$.canary_duration_ms")
        self.assertEqual(by_metric["JetStreamReplayLatencyMs"]["metric_transformation"].value, "$.duration_ms")
        self.assertEqual(
            by_metric["PlatformJobPhaseFailedByPhase"]["metric_transformation"].dimensions,
            {"Phase": "$.job_phase_key"},
        )

    def test_orchestrator_runtime_id_metric_filters_are_opt_in(self) -> None:
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
                orchestrator_runtime_id_metrics_enabled=True,
            )
        finally:
            monitoring.aws.cloudwatch.LogMetricFilter = original_filter
            monitoring.aws.cloudwatch.LogMetricFilterMetricTransformationArgs = original_args

        by_metric = {call["metric_transformation"].name: call for call in calls}
        self.assertEqual(
            by_metric["OrchestratorRuntimeCompletedByRuntime"]["metric_transformation"].dimensions,
            {"RuntimeId": "$.runtime_id"},
        )
        self.assertEqual(
            by_metric["OrchestratorRuntimeFailuresByRuntime"]["metric_transformation"].dimensions,
            {"RuntimeId": "$.runtime_id"},
        )

    def test_otel_collector_metric_filters_preserve_error_alarm_inputs(self) -> None:
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
            monitoring._create_otel_collector_metric_filters("cerebro-test", "otel-logs")
        finally:
            monitoring.aws.cloudwatch.LogMetricFilter = original_filter
            monitoring.aws.cloudwatch.LogMetricFilterMetricTransformationArgs = original_args

        self.assertEqual(
            {call["name"] for call in calls},
            {
                "cerebro-test-otel-collector-error",
                "cerebro-test-otel-collector-error-uppercase",
                "cerebro-test-otel-collector-refused",
                "cerebro-test-otel-collector-dropped",
                "cerebro-test-otel-collector-failed",
                "cerebro-test-otel-collector-refused-detail",
                "cerebro-test-otel-collector-dropped-detail",
                "cerebro-test-otel-collector-failed-detail",
            },
        )
        self.assertEqual({call["log_group_name"] for call in calls}, {"otel-logs"})
        for call in calls:
            self.assertEqual(call["metric_transformation"].value, "1")
            self.assertEqual(call["metric_transformation"].default_value, 0)
        by_name = {call["name"]: call["metric_transformation"].name for call in calls}
        self.assertEqual(by_name["cerebro-test-otel-collector-error"], "OtelCollectorErrors")
        self.assertEqual(by_name["cerebro-test-otel-collector-dropped-detail"], "OtelCollectorDropped")
        self.assertEqual(by_name["cerebro-test-otel-collector-refused-detail"], "OtelCollectorRefused")
        self.assertEqual(by_name["cerebro-test-otel-collector-failed-detail"], "OtelCollectorFailures")

    def test_source_runtime_observability_filters_roll_up_to_source_dimensions(self) -> None:
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

        source_calls = [
            call
            for call in calls
            if getattr(call["metric_transformation"], "dimensions", None) == {"SourceId": "$.source_id"}
            and call["metric_transformation"].name.startswith("SourceRuntime")
            and call["metric_transformation"].name
            not in {"SourceRuntimeEventsAppended", "SourceRuntimePagesRead", "SourceRuntimeWatermarkLagSeconds"}
        ]
        self.assertEqual(len(source_calls), 10)
        self.assertEqual(
            {call["metric_transformation"].name for call in source_calls},
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
        for call in source_calls:
            self.assertIn("source-runtime-observability", call["name"])
            self.assertEqual(call["metric_transformation"].dimensions, {"SourceId": "$.source_id"})
            self.assertIn("$.source_id = *", call["pattern"])
            self.assertNotIn("$.runtime_id = *", call["pattern"])
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
            self.assertTrue(spec["suffix"].startswith("source-runtime-observability-"))
            self.assertEqual(spec["dimensions"], {"SourceId": "$.source_id"})
            self.assertNotIn("tenant_id", spec["pattern"])
            self.assertNotIn("evidence_id", spec["pattern"])
            self.assertNotIn("resource_urn", spec["pattern"])
            self.assertNotIn("request_id", spec["pattern"])
            self.assertNotIn("trace_id", spec["pattern"])
            self.assertIn("$.source_id = *", spec["pattern"])
            self.assertNotIn("$.runtime_id = *", spec["pattern"])
        specs_by_metric = {spec["metric_name"]: spec for spec in specs}
        self.assertIn('$.name = "source_runtime.contract_probe"', specs_by_metric["SourceRuntimeContractProbeSuccess"]["pattern"])
        self.assertIn('$.contract_probe_status = "success"', specs_by_metric["SourceRuntimeContractProbeSuccess"]["pattern"])
        contract_failure_pattern = specs_by_metric["SourceRuntimeContractProbeFailure"]["pattern"]
        self.assertIn('$.contract_probe_status = "failure"', contract_failure_pattern)
        self.assertIn('$.contract_probe_status = "stale"', contract_failure_pattern)
        self.assertIn('$.contract_probe_status = "unknown"', contract_failure_pattern)
        validation_pattern = specs_by_metric["SourceRuntimeMissingCanonicalFields"]["pattern"]
        self.assertIn('$.name = "source_runtime.validation"', validation_pattern)
        self.assertIn("$.missing_canonical_field_class = *", validation_pattern)
        link_pattern = specs_by_metric["SourceRuntimeOrphanMissingLink"]["pattern"]
        self.assertIn('$.name = "runtime.evidence.link_status"', link_pattern)
        self.assertIn('$.link_status = "orphan"', link_pattern)
        self.assertIn('$.link_status = "missing_resource"', link_pattern)
        self.assertIn('$.link_status = "missing_case"', link_pattern)

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
        self.assertIn("sync successes", body)
        self.assertIn("SourceId", body)
        self.assertIn("Contract Probe Status", body)
        self.assertIn("Orphan / Missing Link Indicators", body)
        self.assertNotIn("writer-evidence-cas-cases", body)
        self.assertNotIn("writer-panopticon-alerts", body)
        self.assertNotIn("writer-okta-user", body)

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
                },
                {
                    "environment": "sec-dev",
                    "sourceSystem": "panopticon",
                    "sourceRuntimeId": "writer-panopticon-cases",
                    "runtimeClass": "case",
                    "enabled": True,
                    "freshnessSlaMinutes": 45,
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
        self.assertEqual(len(specs), 6)
        self.assertTrue(any(spec["comparison_operator"] == "LessThanThreshold" for spec in specs))
        self.assertTrue(all("inspect" in spec["description"] or "check" in spec["description"] for spec in specs))
        for spec in specs:
            self.assertEqual(spec["dimensions"], {"SourceId": "panopticon"})
            self.assertNotIn("writer-panopticon-alerts", spec["description"])
            self.assertNotIn("writer-panopticon-cases", spec["description"])
            self.assertNotIn("tenant_id", spec["description"])
            self.assertNotIn("resource_urn", spec["description"])
            self.assertNotIn("evidence_id", spec["description"])
            self.assertNotIn("arn:", spec["description"].lower())


if __name__ == "__main__":
    unittest.main()
