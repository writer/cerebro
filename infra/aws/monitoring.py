"""
AWS CloudWatch monitoring and alarms.
"""

import pulumi
import pulumi_aws as aws


def _safe_resource_suffix(value: str) -> str:
    suffix = "".join(ch if ch.isalnum() else "-" for ch in value.lower()).strip("-")
    return suffix[:80] or "item"


def _runtime_id_from_command(command) -> str:
    if not isinstance(command, list):
        return ""
    for arg in command:
        text = str(arg).strip()
        if text.startswith("runtime_id="):
            return text.split("=", 1)[1].strip()
    return ""


def _scheduled_source_runtime_ids(source_runtimes: list[dict], scheduled_runtime_ids: set[str]) -> list[str]:
    runtime_ids = {
        str(runtime.get("id", "")).strip()
        for runtime in source_runtimes or []
        if isinstance(runtime, dict) and str(runtime.get("id", "")).strip()
    }
    runtime_ids &= scheduled_runtime_ids
    return sorted(runtime_ids)


def _runtime_heartbeat_period_seconds(schedule: dict | None, default_period_seconds: int) -> int:
    expression = str((schedule or {}).get("scheduleExpression") or "").strip().lower()
    interval_seconds = _schedule_interval_seconds(expression)
    if interval_seconds <= 0:
        return default_period_seconds
    return max(900, interval_seconds * 3)


def _schedule_interval_seconds(expression: str) -> int:
    if expression.startswith("rate(") and expression.endswith(")"):
        parts = expression.removeprefix("rate(").removesuffix(")").split()
        if len(parts) >= 2 and parts[0].isdigit():
            count = int(parts[0])
            unit = parts[1].rstrip("s")
            if unit == "minute":
                return count * 60
            if unit == "hour":
                return count * 3600
    if expression.startswith("cron(") and expression.endswith(")"):
        fields = expression.removeprefix("cron(").removesuffix(")").split()
        if len(fields) >= 2:
            hour_interval = _cron_interval_value(fields[1])
            if hour_interval:
                return hour_interval * 3600
            if fields[1] == "*":
                return 3600
    return 0


def _cron_interval_value(field: str) -> int:
    if "/" not in field:
        return 0
    _, interval = field.rsplit("/", 1)
    return int(interval) if interval.isdigit() else 0


def create_monitoring(
    name: str,
    alb_arn_suffix: pulumi.Output[str],
    target_group_arn_suffix: pulumi.Output[str],
    ecs_cluster_name: pulumi.Output[str],
    ecs_service_name: pulumi.Output[str],
    web_alb_arn_suffix: pulumi.Output[str] = None,
    web_target_group_arn_suffix: pulumi.Output[str] = None,
    web_ecs_service_name: pulumi.Output[str] = None,
    log_group_name: pulumi.Output[str] = None,
    log_retention_days: int = 30,
    jetstream_stream_name: str = "CEREBRO_EVENTS",
    jetstream_lag_alarm_threshold: int = 10000,
    access_audit_denied_alarm_threshold: int = 0,
    access_audit_auth_failure_alarm_threshold: int = 0,
    alarm_action_arns: list[str] = None,
    alarm_email_subscriptions: list[str] = None,
    orchestrator_schedules: list[dict] = None,
    orchestrator_rule_names: list[pulumi.Input[str]] = None,
    source_runtimes: list[dict] = None,
    source_runtime_heartbeat_period_seconds: int = 28800,
) -> dict:
    """
    Create CloudWatch dashboard and alarms.
    """
    # SNS topic for alerts
    alarm_topic = aws.sns.Topic(
        f"{name}-alarms",
        name=f"{name}-alarms",
        tags={"Name": f"{name}-alarms"},
    )
    for email in sorted(set(alarm_email_subscriptions or [])):
        aws.sns.TopicSubscription(
            f"{name}-alarm-email-{_safe_resource_suffix(email)}",
            topic=alarm_topic.arn,
            protocol="email",
            endpoint=email,
        )
    alarm_actions = [alarm_topic.arn, *(alarm_action_arns or [])]

    # High error rate alarm
    aws.cloudwatch.MetricAlarm(
        f"{name}-5xx-alarm",
        name=f"{name}-high-5xx-errors",
        comparison_operator="GreaterThanThreshold",
        evaluation_periods=2,
        metric_name="HTTPCode_Target_5XX_Count",
        namespace="AWS/ApplicationELB",
        period=300,
        statistic="Sum",
        threshold=10,
        alarm_description="High 5xx error rate",
        alarm_actions=alarm_actions,
        treat_missing_data="notBreaching",
        dimensions={
            "LoadBalancer": alb_arn_suffix,
            "TargetGroup": target_group_arn_suffix,
        },
        tags={"Name": f"{name}-5xx-alarm"},
    )

    # High latency alarm
    aws.cloudwatch.MetricAlarm(
        f"{name}-latency-alarm",
        name=f"{name}-high-latency",
        comparison_operator="GreaterThanThreshold",
        evaluation_periods=3,
        metric_name="TargetResponseTime",
        namespace="AWS/ApplicationELB",
        period=300,
        statistic="Average",
        threshold=2.0,
        alarm_description="High API latency (>2s)",
        alarm_actions=alarm_actions,
        treat_missing_data="notBreaching",
        dimensions={
            "LoadBalancer": alb_arn_suffix,
            "TargetGroup": target_group_arn_suffix,
        },
        tags={"Name": f"{name}-latency-alarm"},
    )

    # Unhealthy targets alarm
    aws.cloudwatch.MetricAlarm(
        f"{name}-unhealthy-alarm",
        name=f"{name}-unhealthy-targets",
        comparison_operator="GreaterThanThreshold",
        evaluation_periods=2,
        metric_name="UnHealthyHostCount",
        namespace="AWS/ApplicationELB",
        period=60,
        statistic="Average",
        threshold=0,
        alarm_description="Unhealthy ECS tasks",
        alarm_actions=alarm_actions,
        dimensions={
            "LoadBalancer": alb_arn_suffix,
            "TargetGroup": target_group_arn_suffix,
        },
        tags={"Name": f"{name}-unhealthy-alarm"},
    )

    aws.cloudwatch.MetricAlarm(
        f"{name}-no-healthy-targets-alarm",
        name=f"{name}-no-healthy-targets",
        comparison_operator="LessThanThreshold",
        evaluation_periods=2,
        metric_name="HealthyHostCount",
        namespace="AWS/ApplicationELB",
        period=60,
        statistic="Average",
        threshold=1,
        treat_missing_data="breaching",
        alarm_description="No healthy ALB targets are registered",
        alarm_actions=alarm_actions,
        dimensions={
            "LoadBalancer": alb_arn_suffix,
            "TargetGroup": target_group_arn_suffix,
        },
        tags={"Name": f"{name}-no-healthy-targets-alarm"},
    )

    # ECS CPU alarm
    aws.cloudwatch.MetricAlarm(
        f"{name}-cpu-alarm",
        name=f"{name}-high-cpu",
        comparison_operator="GreaterThanThreshold",
        evaluation_periods=3,
        metric_name="CPUUtilization",
        namespace="AWS/ECS",
        period=300,
        statistic="Average",
        threshold=85,
        alarm_description="High ECS CPU utilization",
        alarm_actions=alarm_actions,
        dimensions={
            "ClusterName": ecs_cluster_name,
            "ServiceName": ecs_service_name,
        },
        tags={"Name": f"{name}-cpu-alarm"},
    )

    # ECS Memory alarm
    aws.cloudwatch.MetricAlarm(
        f"{name}-memory-alarm",
        name=f"{name}-high-memory",
        comparison_operator="GreaterThanThreshold",
        evaluation_periods=3,
        metric_name="MemoryUtilization",
        namespace="AWS/ECS",
        period=300,
        statistic="Average",
        threshold=85,
        alarm_description="High ECS memory utilization",
        alarm_actions=alarm_actions,
        dimensions={
            "ClusterName": ecs_cluster_name,
            "ServiceName": ecs_service_name,
        },
        tags={"Name": f"{name}-memory-alarm"},
    )

    if web_alb_arn_suffix and web_target_group_arn_suffix and web_ecs_service_name:
        aws.cloudwatch.MetricAlarm(
            f"{name}-web-5xx-alarm",
            name=f"{name}-web-high-5xx-errors",
            comparison_operator="GreaterThanThreshold",
            evaluation_periods=2,
            metric_name="HTTPCode_Target_5XX_Count",
            namespace="AWS/ApplicationELB",
            period=300,
            statistic="Sum",
            threshold=10,
            alarm_description="High web console 5xx error rate",
            alarm_actions=alarm_actions,
            treat_missing_data="notBreaching",
            dimensions={
                "LoadBalancer": web_alb_arn_suffix,
                "TargetGroup": web_target_group_arn_suffix,
            },
            tags={"Name": f"{name}-web-5xx-alarm"},
        )

        aws.cloudwatch.MetricAlarm(
            f"{name}-web-latency-alarm",
            name=f"{name}-web-high-latency",
            comparison_operator="GreaterThanThreshold",
            evaluation_periods=3,
            metric_name="TargetResponseTime",
            namespace="AWS/ApplicationELB",
            period=300,
            statistic="Average",
            threshold=2.0,
            alarm_description="High web console latency (>2s)",
            alarm_actions=alarm_actions,
            treat_missing_data="notBreaching",
            dimensions={
                "LoadBalancer": web_alb_arn_suffix,
                "TargetGroup": web_target_group_arn_suffix,
            },
            tags={"Name": f"{name}-web-latency-alarm"},
        )

        aws.cloudwatch.MetricAlarm(
            f"{name}-web-unhealthy-alarm",
            name=f"{name}-web-unhealthy-targets",
            comparison_operator="GreaterThanThreshold",
            evaluation_periods=2,
            metric_name="UnHealthyHostCount",
            namespace="AWS/ApplicationELB",
            period=60,
            statistic="Average",
            threshold=0,
            alarm_description="Unhealthy web console ECS tasks",
            alarm_actions=alarm_actions,
            dimensions={
                "LoadBalancer": web_alb_arn_suffix,
                "TargetGroup": web_target_group_arn_suffix,
            },
            tags={"Name": f"{name}-web-unhealthy-alarm"},
        )

        aws.cloudwatch.MetricAlarm(
            f"{name}-web-no-healthy-targets-alarm",
            name=f"{name}-web-no-healthy-targets",
            comparison_operator="LessThanThreshold",
            evaluation_periods=2,
            metric_name="HealthyHostCount",
            namespace="AWS/ApplicationELB",
            period=60,
            statistic="Average",
            threshold=1,
            treat_missing_data="breaching",
            alarm_description="No healthy web console ALB targets are registered",
            alarm_actions=alarm_actions,
            dimensions={
                "LoadBalancer": web_alb_arn_suffix,
                "TargetGroup": web_target_group_arn_suffix,
            },
            tags={"Name": f"{name}-web-no-healthy-targets-alarm"},
        )

        aws.cloudwatch.MetricAlarm(
            f"{name}-web-cpu-alarm",
            name=f"{name}-web-high-cpu",
            comparison_operator="GreaterThanThreshold",
            evaluation_periods=3,
            metric_name="CPUUtilization",
            namespace="AWS/ECS",
            period=300,
            statistic="Average",
            threshold=85,
            alarm_description="High web console ECS CPU utilization",
            alarm_actions=alarm_actions,
            dimensions={
                "ClusterName": ecs_cluster_name,
                "ServiceName": web_ecs_service_name,
            },
            tags={"Name": f"{name}-web-cpu-alarm"},
        )

        aws.cloudwatch.MetricAlarm(
            f"{name}-web-memory-alarm",
            name=f"{name}-web-high-memory",
            comparison_operator="GreaterThanThreshold",
            evaluation_periods=3,
            metric_name="MemoryUtilization",
            namespace="AWS/ECS",
            period=300,
            statistic="Average",
            threshold=85,
            alarm_description="High web console ECS memory utilization",
            alarm_actions=alarm_actions,
            dimensions={
                "ClusterName": ecs_cluster_name,
                "ServiceName": web_ecs_service_name,
            },
            tags={"Name": f"{name}-web-memory-alarm"},
        )

    # CloudWatch Dashboard
    telemetry_filters = {}
    telemetry_namespace = f"Cerebro/{name}"
    if log_group_name is not None:
        telemetry_filters = _create_telemetry_metric_filters(name, log_group_name)
        _custom_metric_alarm(
            resource_name=f"{name}-source-runtime-failures-alarm",
            alarm_name=f"{name}-source-runtime-sync-failures",
            namespace=telemetry_namespace,
            metric_name="SourceRuntimeSyncFailures",
            threshold=0,
            description="Source runtime sync failures detected",
            alarm_actions=alarm_actions,
        )
        _custom_metric_alarm(
            resource_name=f"{name}-orchestrator-failures-alarm",
            alarm_name=f"{name}-orchestrator-runtime-failures",
            namespace=telemetry_namespace,
            metric_name="OrchestratorRuntimeFailures",
            threshold=0,
            description="Orchestrator runtime failures detected",
            alarm_actions=alarm_actions,
        )
        _custom_metric_alarm(
            resource_name=f"{name}-report-failures-alarm",
            alarm_name=f"{name}-report-generation-failures",
            namespace=telemetry_namespace,
            metric_name="ReportGenerationFailures",
            threshold=0,
            description="Report generation failures detected",
            alarm_actions=alarm_actions,
        )
        _custom_metric_alarm(
            resource_name=f"{name}-graph-ingest-failures-alarm",
            alarm_name=f"{name}-graph-ingest-failures",
            namespace=telemetry_namespace,
            metric_name="GraphIngestFailures",
            threshold=0,
            description="Graph ingestion failures detected",
            alarm_actions=alarm_actions,
        )
        _custom_metric_alarm(
            resource_name=f"{name}-finding-evaluation-run-failures-alarm",
            alarm_name=f"{name}-finding-evaluation-run-failures",
            namespace=telemetry_namespace,
            metric_name="FindingEvaluationRunFailures",
            threshold=0,
            description="Finding evaluation run failures detected",
            alarm_actions=alarm_actions,
        )
        if access_audit_denied_alarm_threshold > 0:
            _custom_metric_alarm(
                resource_name=f"{name}-access-audit-denied-alarm",
                alarm_name=f"{name}-access-audit-denied",
                namespace=telemetry_namespace,
                metric_name="AccessAuditDenied",
                threshold=access_audit_denied_alarm_threshold,
                description="Cerebro API access denials exceeded the configured threshold",
                alarm_actions=alarm_actions,
            )
        if access_audit_auth_failure_alarm_threshold > 0:
            _custom_metric_alarm(
                resource_name=f"{name}-access-audit-auth-failures-alarm",
                alarm_name=f"{name}-access-audit-auth-failures",
                namespace=telemetry_namespace,
                metric_name="AccessAuditAuthFailures",
                threshold=access_audit_auth_failure_alarm_threshold,
                description="Cerebro API unauthenticated access attempts exceeded the configured threshold",
                alarm_actions=alarm_actions,
            )

    if jetstream_lag_alarm_threshold > 0:
        _custom_metric_alarm(
            resource_name=f"{name}-jetstream-lag-alarm",
            alarm_name=f"{name}-jetstream-consumer-lag",
            namespace=telemetry_namespace,
            metric_name="JetStreamConsumerLag",
            threshold=jetstream_lag_alarm_threshold,
            description="JetStream consumer lag is above the autoscaling readiness threshold",
            alarm_actions=alarm_actions,
            statistic="Maximum",
            dimensions={"Service": name, "Stream": jetstream_stream_name},
        )

    runtime_ids = sorted({
        runtime_id
        for runtime_id in (_runtime_id_from_command(schedule.get("command")) for schedule in orchestrator_schedules or [])
        if runtime_id
    })
    for runtime_id in runtime_ids:
        _custom_metric_alarm(
            resource_name=f"{name}-orchestrator-runtime-{_safe_resource_suffix(runtime_id)}-failures-alarm",
            alarm_name=f"{name}-orchestrator-{runtime_id}-failures",
            namespace=telemetry_namespace,
            metric_name="OrchestratorRuntimeFailuresByRuntime",
            threshold=0,
            description=f"Orchestrator runtime failures detected for {runtime_id}",
            alarm_actions=alarm_actions,
            dimensions={"RuntimeId": runtime_id},
        )

    schedules_by_runtime = {
        runtime_id: schedule
        for schedule in orchestrator_schedules or []
        if isinstance(schedule, dict)
        for runtime_id in [_runtime_id_from_command(schedule.get("command"))]
        if runtime_id
    }
    for runtime_id in _scheduled_source_runtime_ids(source_runtimes or [], set(runtime_ids)):
        _runtime_heartbeat_alarm(
            resource_name=f"{name}-source-runtime-{_safe_resource_suffix(runtime_id)}-heartbeat-alarm",
            alarm_name=f"{name}-source-{runtime_id}-stale",
            namespace=telemetry_namespace,
            metric_name="OrchestratorRuntimeCompletedByRuntime",
            runtime_id=runtime_id,
            period=_runtime_heartbeat_period_seconds(
                schedules_by_runtime.get(runtime_id),
                source_runtime_heartbeat_period_seconds,
            ),
            alarm_actions=alarm_actions,
        )

    for index, rule_name in enumerate(orchestrator_rule_names or []):
        aws.cloudwatch.MetricAlarm(
            f"{name}-orchestrator-rule-{index}-failed-invocations",
            name=pulumi.Output.concat(rule_name, "-failed-invocations"),
            comparison_operator="GreaterThanThreshold",
            evaluation_periods=1,
            metric_name="FailedInvocations",
            namespace="AWS/Events",
            period=300,
            statistic="Sum",
            threshold=0,
            treat_missing_data="notBreaching",
            alarm_description=pulumi.Output.concat("EventBridge failed invocations for ", rule_name),
            alarm_actions=alarm_actions,
            dimensions={"RuleName": rule_name},
            tags={"Name": pulumi.Output.concat(rule_name, "-failed-invocations")},
        )

    dashboard = aws.cloudwatch.Dashboard(
        f"{name}-dashboard",
        dashboard_name=f"{name}-dashboard",
        dashboard_body=pulumi.Output.all(
            alb_arn_suffix, target_group_arn_suffix, ecs_cluster_name, ecs_service_name
        ).apply(lambda args: _dashboard_body(name, *args, jetstream_stream_name)),
    )

    return {
        "alarm_topic": alarm_topic,
        "dashboard": dashboard,
        "telemetry_filters": telemetry_filters,
    }


def _custom_metric_alarm(
    resource_name: str,
    alarm_name: str,
    namespace: str,
    metric_name: str,
    threshold: int,
    description: str,
    alarm_actions: list[pulumi.Input[str]],
    statistic: str = "Sum",
    dimensions: dict = None,
) -> aws.cloudwatch.MetricAlarm:
    return aws.cloudwatch.MetricAlarm(
        resource_name,
        name=alarm_name,
        comparison_operator="GreaterThanThreshold",
        evaluation_periods=1,
        metric_name=metric_name,
        namespace=namespace,
        period=300,
        statistic=statistic,
        threshold=threshold,
        treat_missing_data="notBreaching",
        alarm_description=description,
        alarm_actions=alarm_actions,
        dimensions=dimensions,
        tags={"Name": alarm_name},
    )


def _runtime_heartbeat_alarm(
    resource_name: str,
    alarm_name: str,
    namespace: str,
    metric_name: str,
    runtime_id: str,
    period: int,
    alarm_actions: list[pulumi.Input[str]],
) -> aws.cloudwatch.MetricAlarm:
    return aws.cloudwatch.MetricAlarm(
        resource_name,
        name=alarm_name,
        comparison_operator="LessThanThreshold",
        evaluation_periods=1,
        metric_name=metric_name,
        namespace=namespace,
        period=period,
        statistic="Sum",
        threshold=1,
        treat_missing_data="breaching",
        alarm_description=f"No successful source runtime sync observed for {runtime_id}",
        alarm_actions=alarm_actions,
        dimensions={"RuntimeId": runtime_id},
        tags={"Name": alarm_name},
    )


def _access_audit_metric_filter_specs() -> dict[str, dict[str, str]]:
    return {
        "access_audit_events": {
            "suffix": "access-audit-events",
            "metric_name": "AccessAuditEvents",
            "pattern": '{ $.kind = "event" && $.name = "cerebro.api.access" }',
        },
        "access_audit_allowed": {
            "suffix": "access-audit-allowed",
            "metric_name": "AccessAuditAllowed",
            "pattern": '{ $.kind = "event" && $.name = "cerebro.api.access" && $.outcome = "allowed" }',
        },
        "access_audit_denied": {
            "suffix": "access-audit-denied",
            "metric_name": "AccessAuditDenied",
            "pattern": '{ $.kind = "event" && $.name = "cerebro.api.access" && $.outcome = "denied" }',
        },
        "access_audit_auth_failures": {
            "suffix": "access-audit-auth-failures",
            "metric_name": "AccessAuditAuthFailures",
            "pattern": '{ $.kind = "event" && $.name = "cerebro.api.access" && $.denial_reason = "unauthenticated" }',
        },
        "access_audit_forbidden": {
            "suffix": "access-audit-forbidden",
            "metric_name": "AccessAuditForbidden",
            "pattern": '{ $.kind = "event" && $.name = "cerebro.api.access" && $.status = 403 }',
        },
    }


def _create_access_audit_metric_filters(name: str, log_group_name: pulumi.Output[str], namespace: str) -> dict:
    filters = {}
    for key, spec in _access_audit_metric_filter_specs().items():
        suffix = spec["suffix"]
        filters[key] = aws.cloudwatch.LogMetricFilter(
            f"{name}-{suffix}-filter",
            name=f"{name}-{suffix}",
            log_group_name=log_group_name,
            pattern=spec["pattern"],
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name=spec["metric_name"],
                namespace=namespace,
                value="1",
                default_value=0,
            ),
        )
    return filters


def _create_telemetry_metric_filters(name: str, log_group_name: pulumi.Output[str]) -> dict:
    namespace = f"Cerebro/{name}"
    filters = {
        "source_sync_events": aws.cloudwatch.LogMetricFilter(
            f"{name}-source-sync-events-filter",
            name=f"{name}-source-sync-events",
            log_group_name=log_group_name,
            pattern='{ $.kind = "span_end" && $.name = "source_runtime.sync" && $.status = "completed" }',
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="SourceRuntimeEventsAppended",
                namespace=namespace,
                value="$.events_appended",
                default_value=0,
            ),
        ),
        "source_sync_pages": aws.cloudwatch.LogMetricFilter(
            f"{name}-source-sync-pages-filter",
            name=f"{name}-source-sync-pages",
            log_group_name=log_group_name,
            pattern='{ $.kind = "span_end" && $.name = "source_runtime.sync" && $.status = "completed" }',
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="SourceRuntimePagesRead",
                namespace=namespace,
                value="$.pages_read",
                default_value=0,
            ),
        ),
        "source_sync_failures": aws.cloudwatch.LogMetricFilter(
            f"{name}-source-sync-failures-filter",
            name=f"{name}-source-sync-failures",
            log_group_name=log_group_name,
            pattern='{ $.kind = "span_end" && $.name = "source_runtime.sync" && $.status = "failed" }',
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="SourceRuntimeSyncFailures",
                namespace=namespace,
                value="1",
                default_value=0,
            ),
        ),
        "orchestrator_completed_by_runtime": aws.cloudwatch.LogMetricFilter(
            f"{name}-orchestrator-completed-by-runtime-filter",
            name=f"{name}-orchestrator-completed-by-runtime",
            log_group_name=log_group_name,
            pattern='{ $.kind = "span_end" && $.name = "orchestrator.runtime" && $.status = "completed" }',
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="OrchestratorRuntimeCompletedByRuntime",
                namespace=namespace,
                value="1",
                dimensions={"RuntimeId": "$.runtime_id"},
            ),
        ),
        "orchestrator_failures": aws.cloudwatch.LogMetricFilter(
            f"{name}-orchestrator-failures-filter",
            name=f"{name}-orchestrator-failures",
            log_group_name=log_group_name,
            pattern='{ $.kind = "span_end" && $.name = "orchestrator.runtime" && $.status = "failed" }',
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="OrchestratorRuntimeFailures",
                namespace=namespace,
                value="1",
                default_value=0,
            ),
        ),
        "orchestrator_failures_by_runtime": aws.cloudwatch.LogMetricFilter(
            f"{name}-orchestrator-failures-by-runtime-filter",
            name=f"{name}-orchestrator-failures-by-runtime",
            log_group_name=log_group_name,
            pattern='{ $.kind = "span_end" && $.name = "orchestrator.runtime" && $.status = "failed" }',
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="OrchestratorRuntimeFailuresByRuntime",
                namespace=namespace,
                value="1",
                dimensions={"RuntimeId": "$.runtime_id"},
            ),
        ),
        **_create_access_audit_metric_filters(name, log_group_name, namespace),
        "graph_entities": aws.cloudwatch.LogMetricFilter(
            f"{name}-graph-entities-filter",
            name=f"{name}-graph-entities",
            log_group_name=log_group_name,
            pattern='{ $.kind = "span_end" && $.name = "orchestrator.runtime" && $.status = "completed" }',
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="GraphEntitiesProjected",
                namespace=namespace,
                value="$.entities_projected",
                default_value=0,
            ),
        ),
        "finding_evaluation_failures": aws.cloudwatch.LogMetricFilter(
            f"{name}-finding-evaluation-failures-filter",
            name=f"{name}-finding-evaluation-failures",
            log_group_name=log_group_name,
            pattern='{ $.kind = "event" && $.name = "finding_evaluation.run" && $.status = "failed" }',
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="FindingEvaluationRunFailures",
                namespace=namespace,
                value="1",
                default_value=0,
            ),
        ),
        "finding_evaluation_events_processed": aws.cloudwatch.LogMetricFilter(
            f"{name}-finding-evaluation-events-processed-filter",
            name=f"{name}-finding-evaluation-events-processed",
            log_group_name=log_group_name,
            pattern='{ $.kind = "event" && $.name = "finding_evaluation.run" && $.events_processed = * }',
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="FindingEvaluationEventsProcessed",
                namespace=namespace,
                value="$.events_processed",
                default_value=0,
            ),
        ),
        "finding_evaluation_events_matched": aws.cloudwatch.LogMetricFilter(
            f"{name}-finding-evaluation-events-matched-filter",
            name=f"{name}-finding-evaluation-events-matched",
            log_group_name=log_group_name,
            pattern='{ $.kind = "event" && $.name = "finding_evaluation.run" && $.events_matched = * }',
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="FindingEvaluationEventsMatched",
                namespace=namespace,
                value="$.events_matched",
                default_value=0,
            ),
        ),
        "finding_evaluation_findings_emitted": aws.cloudwatch.LogMetricFilter(
            f"{name}-finding-evaluation-findings-emitted-filter",
            name=f"{name}-finding-evaluation-findings-emitted",
            log_group_name=log_group_name,
            pattern='{ $.kind = "event" && $.name = "finding_evaluation.run" && $.findings_emitted = * }',
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="FindingEvaluationFindingsEmitted",
                namespace=namespace,
                value="$.findings_emitted",
                default_value=0,
            ),
        ),
        "graph_rule_rows_read": aws.cloudwatch.LogMetricFilter(
            f"{name}-graph-rule-rows-read-filter",
            name=f"{name}-graph-rule-rows-read",
            log_group_name=log_group_name,
            pattern='{ $.kind = "span_end" && $.name = "orchestrator.runtime" && $.graph_rule_rows_read = * }',
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="GraphRuleRowsRead",
                namespace=namespace,
                value="$.graph_rule_rows_read",
                default_value=0,
            ),
        ),
        "graph_rule_findings": aws.cloudwatch.LogMetricFilter(
            f"{name}-graph-rule-findings-filter",
            name=f"{name}-graph-rule-findings",
            log_group_name=log_group_name,
            pattern='{ $.kind = "span_end" && $.name = "orchestrator.runtime" && $.graph_rule_findings = * }',
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="GraphRuleFindingsEmitted",
                namespace=namespace,
                value="$.graph_rule_findings",
                default_value=0,
            ),
        ),
        "report_failures": aws.cloudwatch.LogMetricFilter(
            f"{name}-report-failures-filter",
            name=f"{name}-report-failures",
            log_group_name=log_group_name,
            pattern='{ $.status = "failed" && $.name = "report.*" }',
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="ReportGenerationFailures",
                namespace=namespace,
                value="1",
                default_value=0,
            ),
        ),
        "graph_ingest_failures": aws.cloudwatch.LogMetricFilter(
            f"{name}-graph-ingest-failures-filter",
            name=f"{name}-graph-ingest-failures",
            log_group_name=log_group_name,
            pattern='{ $.status = "failed" && $.name = "graph.*" }',
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="GraphIngestFailures",
                namespace=namespace,
                value="1",
                default_value=0,
            ),
        ),
        "graph_ingest_lag": aws.cloudwatch.LogMetricFilter(
            f"{name}-graph-ingest-lag-filter",
            name=f"{name}-graph-ingest-lag",
            log_group_name=log_group_name,
            pattern='{ $.graph_ingest_lag_seconds = * }',
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="GraphIngestLagSeconds",
                namespace=namespace,
                value="$.graph_ingest_lag_seconds",
                default_value=0,
            ),
        ),
    }
    return filters


def _dashboard_body(name: str, alb_arn: str, tg_arn: str, cluster: str, service: str, jetstream_stream_name: str) -> str:
    import json
    telemetry_namespace = f"Cerebro/{name}"
    return json.dumps({
        "widgets": [
            {
                "type": "metric",
                "x": 0, "y": 0, "width": 12, "height": 6,
                "properties": {
                    "title": "Request Count",
                    "metrics": [
                        ["AWS/ApplicationELB", "RequestCount", "LoadBalancer", alb_arn, {"stat": "Sum"}]
                    ],
                    "period": 60,
                    "region": aws.get_region().region,
                },
            },
            {
                "type": "metric",
                "x": 12, "y": 0, "width": 12, "height": 6,
                "properties": {
                    "title": "Response Time",
                    "metrics": [
                        ["AWS/ApplicationELB", "TargetResponseTime", "LoadBalancer", alb_arn, {"stat": "Average"}]
                    ],
                    "period": 60,
                    "region": aws.get_region().region,
                },
            },
            {
                "type": "metric",
                "x": 0, "y": 6, "width": 12, "height": 6,
                "properties": {
                    "title": "ECS CPU",
                    "metrics": [
                        ["AWS/ECS", "CPUUtilization", "ClusterName", cluster, "ServiceName", service]
                    ],
                    "period": 60,
                    "region": aws.get_region().region,
                },
            },
            {
                "type": "metric",
                "x": 12, "y": 6, "width": 12, "height": 6,
                "properties": {
                    "title": "ECS Memory",
                    "metrics": [
                        ["AWS/ECS", "MemoryUtilization", "ClusterName", cluster, "ServiceName", service]
                    ],
                    "period": 60,
                    "region": aws.get_region().region,
                },
            },
            {
                "type": "metric",
                "x": 0, "y": 12, "width": 12, "height": 6,
                "properties": {
                    "title": "HTTP 5xx Errors",
                    "metrics": [
                        ["AWS/ApplicationELB", "HTTPCode_Target_5XX_Count", "LoadBalancer", alb_arn, "TargetGroup", tg_arn, {"stat": "Sum"}]
                    ],
                    "period": 60,
                    "region": aws.get_region().region,
                },
            },
            {
                "type": "metric",
                "x": 12, "y": 12, "width": 12, "height": 6,
                "properties": {
                    "title": "Healthy Targets",
                    "metrics": [
                        ["AWS/ApplicationELB", "HealthyHostCount", "LoadBalancer", alb_arn, "TargetGroup", tg_arn]
                    ],
                    "period": 60,
                    "region": aws.get_region().region,
                },
            },
            {
                "type": "metric",
                "x": 0, "y": 18, "width": 12, "height": 6,
                "properties": {
                    "title": "Source Runtime Throughput",
                    "metrics": [
                        [telemetry_namespace, "SourceRuntimeEventsAppended", {"stat": "Sum"}],
                        [".", "SourceRuntimePagesRead", {"stat": "Sum"}],
                    ],
                    "period": 60,
                    "region": aws.get_region().region,
                },
            },
            {
                "type": "metric",
                "x": 12, "y": 18, "width": 12, "height": 6,
                "properties": {
                    "title": "Orchestrator Flow",
                    "metrics": [
                        [telemetry_namespace, "GraphEntitiesProjected", {"stat": "Sum"}],
                        [".", "SourceRuntimeSyncFailures", {"stat": "Sum"}],
                        [".", "OrchestratorRuntimeFailures", {"stat": "Sum"}],
                    ],
                    "period": 60,
                    "region": aws.get_region().region,
                },
            },
            {
                "type": "metric",
                "x": 0, "y": 24, "width": 12, "height": 6,
                "properties": {
                    "title": "JetStream Consumer Lag",
                    "metrics": [
                        [telemetry_namespace, "JetStreamConsumerLag", "Service", name, "Stream", jetstream_stream_name, {"stat": "Maximum"}],
                    ],
                    "period": 60,
                    "region": aws.get_region().region,
                },
            },
            {
                "type": "metric",
                "x": 12, "y": 24, "width": 12, "height": 6,
                "properties": {
                    "title": "JetStream Stream Depth",
                    "metrics": [
                        [telemetry_namespace, "JetStreamStreamMessages", "Service", name, "Stream", jetstream_stream_name, {"stat": "Maximum"}],
                        [".", "JetStreamStreamBytes", ".", ".", ".", ".", {"stat": "Maximum", "yAxis": "right"}],
                    ],
                    "period": 60,
                    "region": aws.get_region().region,
                },
            },
            {
                "type": "metric",
                "x": 0, "y": 30, "width": 12, "height": 6,
                "properties": {
                    "title": "Runtime / Report Failures",
                    "metrics": [
                        [telemetry_namespace, "SourceRuntimeSyncFailures", {"stat": "Sum"}],
                        [".", "OrchestratorRuntimeFailures", {"stat": "Sum"}],
                        [".", "ReportGenerationFailures", {"stat": "Sum"}],
                    ],
                    "period": 300,
                    "region": aws.get_region().region,
                },
            },
            {
                "type": "metric",
                "x": 12, "y": 30, "width": 12, "height": 6,
                "properties": {
                    "title": "Graph Ingest Health",
                    "metrics": [
                        [telemetry_namespace, "GraphEntitiesProjected", {"stat": "Sum"}],
                        [".", "GraphIngestFailures", {"stat": "Sum"}],
                        [".", "GraphIngestLagSeconds", {"stat": "Maximum", "yAxis": "right"}],
                    ],
                    "period": 300,
                    "region": aws.get_region().region,
                },
            },
            {
                "type": "metric",
                "x": 0, "y": 36, "width": 12, "height": 6,
                "properties": {
                    "title": "Finding Evaluation Throughput",
                    "metrics": [
                        [telemetry_namespace, "FindingEvaluationEventsProcessed", {"stat": "Sum"}],
                        [".", "FindingEvaluationEventsMatched", {"stat": "Sum"}],
                        [".", "FindingEvaluationFindingsEmitted", {"stat": "Sum"}],
                    ],
                    "period": 300,
                    "region": aws.get_region().region,
                },
            },
            {
                "type": "metric",
                "x": 12, "y": 36, "width": 12, "height": 6,
                "properties": {
                    "title": "Finding Evaluation / Graph Rule Health",
                    "metrics": [
                        [telemetry_namespace, "FindingEvaluationRunFailures", {"stat": "Sum"}],
                        [".", "GraphRuleRowsRead", {"stat": "Sum"}],
                        [".", "GraphRuleFindingsEmitted", {"stat": "Sum"}],
                    ],
                    "period": 300,
                    "region": aws.get_region().region,
                },
            },
            {
                "type": "metric",
                "x": 0, "y": 42, "width": 12, "height": 6,
                "properties": {
                    "title": "API Access Audit Volume",
                    "metrics": [
                        [telemetry_namespace, "AccessAuditEvents", {"stat": "Sum"}],
                        [".", "AccessAuditAllowed", {"stat": "Sum"}],
                    ],
                    "period": 300,
                    "region": aws.get_region().region,
                },
            },
            {
                "type": "metric",
                "x": 12, "y": 42, "width": 12, "height": 6,
                "properties": {
                    "title": "API Access Denials",
                    "metrics": [
                        [telemetry_namespace, "AccessAuditDenied", {"stat": "Sum"}],
                        [".", "AccessAuditAuthFailures", {"stat": "Sum"}],
                        [".", "AccessAuditForbidden", {"stat": "Sum"}],
                    ],
                    "period": 300,
                    "region": aws.get_region().region,
                },
            },
        ],
    })
