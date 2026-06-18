"""
AWS CloudWatch monitoring and alarms.
"""

import pulumi
import pulumi_aws as aws


def _safe_resource_suffix(value: str) -> str:
    suffix = "".join(ch if ch.isalnum() else "-" for ch in value.lower()).strip("-")
    return suffix[:80] or "item"


def _orchestrator_rule_alarm_resource_name(name: str, index: int, schedule: dict | None) -> str:
    schedule_name = str((schedule or {}).get("name") or "").strip()
    suffix = _safe_resource_suffix(schedule_name) if schedule_name else str(index)
    return f"{name}-orchestrator-rule-{suffix}-failed-invocations"


def _orchestrator_rule_alarm_schedules(orchestrator_schedules: list[dict] | None, rule_count: int) -> list[dict | None]:
    eventbridge_schedules = [
        schedule
        for schedule in orchestrator_schedules or []
        if str(schedule.get("backend") or schedule.get("scheduleBackend") or "eventbridge").strip() == "eventbridge"
    ]
    return [
        eventbridge_schedules[index] if index < len(eventbridge_schedules) else None
        for index in range(rule_count)
    ]


def _scheduler_alarm_specs(name: str, schedule_group_name: pulumi.Input[str] = None, dlq_queue_name: pulumi.Input[str] = None) -> list[dict]:
    specs = []
    if schedule_group_name:
        specs.extend(
            [
                {
                    "resource_name": f"{name}-scheduler-target-errors-alarm",
                    "alarm_name": f"{name}-scheduler-target-errors",
                    "namespace": "AWS/Scheduler",
                    "metric_name": "TargetErrorCount",
                    "dimensions": {"ScheduleGroup": schedule_group_name},
                    "description": "EventBridge Scheduler target invocations failed for orchestrator schedules; inspect ECS RunTask failures and Scheduler DLQ.",
                },
                {
                    "resource_name": f"{name}-scheduler-dropped-invocations-alarm",
                    "alarm_name": f"{name}-scheduler-dropped-invocations",
                    "namespace": "AWS/Scheduler",
                    "metric_name": "InvocationDroppedCount",
                    "dimensions": {"ScheduleGroup": schedule_group_name},
                    "description": "EventBridge Scheduler dropped orchestrator invocations after retries or event age limits.",
                },
            ]
        )
    if dlq_queue_name:
        specs.extend(
            [
                {
                    "resource_name": f"{name}-scheduler-dlq-visible-alarm",
                    "alarm_name": f"{name}-scheduler-dlq-visible",
                    "namespace": "AWS/SQS",
                    "metric_name": "ApproximateNumberOfMessagesVisible",
                    "dimensions": {"QueueName": dlq_queue_name},
                    "description": "EventBridge Scheduler DLQ has undelivered orchestrator events waiting for triage.",
                },
                {
                    "resource_name": f"{name}-scheduler-dlq-age-alarm",
                    "alarm_name": f"{name}-scheduler-dlq-age",
                    "namespace": "AWS/SQS",
                    "metric_name": "ApproximateAgeOfOldestMessage",
                    "dimensions": {"QueueName": dlq_queue_name},
                    "description": "EventBridge Scheduler DLQ contains stale undelivered orchestrator events.",
                    "threshold": 900,
                    "statistic": "Maximum",
                },
            ]
        )
    return specs


def _service_quota_alarm_specs(name: str, threshold_percent: int) -> list[dict]:
    if threshold_percent <= 0:
        return []
    return []


def _cloudtrail_audit_metric_filter_specs(name: str) -> list[dict]:
    return [
        {
            "resource_name": f"{name}-audit-scheduler-mutations-filter",
            "filter_name": f"{name}-audit-scheduler-mutations",
            "metric_name": "AwsControlPlaneSchedulerMutations",
            "pattern": '{ ($.eventSource = "scheduler.amazonaws.com") && (($.eventName = "DeleteSchedule") || ($.eventName = "UpdateSchedule") || ($.eventName = "CreateSchedule") || ($.eventName = "DeleteScheduleGroup")) }',
            "description": "Scheduler schedules were created, updated, or deleted through the AWS control plane.",
        },
        {
            "resource_name": f"{name}-audit-sqs-dlq-mutations-filter",
            "filter_name": f"{name}-audit-sqs-dlq-mutations",
            "metric_name": "AwsControlPlaneSqsDlqMutations",
            "pattern": '{ ($.eventSource = "sqs.amazonaws.com") && (($.eventName = "PurgeQueue") || ($.eventName = "DeleteQueue") || ($.eventName = "SetQueueAttributes")) }',
            "description": "SQS queue or DLQ was purged, deleted, or reconfigured through the AWS control plane.",
        },
        {
            "resource_name": f"{name}-audit-alarm-mutations-filter",
            "filter_name": f"{name}-audit-alarm-mutations",
            "metric_name": "AwsControlPlaneAlarmMutations",
            "pattern": '{ ($.eventSource = "monitoring.amazonaws.com") && (($.eventName = "DeleteAlarms") || ($.eventName = "DisableAlarmActions") || ($.eventName = "PutMetricAlarm")) }',
            "description": "CloudWatch alarms were deleted, disabled, or changed through the AWS control plane.",
        },
        {
            "resource_name": f"{name}-audit-iam-mutations-filter",
            "filter_name": f"{name}-audit-iam-mutations",
            "metric_name": "AwsControlPlaneIamMutations",
            "pattern": '{ ($.eventSource = "iam.amazonaws.com") && (($.eventName = "PutRolePolicy") || ($.eventName = "AttachRolePolicy") || ($.eventName = "UpdateAssumeRolePolicy") || ($.eventName = "DeleteRolePolicy") || ($.eventName = "DetachRolePolicy")) }',
            "description": "IAM role trust or inline/attached policies changed through the AWS control plane.",
        },
    ]


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


def _source_runtime_display_name(source_system: str) -> str:
    if source_system == "evidence_cas":
        return "EvidenceCAS"
    return "".join(part.capitalize() for part in source_system.split("_"))


def _metric_component(value: str) -> str:
    words = [word for word in "".join(ch if ch.isalnum() else " " for ch in value).split() if word]
    return "".join(word[:1].upper() + word[1:] for word in words) or "Unknown"


def _observability_legacy_metric_suffix(entry: dict) -> str:
    prefix = (
        "SourceRuntime"
        f"{_metric_component(str(entry.get('sourceSystem', '')))}"
        f"{_metric_component(str(entry.get('runtimeClass', '')))}"
    )
    return _safe_resource_suffix(prefix)


def _source_runtime_observability_entries(entries: list[dict] | None, dashboard_enabled: bool = False) -> list[dict]:
    valid_entries = []
    for entry in entries or []:
        if not isinstance(entry, dict) or entry.get("enabled") is not True:
            continue
        if dashboard_enabled and entry.get("dashboardEnabled") is not True:
            continue
        source_system = str(entry.get("sourceSystem", "")).strip()
        runtime_id = str(entry.get("sourceRuntimeId", "")).strip()
        runtime_class = str(entry.get("runtimeClass", "")).strip()
        if not (source_system and runtime_id and runtime_class):
            continue
        valid_entries.append(entry)
    return valid_entries


def _source_runtime_observability_metric_specs(entries: list[dict] | None) -> list[dict]:
    valid_entries = _source_runtime_observability_entries(entries)
    if not valid_entries:
        return []
    legacy_suffix = _observability_legacy_metric_suffix(valid_entries[0])
    runtime_dimension = {"RuntimeId": "$.runtime_id"}
    return [
        {
            "key": "source_runtime_ingest_success",
            "suffix": f"{legacy_suffix}-ingest-success",
            "metric_name": "SourceRuntimeIngestSuccess",
            "pattern": '{ $.kind = "span_end" && $.name = "source_runtime.sync" && $.status = "completed" && $.runtime_id = * }',
            "value": "1",
            "dimensions": runtime_dimension,
        },
        {
            "key": "source_runtime_ingest_failure",
            "suffix": f"{legacy_suffix}-ingest-failure",
            "metric_name": "SourceRuntimeIngestFailure",
            "pattern": '{ $.kind = "span_end" && $.name = "source_runtime.sync" && $.status = "failed" && $.runtime_id = * }',
            "value": "1",
            "dimensions": runtime_dimension,
        },
        {
            "key": "source_runtime_records_accepted",
            "suffix": f"{legacy_suffix}-records-accepted",
            "metric_name": "SourceRuntimeRecordsAccepted",
            "pattern": '{ $.kind = "span_end" && $.name = "source_runtime.sync" && $.status = "completed" && $.records_accepted = * && $.runtime_id = * }',
            "value": "$.records_accepted",
            "dimensions": runtime_dimension,
        },
        {
            "key": "source_runtime_records_rejected",
            "suffix": f"{legacy_suffix}-records-rejected",
            "metric_name": "SourceRuntimeRecordsRejected",
            "pattern": '{ $.kind = "span_end" && $.name = "source_runtime.sync" && $.records_rejected = * && $.runtime_id = * }',
            "value": "$.records_rejected",
            "dimensions": runtime_dimension,
        },
        {
            "key": "source_runtime_projection_success",
            "suffix": f"{legacy_suffix}-projection-success",
            "metric_name": "SourceRuntimeProjectionSuccess",
            "pattern": '{ $.kind = "span_end" && $.name = "orchestrator.runtime" && $.status = "completed" && $.entities_projected = * && $.runtime_id = * }',
            "value": "$.entities_projected",
            "dimensions": runtime_dimension,
        },
        {
            "key": "source_runtime_projection_failure",
            "suffix": f"{legacy_suffix}-projection-failure",
            "metric_name": "SourceRuntimeProjectionFailure",
            "pattern": '{ $.kind = "span_end" && $.status = "failed" && ($.name = "graph.ingest_runtime" || $.name = "orchestrator.graph_ingest" || $.name = "orchestrator.runtime") && $.runtime_id = * }',
            "value": "1",
            "dimensions": runtime_dimension,
        },
        {
            "key": "source_runtime_contract_probe_success",
            "suffix": f"{legacy_suffix}-contract-probe-success",
            "metric_name": "SourceRuntimeContractProbeSuccess",
            "pattern": '{ $.kind = "event" && $.name = "source_runtime.contract_probe" && $.contract_probe_status = "success" && $.runtime_id = * }',
            "value": "1",
            "dimensions": runtime_dimension,
        },
        {
            "key": "source_runtime_contract_probe_failure",
            "suffix": f"{legacy_suffix}-contract-probe-failure",
            "metric_name": "SourceRuntimeContractProbeFailure",
            "pattern": '{ $.kind = "event" && $.name = "source_runtime.contract_probe" && ($.contract_probe_status = "failure" || $.contract_probe_status = "stale" || $.contract_probe_status = "unknown") && $.runtime_id = * }',
            "value": "1",
            "dimensions": runtime_dimension,
        },
        {
            "key": "source_runtime_missing_canonical_fields",
            "suffix": f"{legacy_suffix}-missing-canonical-fields",
            "metric_name": "SourceRuntimeMissingCanonicalFields",
            "pattern": '{ $.kind = "event" && $.name = "source_runtime.validation" && $.missing_canonical_field_class = * && $.runtime_id = * }',
            "value": "1",
            "dimensions": runtime_dimension,
        },
        {
            "key": "source_runtime_orphan_missing_link",
            "suffix": f"{legacy_suffix}-orphan-missing-link",
            "metric_name": "SourceRuntimeOrphanMissingLink",
            "pattern": '{ $.kind = "event" && ($.name = "runtime.evidence.link_status" || $.name = "source_runtime.link_status") && ($.link_status = "orphan" || $.link_status = "missing_resource" || $.link_status = "missing_case") && $.runtime_id = * }',
            "value": "1",
            "dimensions": runtime_dimension,
        },
    ]


def _source_runtime_observability_alarm_specs(name: str, entries: list[dict] | None) -> list[dict]:
    specs = []
    for entry in entries or []:
        if not isinstance(entry, dict) or entry.get("enabled") is not True or entry.get("alarmEnabled") is not True:
            continue
        source_system = str(entry.get("sourceSystem", "")).strip()
        runtime_id = str(entry.get("sourceRuntimeId", "")).strip()
        runtime_class = str(entry.get("runtimeClass", "")).strip()
        if not (source_system and runtime_id and runtime_class):
            continue
        source_label = _source_runtime_display_name(source_system)
        class_label = runtime_class.replace("_", " ")
        alarm_suffix = _safe_resource_suffix(f"{source_system}-{runtime_class}")
        freshness_minutes = int(entry.get("freshnessSlaMinutes") or 60)
        context = f"{source_label} {class_label} source-runtime observability"
        dimensions = {"RuntimeId": runtime_id}
        specs.extend(
            [
                {
                    "resource_name": f"{name}-{alarm_suffix}-ingest-failure-alarm",
                    "alarm_name": f"{name}-{alarm_suffix}-ingest-failure",
                    "metric_name": "SourceRuntimeIngestFailure",
                    "dimensions": dimensions,
                    "comparison_operator": "GreaterThanThreshold",
                    "threshold": 0,
                    "statistic": "Sum",
                    "period": 300,
                    "treat_missing_data": "notBreaching",
                    "description": f"{context}: sustained ingest failures; inspect structured runtime logs and stack config for the configured runtime.",
                },
                {
                    "resource_name": f"{name}-{alarm_suffix}-projection-failure-alarm",
                    "alarm_name": f"{name}-{alarm_suffix}-projection-failure",
                    "metric_name": "SourceRuntimeProjectionFailure",
                    "dimensions": dimensions,
                    "comparison_operator": "GreaterThanThreshold",
                    "threshold": 0,
                    "statistic": "Sum",
                    "period": 300,
                    "treat_missing_data": "notBreaching",
                    "description": f"{context}: graph projection failures detected; inspect structured runtime logs for bounded failure categories.",
                },
                {
                    "resource_name": f"{name}-{alarm_suffix}-contract-probe-failure-alarm",
                    "alarm_name": f"{name}-{alarm_suffix}-contract-probe-failure",
                    "metric_name": "SourceRuntimeContractProbeFailure",
                    "dimensions": dimensions,
                    "comparison_operator": "GreaterThanThreshold",
                    "threshold": 0,
                    "statistic": "Sum",
                    "period": 300,
                    "treat_missing_data": "notBreaching",
                    "description": f"{context}: contract probe is failing, stale, or unknown; check source-runtime verification before treating lifecycle joins as healthy.",
                },
                {
                    "resource_name": f"{name}-{alarm_suffix}-missing-fields-alarm",
                    "alarm_name": f"{name}-{alarm_suffix}-missing-canonical-fields",
                    "metric_name": "SourceRuntimeMissingCanonicalFields",
                    "dimensions": dimensions,
                    "comparison_operator": "GreaterThanThreshold",
                    "threshold": 0,
                    "statistic": "Sum",
                    "period": 300,
                    "treat_missing_data": "notBreaching",
                    "description": f"{context}: required canonical field classes are missing; inspect redacted validation logs, dashboards and notifications intentionally omit raw field values.",
                },
                {
                    "resource_name": f"{name}-{alarm_suffix}-orphan-missing-link-alarm",
                    "alarm_name": f"{name}-{alarm_suffix}-orphan-missing-link",
                    "metric_name": "SourceRuntimeOrphanMissingLink",
                    "dimensions": dimensions,
                    "comparison_operator": "GreaterThanThreshold",
                    "threshold": 0,
                    "statistic": "Sum",
                    "period": 300,
                    "treat_missing_data": "notBreaching",
                    "description": f"{context}: orphan or missing-link evidence symptoms detected; inspect redacted structured diagnostics for safe correlation keys.",
                },
                {
                    "resource_name": f"{name}-{alarm_suffix}-staleness-alarm",
                    "alarm_name": f"{name}-{alarm_suffix}-stale",
                    "metric_name": "SourceRuntimeIngestSuccess",
                    "dimensions": dimensions,
                    "comparison_operator": "LessThanThreshold",
                    "threshold": 1,
                    "statistic": "Sum",
                    "period": max(900, freshness_minutes * 60),
                    "treat_missing_data": "breaching",
                    "description": f"{context}: no successful sync observed within the configured freshness SLA; check source-runtime verification.",
                },
            ]
        )
    return specs


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
    postgres_identifier: pulumi.Input[str] = None,
    web_alb_arn_suffix: pulumi.Output[str] = None,
    web_target_group_arn_suffix: pulumi.Output[str] = None,
    web_ecs_service_name: pulumi.Output[str] = None,
    log_group_name: pulumi.Output[str] = None,
    otel_collector_enabled: bool = False,
    otel_collector_log_group_name: pulumi.Input[str] = None,
    log_retention_days: int = 30,
    jetstream_stream_name: str = "CEREBRO_EVENTS",
    jetstream_lag_alarm_threshold: int = 10000,
    api_request_count_per_target_alarm_threshold: int = 0,
    api_latency_p95_alarm_threshold_seconds: int = 3,
    web_latency_p95_alarm_threshold_seconds: int = 3,
    dashboard_latency_p95_alarm_threshold_ms: int = 3000,
    access_audit_denied_alarm_threshold: int = 0,
    access_audit_auth_failure_alarm_threshold: int = 0,
    access_audit_tenant_mismatch_alarm_threshold: int = -1,
    access_audit_sensitive_denied_alarm_threshold: int = -1,
    aws_service_quota_alarm_threshold_percent: int = 80,
    alarm_action_arns: list[str] = None,
    alarm_email_subscriptions: list[str] = None,
    orchestrator_schedules: list[dict] = None,
    orchestrator_rule_names: list[pulumi.Input[str]] = None,
    orchestrator_scheduler_group_name: pulumi.Input[str] = None,
    orchestrator_scheduler_dlq_queue_name: pulumi.Input[str] = None,
    cloudtrail_audit_log_group_name: pulumi.Input[str] = None,
    source_runtimes: list[dict] = None,
    source_runtime_heartbeat_period_seconds: int = 28800,
    source_runtime_observability: list[dict] = None,
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
    if api_latency_p95_alarm_threshold_seconds > 0:
        aws.cloudwatch.MetricAlarm(
            f"{name}-latency-p95-alarm",
            name=f"{name}-high-latency-p95",
            comparison_operator="GreaterThanThreshold",
            evaluation_periods=3,
            metric_name="TargetResponseTime",
            namespace="AWS/ApplicationELB",
            period=300,
            extended_statistic="p95",
            threshold=api_latency_p95_alarm_threshold_seconds,
            alarm_description=f"High API p95 latency (>{api_latency_p95_alarm_threshold_seconds}s)",
            alarm_actions=alarm_actions,
            treat_missing_data="notBreaching",
            dimensions={
                "LoadBalancer": alb_arn_suffix,
                "TargetGroup": target_group_arn_suffix,
            },
            tags={"Name": f"{name}-latency-p95-alarm"},
        )

    if api_request_count_per_target_alarm_threshold > 0:
        aws.cloudwatch.MetricAlarm(
            f"{name}-request-count-per-target-alarm",
            name=f"{name}-request-count-per-target",
            comparison_operator="GreaterThanThreshold",
            evaluation_periods=3,
            metric_name="RequestCountPerTarget",
            namespace="AWS/ApplicationELB",
            period=300,
            statistic="Sum",
            threshold=api_request_count_per_target_alarm_threshold,
            alarm_description="API requests per target exceeded autoscaling saturation threshold",
            alarm_actions=alarm_actions,
            treat_missing_data="notBreaching",
            dimensions={
                "LoadBalancer": alb_arn_suffix,
                "TargetGroup": target_group_arn_suffix,
            },
            tags={"Name": f"{name}-request-count-per-target-alarm"},
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

    if postgres_identifier:
        _rds_metric_alarm(
            resource_name=f"{name}-postgres-queue-depth-alarm",
            alarm_name=f"{name}-postgres-disk-queue-depth",
            db_identifier=postgres_identifier,
            metric_name="DiskQueueDepth",
            threshold=5,
            description="Postgres disk queue depth is high enough to affect API latency",
            alarm_actions=alarm_actions,
            statistic="Average",
        )
        _rds_metric_alarm(
            resource_name=f"{name}-postgres-read-latency-alarm",
            alarm_name=f"{name}-postgres-read-latency",
            db_identifier=postgres_identifier,
            metric_name="ReadLatency",
            threshold=0.05,
            description="Postgres read latency is elevated",
            alarm_actions=alarm_actions,
            statistic="Average",
        )
        _rds_metric_alarm(
            resource_name=f"{name}-postgres-write-latency-alarm",
            alarm_name=f"{name}-postgres-write-latency",
            db_identifier=postgres_identifier,
            metric_name="WriteLatency",
            threshold=0.1,
            description="Postgres write latency is elevated",
            alarm_actions=alarm_actions,
            statistic="Average",
        )
        _rds_metric_alarm(
            resource_name=f"{name}-postgres-cpu-alarm",
            alarm_name=f"{name}-postgres-high-cpu",
            db_identifier=postgres_identifier,
            metric_name="CPUUtilization",
            threshold=80,
            description="Postgres CPU utilization is high",
            alarm_actions=alarm_actions,
            statistic="Average",
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
        if web_latency_p95_alarm_threshold_seconds > 0:
            aws.cloudwatch.MetricAlarm(
                f"{name}-web-latency-p95-alarm",
                name=f"{name}-web-high-latency-p95",
                comparison_operator="GreaterThanThreshold",
                evaluation_periods=3,
                metric_name="TargetResponseTime",
                namespace="AWS/ApplicationELB",
                period=300,
                extended_statistic="p95",
                threshold=web_latency_p95_alarm_threshold_seconds,
                alarm_description=f"High web console p95 latency (>{web_latency_p95_alarm_threshold_seconds}s)",
                alarm_actions=alarm_actions,
                treat_missing_data="notBreaching",
                dimensions={
                    "LoadBalancer": web_alb_arn_suffix,
                    "TargetGroup": web_target_group_arn_suffix,
                },
                tags={"Name": f"{name}-web-latency-p95-alarm"},
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
        telemetry_filters = _create_telemetry_metric_filters(name, log_group_name, source_runtime_observability)
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
        if access_audit_tenant_mismatch_alarm_threshold >= 0:
            _custom_metric_alarm(
                resource_name=f"{name}-access-audit-tenant-mismatch-alarm",
                alarm_name=f"{name}-access-audit-tenant-mismatch",
                namespace=telemetry_namespace,
                metric_name="AccessAuditTenantMismatch",
                threshold=access_audit_tenant_mismatch_alarm_threshold,
                description="Cerebro API requests included a tenant that differed from the authenticated principal",
                alarm_actions=alarm_actions,
            )
        if access_audit_sensitive_denied_alarm_threshold >= 0:
            _custom_metric_alarm(
                resource_name=f"{name}-access-audit-sensitive-denied-alarm",
                alarm_name=f"{name}-access-audit-sensitive-denied",
                namespace=telemetry_namespace,
                metric_name="AccessAuditSensitiveDenied",
                threshold=access_audit_sensitive_denied_alarm_threshold,
                description="Cerebro API denied sensitive actions exceeded the configured threshold",
                alarm_actions=alarm_actions,
            )
        if dashboard_latency_p95_alarm_threshold_ms > 0:
            aws.cloudwatch.MetricAlarm(
                f"{name}-grc-dashboard-latency-p95-alarm",
                name=f"{name}-grc-dashboard-latency-p95",
                comparison_operator="GreaterThanThreshold",
                evaluation_periods=3,
                metric_name="GRCDashboardLatencyMs",
                namespace=telemetry_namespace,
                period=300,
                extended_statistic="p95",
                threshold=dashboard_latency_p95_alarm_threshold_ms,
                treat_missing_data="notBreaching",
                alarm_description="GRC dashboard p95 application latency exceeded threshold",
                alarm_actions=alarm_actions,
                dimensions={"Dashboard": "grc"},
                tags={"Name": f"{name}-grc-dashboard-latency-p95-alarm"},
            )
    otel_collector_filters = {}
    if otel_collector_enabled and otel_collector_log_group_name:
        otel_collector_filters = _create_otel_collector_metric_filters(name, otel_collector_log_group_name, telemetry_namespace)
        _custom_metric_alarm(
            resource_name=f"{name}-otel-collector-errors-alarm",
            alarm_name=f"{name}-otel-collector-errors",
            namespace=telemetry_namespace,
            metric_name="OtelCollectorErrors",
            threshold=0,
            description="OpenTelemetry collector errors or exporter failures detected",
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

    for spec in _source_runtime_observability_alarm_specs(name, source_runtime_observability):
        aws.cloudwatch.MetricAlarm(
            spec["resource_name"],
            name=spec["alarm_name"],
            comparison_operator=spec["comparison_operator"],
            evaluation_periods=1,
            metric_name=spec["metric_name"],
            namespace=telemetry_namespace,
            period=spec["period"],
            statistic=spec["statistic"],
            threshold=spec["threshold"],
            treat_missing_data=spec["treat_missing_data"],
            alarm_description=spec["description"],
            alarm_actions=alarm_actions,
            dimensions=spec["dimensions"],
            tags={"Name": spec["alarm_name"]},
        )

    rule_schedules = _orchestrator_rule_alarm_schedules(orchestrator_schedules, len(orchestrator_rule_names or []))
    for index, rule_name in enumerate(orchestrator_rule_names or []):
        schedule = rule_schedules[index]
        aws.cloudwatch.MetricAlarm(
            _orchestrator_rule_alarm_resource_name(name, index, schedule),
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

    for spec in _scheduler_alarm_specs(name, orchestrator_scheduler_group_name, orchestrator_scheduler_dlq_queue_name):
        _custom_metric_alarm(
            resource_name=spec["resource_name"],
            alarm_name=spec["alarm_name"],
            namespace=spec["namespace"],
            metric_name=spec["metric_name"],
            threshold=spec.get("threshold", 0),
            description=spec["description"],
            alarm_actions=alarm_actions,
            statistic=spec.get("statistic", "Sum"),
            dimensions=spec["dimensions"],
        )

    for spec in _service_quota_alarm_specs(name, aws_service_quota_alarm_threshold_percent):
        _aws_usage_quota_alarm(
            resource_name=spec["resource_name"],
            alarm_name=spec["alarm_name"],
            dimensions=spec["dimensions"],
            threshold_percent=spec["threshold"],
            description=spec["description"],
            alarm_actions=alarm_actions,
        )

    if cloudtrail_audit_log_group_name:
        for spec in _cloudtrail_audit_metric_filter_specs(name):
            aws.cloudwatch.LogMetricFilter(
                spec["resource_name"],
                name=spec["filter_name"],
                log_group_name=cloudtrail_audit_log_group_name,
                pattern=spec["pattern"],
                metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                    name=spec["metric_name"],
                    namespace=telemetry_namespace,
                    value="1",
                ),
            )
            _custom_metric_alarm(
                resource_name=f"{spec['resource_name']}-alarm",
                alarm_name=f"{spec['filter_name']}-alarm",
                namespace=telemetry_namespace,
                metric_name=spec["metric_name"],
                threshold=0,
                description=spec["description"],
                alarm_actions=alarm_actions,
            )

    dashboard = aws.cloudwatch.Dashboard(
        f"{name}-dashboard",
        dashboard_name=f"{name}-dashboard",
        dashboard_body=pulumi.Output.all(
            alb_arn_suffix,
            target_group_arn_suffix,
            ecs_cluster_name,
            ecs_service_name,
            postgres_identifier,
            otel_collector_log_group_name or "",
        ).apply(
            lambda args: _dashboard_body(
                name,
                *args[:5],
                jetstream_stream_name,
                source_runtime_observability,
                otel_collector_enabled=otel_collector_enabled,
                otel_collector_log_group_name=args[5],
            )
        ),
    )

    return {
        "alarm_topic": alarm_topic,
        "dashboard": dashboard,
        "telemetry_filters": telemetry_filters,
        "otel_collector_filters": otel_collector_filters,
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


def _aws_usage_quota_alarm(
    resource_name: str,
    alarm_name: str,
    dimensions: dict[str, str],
    threshold_percent: int,
    description: str,
    alarm_actions: list[pulumi.Input[str]],
) -> aws.cloudwatch.MetricAlarm:
    return aws.cloudwatch.MetricAlarm(
        resource_name,
        name=alarm_name,
        comparison_operator="GreaterThanThreshold",
        evaluation_periods=1,
        threshold=threshold_percent,
        treat_missing_data="notBreaching",
        alarm_description=description,
        alarm_actions=alarm_actions,
        metric_queries=[
            aws.cloudwatch.MetricAlarmMetricQueryArgs(
                id="usage",
                metric=aws.cloudwatch.MetricAlarmMetricQueryMetricArgs(
                    namespace="AWS/Usage",
                    metric_name="ResourceCount" if dimensions.get("Type") == "Resource" else "CallCount",
                    dimensions=dimensions,
                    period=300,
                    stat="Maximum",
                ),
                return_data=False,
            ),
            aws.cloudwatch.MetricAlarmMetricQueryArgs(
                id="pct",
                expression="usage / SERVICE_QUOTA(usage) * 100",
                label=f"{alarm_name} quota usage percent",
                return_data=True,
            ),
        ],
        tags={"Name": alarm_name},
    )


def _rds_metric_alarm(
    resource_name: str,
    alarm_name: str,
    db_identifier: pulumi.Input[str],
    metric_name: str,
    threshold: float,
    description: str,
    alarm_actions: list[pulumi.Input[str]],
    statistic: str = "Average",
) -> aws.cloudwatch.MetricAlarm:
    return aws.cloudwatch.MetricAlarm(
        resource_name,
        name=alarm_name,
        comparison_operator="GreaterThanThreshold",
        evaluation_periods=3,
        metric_name=metric_name,
        namespace="AWS/RDS",
        period=300,
        statistic=statistic,
        threshold=threshold,
        treat_missing_data="notBreaching",
        alarm_description=description,
        alarm_actions=alarm_actions,
        dimensions={"DBInstanceIdentifier": db_identifier},
        tags={"Name": resource_name},
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
        "access_audit_unauthorized": {
            "suffix": "access-audit-unauthorized",
            "metric_name": "AccessAuditUnauthorized",
            "pattern": '{ $.kind = "event" && $.name = "cerebro.api.access" && $.status = 401 }',
        },
        "access_audit_forbidden": {
            "suffix": "access-audit-forbidden",
            "metric_name": "AccessAuditForbidden",
            "pattern": '{ $.kind = "event" && $.name = "cerebro.api.access" && $.status = 403 }',
        },
        "access_audit_rate_limited": {
            "suffix": "access-audit-rate-limited",
            "metric_name": "AccessAuditRateLimited",
            "pattern": '{ $.kind = "event" && $.name = "cerebro.api.access" && $.status = 429 }',
        },
        "access_audit_client_errors": {
            "suffix": "access-audit-client-errors",
            "metric_name": "AccessAuditClientErrors",
            "pattern": '{ $.kind = "event" && $.name = "cerebro.api.access" && $.status >= 400 && $.status < 500 }',
        },
        "access_audit_server_errors": {
            "suffix": "access-audit-server-errors",
            "metric_name": "AccessAuditServerErrors",
            "pattern": '{ $.kind = "event" && $.name = "cerebro.api.access" && $.status >= 500 }',
        },
        "access_audit_tenant_mismatch": {
            "suffix": "access-audit-tenant-mismatch",
            "metric_name": "AccessAuditTenantMismatch",
            "pattern": '{ $.kind = "event" && $.name = "cerebro.api.access" && $.tenant_mismatch IS TRUE }',
        },
        "access_audit_sensitive_actions": {
            "suffix": "access-audit-sensitive-actions",
            "metric_name": "AccessAuditSensitiveActions",
            "pattern": '{ $.kind = "event" && $.name = "cerebro.api.access" && $.sensitive_action IS TRUE }',
        },
        "access_audit_sensitive_denied": {
            "suffix": "access-audit-sensitive-denied",
            "metric_name": "AccessAuditSensitiveDenied",
            "pattern": '{ $.kind = "event" && $.name = "cerebro.api.access" && $.sensitive_action IS TRUE && $.outcome = "denied" }',
        },
        "access_audit_write_actions": {
            "suffix": "access-audit-write-actions",
            "metric_name": "AccessAuditWriteActions",
            "pattern": '{ $.kind = "event" && $.name = "cerebro.api.access" && $.operation_type = "write" }',
        },
        "access_audit_write_denied": {
            "suffix": "access-audit-write-denied",
            "metric_name": "AccessAuditWriteDenied",
            "pattern": '{ $.kind = "event" && $.name = "cerebro.api.access" && $.operation_type = "write" && $.outcome = "denied" }',
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


def _create_telemetry_metric_filters(name: str, log_group_name: pulumi.Output[str], source_runtime_observability: list[dict] = None) -> dict:
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
        "source_runtime_watermark_lag": aws.cloudwatch.LogMetricFilter(
            f"{name}-source-runtime-watermark-lag-filter",
            name=f"{name}-source-runtime-watermark-lag",
            log_group_name=log_group_name,
            pattern='{ $.kind = "span_end" && $.name = "source_runtime.sync" && $.source_runtime_watermark_lag_seconds = * }',
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="SourceRuntimeWatermarkLagSeconds",
                namespace=namespace,
                value="$.source_runtime_watermark_lag_seconds",
                dimensions={"RuntimeId": "$.runtime_id"},
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
        "grc_dashboard_latency": aws.cloudwatch.LogMetricFilter(
            f"{name}-grc-dashboard-latency-filter",
            name=f"{name}-grc-dashboard-latency",
            log_group_name=log_group_name,
            pattern='{ $.kind = "span_end" && $.name = "grc.dashboard" && $.dashboard = "grc" && $.duration_ms = * }',
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="GRCDashboardLatencyMs",
                namespace=namespace,
                value="$.duration_ms",
                dimensions={"Dashboard": "$.dashboard"},
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
            pattern=_graph_ingest_failure_pattern(),
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
    for spec in _source_runtime_observability_metric_specs(source_runtime_observability):
        metric_args = {
            "name": spec["metric_name"],
            "namespace": namespace,
            "value": spec["value"],
        }
        dimensions = spec.get("dimensions")
        if dimensions:
            metric_args["dimensions"] = dimensions
        else:
            metric_args["default_value"] = 0
        filters[spec["key"]] = aws.cloudwatch.LogMetricFilter(
            f"{name}-{spec['suffix']}-filter",
            name=f"{name}-{spec['suffix']}",
            log_group_name=log_group_name,
            pattern=spec["pattern"],
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(**metric_args),
        )
    return filters


def _create_otel_collector_metric_filters(name: str, log_group_name: pulumi.Input[str], namespace: str | None = None) -> dict:
    namespace = namespace or f"Cerebro/{name}"
    filters = {}
    for suffix, pattern in {
        "error": "error",
        "error-uppercase": "ERROR",
        "failed": "failed",
        "dropped": "dropped",
        "refused": "refused",
    }.items():
        filters[suffix] = aws.cloudwatch.LogMetricFilter(
            f"{name}-otel-collector-{suffix}-filter",
            name=f"{name}-otel-collector-{suffix}",
            log_group_name=log_group_name,
            pattern=pattern,
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="OtelCollectorErrors",
                namespace=namespace,
                value="1",
                default_value=0,
            ),
        )
    return filters


def _graph_ingest_failure_pattern() -> str:
    return '{ $.kind = "span_end" && $.status = "failed" && ($.name = "graph.*" || $.name = "graph.ingest_runtime" || $.name = "orchestrator.graph_ingest") }'


def _dashboard_body(
    name: str,
    alb_arn: str,
    tg_arn: str,
    cluster: str,
    service: str,
    postgres_identifier: str | None,
    jetstream_stream_name: str,
    source_runtime_observability: list[dict] = None,
    otel_collector_enabled: bool = False,
    otel_collector_log_group_name: str | None = None,
) -> str:
    import json
    telemetry_namespace = f"Cerebro/{name}"
    widgets = [
            {
                "type": "metric",
                "x": 0, "y": 0, "width": 12, "height": 6,
                "properties": {
                    "title": "Request Count",
                    "metrics": [
                        ["AWS/ApplicationELB", "RequestCount", "LoadBalancer", alb_arn, {"stat": "Sum"}],
                        [".", "RequestCountPerTarget", ".", ".", "TargetGroup", tg_arn, {"stat": "Sum", "yAxis": "right"}],
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
                        ["AWS/ApplicationELB", "TargetResponseTime", "LoadBalancer", alb_arn, {"stat": "Average"}],
                        [".", ".", ".", ".", {"stat": "p95"}],
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
                        [{"expression": f"SEARCH('{{{telemetry_namespace},RuntimeId}} MetricName=\"SourceRuntimeWatermarkLagSeconds\"', 'Maximum', 300)", "label": "Watermark lag", "id": "e1", "yAxis": "right"}],
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
                        [".", "OtelCollectorErrors", {"stat": "Sum"}],
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
                    "title": "GRC Dashboard Latency",
                    "metrics": [
                        [telemetry_namespace, "GRCDashboardLatencyMs", "Dashboard", "grc", {"stat": "Average"}],
                        [".", ".", ".", ".", {"stat": "p95"}],
                    ],
                    "period": 300,
                    "region": aws.get_region().region,
                },
            },
            {
                "type": "metric",
                "x": 12, "y": 36, "width": 12, "height": 6,
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
                "x": 0, "y": 42, "width": 12, "height": 6,
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
                "x": 12, "y": 42, "width": 12, "height": 6,
                "properties": {
                    "title": "API Access Audit Volume",
                    "metrics": [
                        [telemetry_namespace, "AccessAuditEvents", {"stat": "Sum"}],
                        [".", "AccessAuditAllowed", {"stat": "Sum"}],
                        [".", "AccessAuditSensitiveActions", {"stat": "Sum"}],
                        [".", "AccessAuditWriteActions", {"stat": "Sum"}],
                        [".", "AccessAuditClientErrors", {"stat": "Sum"}],
                        [".", "AccessAuditServerErrors", {"stat": "Sum", "yAxis": "right"}],
                    ],
                    "period": 300,
                    "region": aws.get_region().region,
                },
            },
            {
                "type": "metric",
                "x": 0, "y": 54, "width": 12, "height": 6,
                "properties": {
                    "title": "API Access Denials",
                    "metrics": [
                        [telemetry_namespace, "AccessAuditDenied", {"stat": "Sum"}],
                        [".", "AccessAuditAuthFailures", {"stat": "Sum"}],
                        [".", "AccessAuditUnauthorized", {"stat": "Sum"}],
                        [".", "AccessAuditForbidden", {"stat": "Sum"}],
                        [".", "AccessAuditRateLimited", {"stat": "Sum"}],
                        [".", "AccessAuditTenantMismatch", {"stat": "Sum"}],
                        [".", "AccessAuditSensitiveDenied", {"stat": "Sum"}],
                        [".", "AccessAuditWriteDenied", {"stat": "Sum"}],
                    ],
                    "period": 300,
                    "region": aws.get_region().region,
                },
            },
        ]
    if postgres_identifier:
        widgets.extend([
            {
                "type": "metric",
                "x": 0, "y": 48, "width": 12, "height": 6,
                "properties": {
                    "title": "Postgres Latency / Queue",
                    "metrics": [
                        ["AWS/RDS", "DiskQueueDepth", "DBInstanceIdentifier", postgres_identifier, {"stat": "Average", "yAxis": "right"}],
                        [".", "ReadLatency", ".", ".", {"stat": "Average"}],
                        [".", "WriteLatency", ".", ".", {"stat": "Average"}],
                    ],
                    "period": 300,
                    "region": aws.get_region().region,
                },
            },
            {
                "type": "metric",
                "x": 12, "y": 54, "width": 12, "height": 6,
                "properties": {
                    "title": "Postgres CPU / Connections / Memory",
                    "metrics": [
                        ["AWS/RDS", "CPUUtilization", "DBInstanceIdentifier", postgres_identifier, {"stat": "Average"}],
                        [".", "DatabaseConnections", ".", ".", {"stat": "Average", "yAxis": "right"}],
                        [".", "FreeableMemory", ".", ".", {"stat": "Average", "yAxis": "right"}],
                    ],
                    "period": 300,
                    "region": aws.get_region().region,
                },
            },
        ])
    otel_widgets = (
        _otel_collector_observability_widgets(
            name,
            cluster,
            telemetry_namespace,
            otel_collector_log_group_name,
            60,
        )
        if otel_collector_enabled and otel_collector_log_group_name
        else []
    )
    widgets.extend(otel_widgets)
    widgets.extend(
        _source_runtime_observability_widgets(
            telemetry_namespace,
            source_runtime_observability,
            start_y=72 if otel_widgets else 60,
        )
    )
    return json.dumps({"widgets": widgets})


def _otel_collector_observability_widgets(
    name: str,
    cluster: str,
    telemetry_namespace: str,
    log_group_name: str,
    y: int,
) -> list[dict]:
    region = aws.get_region().region
    return [
        {
            "type": "metric",
            "x": 0,
            "y": y,
            "width": 12,
            "height": 6,
            "properties": {
                "title": "OTEL Collector Container",
                "metrics": [
                    [
                        "ECS/ContainerInsights",
                        "CpuUtilized",
                        "ClusterName",
                        cluster,
                        "TaskDefinitionFamily",
                        name,
                        "ContainerName",
                        "otel-collector",
                        {"stat": "Average", "label": "CPU utilized"},
                    ],
                    [
                        ".",
                        "MemoryUtilized",
                        ".",
                        ".",
                        ".",
                        ".",
                        ".",
                        ".",
                        {"stat": "Average", "label": "Memory utilized", "yAxis": "right"},
                    ],
                    [telemetry_namespace, "OtelCollectorErrors", {"stat": "Sum", "label": "Collector errors"}],
                ],
                "period": 60,
                "region": region,
            },
        },
        {
            "type": "log",
            "x": 12,
            "y": y,
            "width": 12,
            "height": 6,
            "properties": {
                "title": "OTEL Collector Errors",
                "query": (
                    f"SOURCE '{log_group_name}' | fields @timestamp, @message "
                    "| filter @message like /(?i)(error|failed|refused|dropped|retry|exporter)/ "
                    "| sort @timestamp desc | limit 20"
                ),
                "region": region,
                "view": "table",
            },
        },
        {
            "type": "log",
            "x": 0,
            "y": y + 6,
            "width": 24,
            "height": 6,
            "properties": {
                "title": "OTEL Collector Recent Logs",
                "query": f"SOURCE '{log_group_name}' | fields @timestamp, @message | sort @timestamp desc | limit 40",
                "region": region,
                "view": "table",
            },
        },
    ]


def _source_runtime_observability_widgets(
    telemetry_namespace: str,
    entries: list[dict] | None,
    start_y: int = 60,
) -> list[dict]:
    enabled_entries = _source_runtime_observability_entries(entries, dashboard_enabled=True)
    if not enabled_entries:
        return []

    widgets = []
    y = start_y
    source_system_priority = {"evidence_cas": 0, "panopticon": 1}
    source_systems = {
        str(entry.get("sourceSystem", "")).strip()
        for entry in enabled_entries
        if str(entry.get("sourceSystem", "")).strip()
    }
    for source_system in sorted(source_systems, key=lambda value: (source_system_priority.get(value, 10), value)):
        source_entries = [entry for entry in enabled_entries if str(entry.get("sourceSystem", "")).strip() == source_system]
        if not source_entries:
            continue
        source_label = _source_runtime_display_name(source_system)
        throughput_metrics = []
        probe_metrics = []
        projection_metrics = []
        link_metrics = []
        for entry in source_entries:
            runtime_id = str(entry.get("sourceRuntimeId", "")).strip()
            runtime_label = str(entry.get("runtimeClass", "")).replace("_", " ").title()
            throughput_metrics.extend(
                [
                    [telemetry_namespace, "SourceRuntimeIngestSuccess", "RuntimeId", runtime_id, {"stat": "Sum", "label": f"{runtime_label} sync successes"}],
                    [".", "SourceRuntimeIngestFailure", ".", ".", {"stat": "Sum", "label": f"{runtime_label} sync failures"}],
                    [".", "SourceRuntimeRecordsAccepted", ".", ".", {"stat": "Sum", "label": f"{runtime_label} records accepted"}],
                    [".", "SourceRuntimeRecordsRejected", ".", ".", {"stat": "Sum", "label": f"{runtime_label} records rejected"}],
                ]
            )
            probe_metrics.extend(
                [
                    [telemetry_namespace, "SourceRuntimeContractProbeSuccess", "RuntimeId", runtime_id, {"stat": "Sum", "label": f"{runtime_label} probe success"}],
                    [".", "SourceRuntimeContractProbeFailure", ".", ".", {"stat": "Sum", "label": f"{runtime_label} probe failure/stale/unknown"}],
                ]
            )
            projection_metrics.extend(
                [
                    [telemetry_namespace, "SourceRuntimeProjectionSuccess", "RuntimeId", runtime_id, {"stat": "Sum", "label": f"{runtime_label} entities projected"}],
                    [".", "SourceRuntimeProjectionFailure", ".", ".", {"stat": "Sum", "label": f"{runtime_label} projection failures"}],
                ]
            )
            link_metrics.extend(
                [
                    [telemetry_namespace, "SourceRuntimeOrphanMissingLink", "RuntimeId", runtime_id, {"stat": "Sum", "label": f"{runtime_label} orphan/missing-link"}],
                    [".", "SourceRuntimeMissingCanonicalFields", ".", ".", {"stat": "Sum", "label": f"{runtime_label} missing canonical fields"}],
                ]
            )
        widgets.extend(
            [
                {
                    "type": "metric",
                    "x": 0,
                    "y": y,
                    "width": 12,
                    "height": 6,
                    "properties": {
                        "title": f"{source_label} Source Runtime Health",
                        "metrics": throughput_metrics,
                        "period": 300,
                        "region": aws.get_region().region,
                    },
                },
                {
                    "type": "metric",
                    "x": 12,
                    "y": y,
                    "width": 12,
                    "height": 6,
                    "properties": {
                        "title": f"{source_label} Contract Probe Status",
                        "metrics": probe_metrics,
                        "period": 300,
                        "region": aws.get_region().region,
                    },
                },
                {
                    "type": "metric",
                    "x": 0,
                    "y": y + 6,
                    "width": 12,
                    "height": 6,
                    "properties": {
                        "title": f"{source_label} Projection Counts",
                        "metrics": projection_metrics,
                        "period": 300,
                        "region": aws.get_region().region,
                    },
                },
                {
                    "type": "metric",
                    "x": 12,
                    "y": y + 6,
                    "width": 12,
                    "height": 6,
                    "properties": {
                        "title": f"{source_label} Orphan / Missing Link Indicators",
                        "metrics": link_metrics,
                        "period": 300,
                        "region": aws.get_region().region,
                    },
                },
            ]
        )
        y += 12
    return widgets
