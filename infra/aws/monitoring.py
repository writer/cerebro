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


def _nats_log_metric_filter_specs() -> dict[str, dict[str, str]]:
    return {
        "nats_healthcheck_failures": {
            "suffix": "nats-healthcheck-failures",
            "metric_name": "NatsHealthcheckFailures",
            "pattern": '"Healthcheck failed"',
        },
        "nats_bootstrap_errors": {
            "suffix": "nats-bootstrap-errors",
            "metric_name": "NatsBootstrapErrors",
            "pattern": '"nats: error"',
        },
        "nats_corrupt_state_recoveries": {
            "suffix": "nats-corrupt-state-recoveries",
            "metric_name": "NatsCorruptStateRecoveries",
            "pattern": '"corrupt state file"',
        },
        "nats_restore_completions": {
            "suffix": "nats-restore-completions",
            "metric_name": "NatsRestoreCompletions",
            "pattern": '"Restored" "messages for stream"',
        },
    }


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


def _runtime_ids_from_command(command) -> list[str]:
    runtime_ids: list[str] = []
    if not isinstance(command, list):
        return runtime_ids
    for arg in command:
        text = str(arg).strip()
        if text.startswith("runtime_id="):
            _append_unique_runtime_id(runtime_ids, text.split("=", 1)[1].strip())
        elif text.startswith("runtime_ids="):
            for runtime_id in text.split("=", 1)[1].split(","):
                _append_unique_runtime_id(runtime_ids, runtime_id.strip())
    return runtime_ids


def _runtime_id_from_command(command) -> str:
    runtime_ids = _runtime_ids_from_command(command)
    return runtime_ids[0] if runtime_ids else ""


def _append_unique_runtime_id(out: list[str], value: str) -> None:
    if value and value not in out:
        out.append(value)


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
    source_dimension = {"SourceId": "$.source_id"}
    return [
        {
            "key": "source_runtime_ingest_success",
            "suffix": "source-runtime-observability-ingest-success",
            "metric_name": "SourceRuntimeIngestSuccess",
            "pattern": '{ $.kind = "span_end" && $.name = "source_runtime.sync" && $.status = "completed" && $.source_id = * }',
            "value": "1",
            "dimensions": source_dimension,
        },
        {
            "key": "source_runtime_ingest_failure",
            "suffix": "source-runtime-observability-ingest-failure",
            "metric_name": "SourceRuntimeIngestFailure",
            "pattern": '{ $.kind = "span_end" && $.name = "source_runtime.sync" && $.status = "failed" && $.source_id = * }',
            "value": "1",
            "dimensions": source_dimension,
        },
        {
            "key": "source_runtime_records_accepted",
            "suffix": "source-runtime-observability-records-accepted",
            "metric_name": "SourceRuntimeRecordsAccepted",
            "pattern": '{ $.kind = "span_end" && $.name = "source_runtime.sync" && $.status = "completed" && $.records_accepted = * && $.source_id = * }',
            "value": "$.records_accepted",
            "dimensions": source_dimension,
        },
        {
            "key": "source_runtime_records_rejected",
            "suffix": "source-runtime-observability-records-rejected",
            "metric_name": "SourceRuntimeRecordsRejected",
            "pattern": '{ $.kind = "span_end" && $.name = "source_runtime.sync" && $.records_rejected = * && $.source_id = * }',
            "value": "$.records_rejected",
            "dimensions": source_dimension,
        },
        {
            "key": "source_runtime_projection_success",
            "suffix": "source-runtime-observability-projection-success",
            "metric_name": "SourceRuntimeProjectionSuccess",
            "pattern": '{ $.kind = "span_end" && $.name = "orchestrator.runtime" && $.status = "completed" && $.entities_projected = * && $.source_id = * }',
            "value": "$.entities_projected",
            "dimensions": source_dimension,
        },
        {
            "key": "source_runtime_projection_failure",
            "suffix": "source-runtime-observability-projection-failure",
            "metric_name": "SourceRuntimeProjectionFailure",
            "pattern": '{ $.kind = "span_end" && $.status = "failed" && ($.name = "graph.ingest_runtime" || $.name = "orchestrator.graph_ingest" || $.name = "orchestrator.runtime") && $.source_id = * }',
            "value": "1",
            "dimensions": source_dimension,
        },
        {
            "key": "source_runtime_contract_probe_success",
            "suffix": "source-runtime-observability-contract-probe-success",
            "metric_name": "SourceRuntimeContractProbeSuccess",
            "pattern": '{ $.kind = "event" && $.name = "source_runtime.contract_probe" && $.contract_probe_status = "success" && $.source_id = * }',
            "value": "1",
            "dimensions": source_dimension,
        },
        {
            "key": "source_runtime_contract_probe_failure",
            "suffix": "source-runtime-observability-contract-probe-failure",
            "metric_name": "SourceRuntimeContractProbeFailure",
            "pattern": '{ $.kind = "event" && $.name = "source_runtime.contract_probe" && ($.contract_probe_status = "failure" || $.contract_probe_status = "stale" || $.contract_probe_status = "unknown") && $.source_id = * }',
            "value": "1",
            "dimensions": source_dimension,
        },
        {
            "key": "source_runtime_missing_canonical_fields",
            "suffix": "source-runtime-observability-missing-canonical-fields",
            "metric_name": "SourceRuntimeMissingCanonicalFields",
            "pattern": '{ $.kind = "event" && $.name = "source_runtime.validation" && $.missing_canonical_field_class = * && $.source_id = * }',
            "value": "1",
            "dimensions": source_dimension,
        },
        {
            "key": "source_runtime_orphan_missing_link",
            "suffix": "source-runtime-observability-orphan-missing-link",
            "metric_name": "SourceRuntimeOrphanMissingLink",
            "pattern": '{ $.kind = "event" && ($.name = "runtime.evidence.link_status" || $.name = "source_runtime.link_status") && ($.link_status = "orphan" || $.link_status = "missing_resource" || $.link_status = "missing_case") && $.source_id = * }',
            "value": "1",
            "dimensions": source_dimension,
        },
    ]


def _source_runtime_observability_alarm_specs(name: str, entries: list[dict] | None) -> list[dict]:
    specs = []
    entries_by_source: dict[str, list[dict]] = {}
    for entry in _source_runtime_observability_entries(entries):
        if entry.get("alarmEnabled") is True:
            source_system = str(entry.get("sourceSystem", "")).strip()
            entries_by_source.setdefault(source_system, []).append(entry)

    for source_system, source_entries in sorted(entries_by_source.items()):
        source_label = _source_runtime_display_name(source_system)
        alarm_suffix = _safe_resource_suffix(f"{source_system}-source-runtime")
        freshness_minutes = min(int(entry.get("freshnessSlaMinutes") or 60) for entry in source_entries)
        context = f"{source_label} source-runtime observability"
        dimensions = {"SourceId": source_system}
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
                    "description": f"{context}: sustained ingest failures; inspect structured runtime logs for affected runtime ids.",
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
                    "description": f"{context}: graph projection failures detected; inspect structured runtime logs for affected runtime ids.",
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
                    "description": f"{context}: required canonical field classes are missing; inspect redacted validation logs for affected runtime ids.",
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
    jetstream_stream_bytes_alarm_threshold: int = 0,
    jetstream_app_error_alarm_threshold: int = 10,
    jetstream_publish_retry_alarm_threshold: int = 25,
    nats_log_group_name: pulumi.Input[str] = None,
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
            resource_name=f"{name}-graph-rule-timeouts-alarm",
            alarm_name=f"{name}-graph-rule-timeouts",
            namespace=telemetry_namespace,
            metric_name="GraphRuleTimeouts",
            threshold=0,
            description="Graph rule phase timeouts detected; inspect source/rule telemetry and slow Neo4j queries.",
            alarm_actions=alarm_actions,
        )
        _custom_metric_alarm(
            resource_name=f"{name}-graph-ingest-duration-p95-alarm",
            alarm_name=f"{name}-graph-ingest-duration-p95",
            namespace=telemetry_namespace,
            metric_name="GraphIngestDurationMs",
            threshold=900000,
            extended_statistic="p95",
            description="Graph ingest phase p95 duration exceeded 15 minutes.",
            alarm_actions=alarm_actions,
            evaluation_periods=3,
        )
        _custom_metric_alarm(
            resource_name=f"{name}-graph-rule-duration-p95-alarm",
            alarm_name=f"{name}-graph-rule-duration-p95",
            namespace=telemetry_namespace,
            metric_name="GraphRuleDurationMs",
            threshold=840000,
            extended_statistic="p95",
            description="Graph rule phase p95 duration exceeded the pre-timeout guardrail.",
            alarm_actions=alarm_actions,
            evaluation_periods=3,
        )
        _custom_metric_alarm(
            resource_name=f"{name}-neo4j-connectivity-errors-alarm",
            alarm_name=f"{name}-neo4j-connectivity-errors",
            namespace=telemetry_namespace,
            metric_name="Neo4jConnectivityErrors",
            threshold=10,
            description="Neo4j connectivity errors exceeded the operational threshold.",
            alarm_actions=alarm_actions,
        )
        _custom_metric_alarm(
            resource_name=f"{name}-neo4j-transaction-limit-errors-alarm",
            alarm_name=f"{name}-neo4j-transaction-limit-errors",
            namespace=telemetry_namespace,
            metric_name="Neo4jTransactionExecutionLimitErrors",
            threshold=0,
            description="Neo4j transaction execution limit errors detected; inspect graph-rule and ingest query shape.",
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
        if jetstream_app_error_alarm_threshold > 0:
            _custom_metric_alarm(
                resource_name=f"{name}-jetstream-app-errors-alarm",
                alarm_name=f"{name}-jetstream-app-errors",
                namespace=telemetry_namespace,
                metric_name="JetStreamAppErrors",
                threshold=jetstream_app_error_alarm_threshold,
                description="Application-level JetStream errors exceeded the configured threshold; inspect structured app logs for jetstream.error and publish retry exhaustion.",
                alarm_actions=alarm_actions,
            )
        if jetstream_publish_retry_alarm_threshold > 0:
            _custom_metric_alarm(
                resource_name=f"{name}-jetstream-publish-retries-alarm",
                alarm_name=f"{name}-jetstream-publish-retries",
                namespace=telemetry_namespace,
                metric_name="JetStreamPublishRetries",
                threshold=jetstream_publish_retry_alarm_threshold,
                description="JetStream publish retries exceeded the configured threshold; NATS may be accepting connections while publish acknowledgements are unhealthy.",
                alarm_actions=alarm_actions,
            )
        _custom_metric_alarm(
            resource_name=f"{name}-jetstream-publish-retry-exhausted-alarm",
            alarm_name=f"{name}-jetstream-publish-retry-exhausted",
            namespace=telemetry_namespace,
            metric_name="JetStreamPublishRetryExhausted",
            threshold=0,
            description="A JetStream publish exhausted all idempotent retry attempts; inspect jetstream.publish.retry_exhausted and correlated wide events immediately.",
            alarm_actions=alarm_actions,
        )
        _custom_metric_alarm(
            resource_name=f"{name}-jetstream-canary-failures-alarm",
            alarm_name=f"{name}-jetstream-canary-failures",
            namespace=telemetry_namespace,
            metric_name="JetStreamCanaryFailures",
            threshold=0,
            description="The app-level JetStream publish+replay canary failed; inspect jetstream.canary.failed and NATS stream state before trusting health checks.",
            alarm_actions=alarm_actions,
        )
        if jetstream_app_error_alarm_threshold > 0:
            _custom_metric_alarm(
                resource_name=f"{name}-jetstream-append-errors-alarm",
                alarm_name=f"{name}-jetstream-append-errors",
                namespace=telemetry_namespace,
                metric_name="JetStreamAppendErrors",
                threshold=jetstream_app_error_alarm_threshold,
                description="JetStream append errors exceeded the configured threshold; inspect operation=append wide events and publish retry detail.",
                alarm_actions=alarm_actions,
            )
            _custom_metric_alarm(
                resource_name=f"{name}-jetstream-replay-errors-alarm",
                alarm_name=f"{name}-jetstream-replay-errors",
                namespace=telemetry_namespace,
                metric_name="JetStreamReplayErrors",
                threshold=jetstream_app_error_alarm_threshold,
                description="JetStream replay errors exceeded the configured threshold; inspect operation=replay wide events, replay scan counts, and timeout budgets.",
                alarm_actions=alarm_actions,
            )
        _custom_metric_alarm(
            resource_name=f"{name}-platform-job-failures-alarm",
            alarm_name=f"{name}-platform-job-failures",
            namespace=telemetry_namespace,
            metric_name="PlatformJobFailed",
            threshold=0,
            description="A platform or orchestrator job emitted a terminal failed event.",
            alarm_actions=alarm_actions,
        )
        _custom_metric_alarm(
            resource_name=f"{name}-platform-job-phase-failures-alarm",
            alarm_name=f"{name}-platform-job-phase-failures",
            namespace=telemetry_namespace,
            metric_name="PlatformJobPhaseFailed",
            threshold=0,
            description="A platform job phase failed; inspect platform.job.phase.failed for phase, runtime, source, and bounded error kind.",
            alarm_actions=alarm_actions,
        )
        _custom_metric_alarm(
            resource_name=f"{name}-platform-job-runtime-failures-alarm",
            alarm_name=f"{name}-platform-job-runtime-failures",
            namespace=telemetry_namespace,
            metric_name="PlatformJobRuntimeFailed",
            threshold=0,
            description="A platform job runtime failed; inspect platform.job.runtime.failed for runtime/source/tenant and phase counters.",
            alarm_actions=alarm_actions,
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
        for metric_name, description in {
            "OtelCollectorDropped": "OpenTelemetry collector logs report dropped telemetry.",
            "OtelCollectorRefused": "OpenTelemetry collector logs report refused telemetry.",
            "OtelCollectorFailures": "OpenTelemetry collector logs report failed sends or pipeline failures.",
        }.items():
            _custom_metric_alarm(
                resource_name=f"{name}-{_safe_resource_suffix(metric_name)}-alarm",
                alarm_name=f"{name}-{_safe_resource_suffix(metric_name)}",
                namespace=telemetry_namespace,
                metric_name=metric_name,
                threshold=0,
                description=description,
                alarm_actions=alarm_actions,
            )

    nats_log_filters = {}
    if nats_log_group_name is not None:
        nats_log_filters = _create_nats_log_metric_filters(name, nats_log_group_name, telemetry_namespace)
        _custom_metric_alarm(
            resource_name=f"{name}-nats-bootstrap-errors-alarm",
            alarm_name=f"{name}-nats-bootstrap-errors",
            namespace=telemetry_namespace,
            metric_name="NatsBootstrapErrors",
            threshold=0,
            description="NATS JetStream bootstrap reported CLI errors; inspect /ecs/<stack>/nats for stream config drift or request timeouts.",
            alarm_actions=alarm_actions,
        )
        _custom_metric_alarm(
            resource_name=f"{name}-nats-corrupt-state-alarm",
            alarm_name=f"{name}-nats-corrupt-state-recoveries",
            namespace=telemetry_namespace,
            metric_name="NatsCorruptStateRecoveries",
            threshold=0,
            description="NATS JetStream recovered from a corrupt state file; inspect stream restore duration and storage health.",
            alarm_actions=alarm_actions,
        )
        _custom_metric_alarm(
            resource_name=f"{name}-nats-healthcheck-failures-alarm",
            alarm_name=f"{name}-nats-healthcheck-failures",
            namespace=telemetry_namespace,
            metric_name="NatsHealthcheckFailures",
            threshold=0,
            description="NATS health checks have failed for three consecutive periods; JetStream may be restoring or unavailable.",
            alarm_actions=alarm_actions,
            evaluation_periods=3,
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
    if jetstream_stream_bytes_alarm_threshold > 0:
        _custom_metric_alarm(
            resource_name=f"{name}-jetstream-stream-bytes-alarm",
            alarm_name=f"{name}-jetstream-stream-bytes",
            namespace=telemetry_namespace,
            metric_name="JetStreamStreamBytes",
            threshold=jetstream_stream_bytes_alarm_threshold,
            description="JetStream stream bytes are above the configured restore-risk threshold; trim retention or scale storage before restart risk grows.",
            alarm_actions=alarm_actions,
            statistic="Maximum",
            dimensions={"Service": name, "Stream": jetstream_stream_name},
        )

    runtime_ids = sorted({
        runtime_id
        for schedule in orchestrator_schedules or []
        for runtime_id in _runtime_ids_from_command(schedule.get("command") if isinstance(schedule, dict) else None)
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
        for runtime_id in _runtime_ids_from_command(schedule.get("command"))
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
            log_group_name or "",
        ).apply(
            lambda args: _dashboard_body(
                name,
                *args[:5],
                jetstream_stream_name,
                source_runtime_observability,
                otel_collector_enabled=otel_collector_enabled,
                otel_collector_log_group_name=args[5],
                app_log_group_name=args[6],
            )
        ),
    )

    return {
        "alarm_topic": alarm_topic,
        "dashboard": dashboard,
        "telemetry_filters": telemetry_filters,
        "otel_collector_filters": otel_collector_filters,
        "nats_log_filters": nats_log_filters,
    }


def _custom_metric_alarm(
    resource_name: str,
    alarm_name: str,
    namespace: str,
    metric_name: str,
    threshold: int | float,
    description: str,
    alarm_actions: list[pulumi.Input[str]],
    statistic: str = "Sum",
    extended_statistic: str | None = None,
    dimensions: dict = None,
    period: int = 300,
    evaluation_periods: int = 1,
) -> aws.cloudwatch.MetricAlarm:
    alarm_args = {
        "name": alarm_name,
        "comparison_operator": "GreaterThanThreshold",
        "evaluation_periods": evaluation_periods,
        "metric_name": metric_name,
        "namespace": namespace,
        "period": period,
        "threshold": threshold,
        "treat_missing_data": "notBreaching",
        "alarm_description": description,
        "alarm_actions": alarm_actions,
        "dimensions": dimensions,
        "tags": {"Name": alarm_name},
    }
    if extended_statistic:
        alarm_args["extended_statistic"] = extended_statistic
    else:
        alarm_args["statistic"] = statistic
    return aws.cloudwatch.MetricAlarm(resource_name, **alarm_args)


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


def _create_nats_log_metric_filters(name: str, log_group_name: pulumi.Input[str], namespace: str) -> dict:
    filters = {}
    for key, spec in _nats_log_metric_filter_specs().items():
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
            pattern='{ $.kind = "span_end" && $.name = "source_runtime.sync" && $.source_runtime_watermark_lag_seconds = * && $.source_id = * }',
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="SourceRuntimeWatermarkLagSeconds",
                namespace=namespace,
                value="$.source_runtime_watermark_lag_seconds",
                dimensions={"SourceId": "$.source_id"},
            ),
        ),
        "jetstream_app_errors": aws.cloudwatch.LogMetricFilter(
            f"{name}-jetstream-app-errors-filter",
            name=f"{name}-jetstream-app-errors",
            log_group_name=log_group_name,
            pattern='{ $.kind = "event" && $.name = "jetstream.error" }',
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="JetStreamAppErrors",
                namespace=namespace,
                value="1",
                default_value=0,
            ),
        ),
        "jetstream_app_errors_by_kind": aws.cloudwatch.LogMetricFilter(
            f"{name}-jetstream-app-errors-by-kind-filter",
            name=f"{name}-jetstream-app-errors-by-kind",
            log_group_name=log_group_name,
            pattern='{ $.kind = "event" && $.name = "jetstream.error" && $.error_kind = * && $.operation = * }',
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="JetStreamAppErrorsByKind",
                namespace=namespace,
                value="1",
                dimensions={"ErrorKind": "$.error_kind", "Operation": "$.operation"},
            ),
        ),
        "jetstream_js_errors": aws.cloudwatch.LogMetricFilter(
            f"{name}-jetstream-js-errors-filter",
            name=f"{name}-jetstream-js-errors",
            log_group_name=log_group_name,
            pattern='{ $.kind = "event" && $.name = "jetstream.error" && $.error_kind = "jetstream_js_error" }',
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="JetStreamJSErrors",
                namespace=namespace,
                value="1",
                default_value=0,
            ),
        ),
        "jetstream_timeouts": aws.cloudwatch.LogMetricFilter(
            f"{name}-jetstream-timeouts-filter",
            name=f"{name}-jetstream-timeouts",
            log_group_name=log_group_name,
            pattern='{ $.kind = "event" && $.name = "jetstream.error" && (($.error_kind = "context_deadline_exceeded") || ($.error_kind = "context_canceled")) }',
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="JetStreamTimeouts",
                namespace=namespace,
                value="1",
                default_value=0,
            ),
        ),
        "jetstream_publish_retries": aws.cloudwatch.LogMetricFilter(
            f"{name}-jetstream-publish-retries-filter",
            name=f"{name}-jetstream-publish-retries",
            log_group_name=log_group_name,
            pattern='{ $.kind = "event" && $.name = "jetstream.publish.retry" }',
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="JetStreamPublishRetries",
                namespace=namespace,
                value="1",
                default_value=0,
            ),
        ),
        "jetstream_publish_recovered": aws.cloudwatch.LogMetricFilter(
            f"{name}-jetstream-publish-recovered-filter",
            name=f"{name}-jetstream-publish-recovered",
            log_group_name=log_group_name,
            pattern='{ $.kind = "event" && $.name = "jetstream.publish.recovered" }',
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="JetStreamPublishRecovered",
                namespace=namespace,
                value="1",
                default_value=0,
            ),
        ),
        "jetstream_publish_retry_exhausted": aws.cloudwatch.LogMetricFilter(
            f"{name}-jetstream-publish-retry-exhausted-filter",
            name=f"{name}-jetstream-publish-retry-exhausted",
            log_group_name=log_group_name,
            pattern='{ $.kind = "event" && $.name = "jetstream.publish.retry_exhausted" }',
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="JetStreamPublishRetryExhausted",
                namespace=namespace,
                value="1",
                default_value=0,
            ),
        ),
        "jetstream_canary_completed": aws.cloudwatch.LogMetricFilter(
            f"{name}-jetstream-canary-completed-filter",
            name=f"{name}-jetstream-canary-completed",
            log_group_name=log_group_name,
            pattern='{ $.kind = "event" && $.name = "jetstream.canary.completed" }',
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="JetStreamCanaryCompleted",
                namespace=namespace,
                value="1",
                default_value=0,
            ),
        ),
        "jetstream_canary_failures": aws.cloudwatch.LogMetricFilter(
            f"{name}-jetstream-canary-failures-filter",
            name=f"{name}-jetstream-canary-failures",
            log_group_name=log_group_name,
            pattern='{ $.kind = "event" && $.name = "jetstream.canary.failed" }',
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="JetStreamCanaryFailures",
                namespace=namespace,
                value="1",
                default_value=0,
            ),
        ),
        "jetstream_canary_latency": aws.cloudwatch.LogMetricFilter(
            f"{name}-jetstream-canary-latency-filter",
            name=f"{name}-jetstream-canary-latency",
            log_group_name=log_group_name,
            pattern='{ $.kind = "event" && $.name = "jetstream.canary.completed" && $.canary_duration_ms = * }',
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="JetStreamCanaryLatencyMs",
                namespace=namespace,
                value="$.canary_duration_ms",
                default_value=0,
            ),
        ),
        "jetstream_append_errors": aws.cloudwatch.LogMetricFilter(
            f"{name}-jetstream-append-errors-filter",
            name=f"{name}-jetstream-append-errors",
            log_group_name=log_group_name,
            pattern='{ $.kind = "event" && $.name = "jetstream.error" && $.operation = "append" }',
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="JetStreamAppendErrors",
                namespace=namespace,
                value="1",
                default_value=0,
            ),
        ),
        "jetstream_replay_errors": aws.cloudwatch.LogMetricFilter(
            f"{name}-jetstream-replay-errors-filter",
            name=f"{name}-jetstream-replay-errors",
            log_group_name=log_group_name,
            pattern='{ $.kind = "event" && $.name = "jetstream.error" && $.operation = "replay" }',
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="JetStreamReplayErrors",
                namespace=namespace,
                value="1",
                default_value=0,
            ),
        ),
        "jetstream_replay_latency": aws.cloudwatch.LogMetricFilter(
            f"{name}-jetstream-replay-latency-filter",
            name=f"{name}-jetstream-replay-latency",
            log_group_name=log_group_name,
            pattern='{ $.kind = "span_end" && $.name = "jetstream.replay" && $.duration_ms = * }',
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="JetStreamReplayLatencyMs",
                namespace=namespace,
                value="$.duration_ms",
                default_value=0,
            ),
        ),
        "platform_job_started": aws.cloudwatch.LogMetricFilter(
            f"{name}-platform-job-started-filter",
            name=f"{name}-platform-job-started",
            log_group_name=log_group_name,
            pattern='{ $.kind = "event" && $.name = "platform.job.started" }',
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="PlatformJobStarted",
                namespace=namespace,
                value="1",
                default_value=0,
            ),
        ),
        "platform_job_completed": aws.cloudwatch.LogMetricFilter(
            f"{name}-platform-job-completed-filter",
            name=f"{name}-platform-job-completed",
            log_group_name=log_group_name,
            pattern='{ $.kind = "event" && $.name = "platform.job.completed" }',
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="PlatformJobCompleted",
                namespace=namespace,
                value="1",
                default_value=0,
            ),
        ),
        "platform_job_failed": aws.cloudwatch.LogMetricFilter(
            f"{name}-platform-job-failed-filter",
            name=f"{name}-platform-job-failed",
            log_group_name=log_group_name,
            pattern='{ $.kind = "event" && $.name = "platform.job.failed" }',
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="PlatformJobFailed",
                namespace=namespace,
                value="1",
                default_value=0,
            ),
        ),
        "platform_job_heartbeat": aws.cloudwatch.LogMetricFilter(
            f"{name}-platform-job-heartbeat-filter",
            name=f"{name}-platform-job-heartbeat",
            log_group_name=log_group_name,
            pattern='{ $.kind = "event" && $.name = "platform.job.heartbeat" }',
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="PlatformJobHeartbeats",
                namespace=namespace,
                value="1",
                default_value=0,
            ),
        ),
        "platform_job_phase_failed": aws.cloudwatch.LogMetricFilter(
            f"{name}-platform-job-phase-failed-filter",
            name=f"{name}-platform-job-phase-failed",
            log_group_name=log_group_name,
            pattern='{ $.kind = "event" && $.name = "platform.job.phase.failed" }',
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="PlatformJobPhaseFailed",
                namespace=namespace,
                value="1",
                default_value=0,
            ),
        ),
        "platform_job_phase_failed_by_phase": aws.cloudwatch.LogMetricFilter(
            f"{name}-platform-job-phase-failed-by-phase-filter",
            name=f"{name}-platform-job-phase-failed-by-phase",
            log_group_name=log_group_name,
            pattern='{ $.kind = "event" && $.name = "platform.job.phase.failed" && $.job_phase_key = * }',
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="PlatformJobPhaseFailedByPhase",
                namespace=namespace,
                value="1",
                dimensions={"Phase": "$.job_phase_key"},
            ),
        ),
        "platform_job_runtime_failed": aws.cloudwatch.LogMetricFilter(
            f"{name}-platform-job-runtime-failed-filter",
            name=f"{name}-platform-job-runtime-failed",
            log_group_name=log_group_name,
            pattern='{ $.kind = "event" && $.name = "platform.job.runtime.failed" }',
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="PlatformJobRuntimeFailed",
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
        "graph_rule_findings_by_source": aws.cloudwatch.LogMetricFilter(
            f"{name}-graph-rule-findings-by-source-filter",
            name=f"{name}-graph-rule-findings-by-source",
            log_group_name=log_group_name,
            pattern='{ $.kind = "span_end" && $.name = "orchestrator.runtime" && $.graph_rule_findings = * && $.source_id = * }',
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="GraphRuleFindingsEmittedBySource",
                namespace=namespace,
                value="$.graph_rule_findings",
                dimensions={"SourceId": "$.source_id"},
            ),
        ),
        "graph_rule_rows_read_by_source": aws.cloudwatch.LogMetricFilter(
            f"{name}-graph-rule-rows-read-by-source-filter",
            name=f"{name}-graph-rule-rows-read-by-source",
            log_group_name=log_group_name,
            pattern='{ $.kind = "span_end" && $.name = "orchestrator.runtime" && $.graph_rule_rows_read = * && $.source_id = * }',
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="GraphRuleRowsReadBySource",
                namespace=namespace,
                value="$.graph_rule_rows_read",
                dimensions={"SourceId": "$.source_id"},
            ),
        ),
        "graph_rule_timeouts": aws.cloudwatch.LogMetricFilter(
            f"{name}-graph-rule-timeouts-filter",
            name=f"{name}-graph-rule-timeouts",
            log_group_name=log_group_name,
            pattern='{ $.kind = "span_end" && $.name = "orchestrator.graph_rules" && $.status = "failed" && $.timeout_exceeded = true }',
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="GraphRuleTimeouts",
                namespace=namespace,
                value="1",
                default_value=0,
            ),
        ),
        "graph_rule_timeouts_by_source": aws.cloudwatch.LogMetricFilter(
            f"{name}-graph-rule-timeouts-by-source-filter",
            name=f"{name}-graph-rule-timeouts-by-source",
            log_group_name=log_group_name,
            pattern='{ $.kind = "span_end" && $.name = "orchestrator.graph_rules" && $.status = "failed" && $.timeout_exceeded = true && $.source_id = * }',
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="GraphRuleTimeoutsBySource",
                namespace=namespace,
                value="1",
                dimensions={"SourceId": "$.source_id"},
            ),
        ),
        "neo4j_connectivity_errors": aws.cloudwatch.LogMetricFilter(
            f"{name}-neo4j-connectivity-errors-filter",
            name=f"{name}-neo4j-connectivity-errors",
            log_group_name=log_group_name,
            pattern='{ $.kind = "event" && $.name = "neo4j.error" && $.error_kind = "errorutil_connectivity_error" }',
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="Neo4jConnectivityErrors",
                namespace=namespace,
                value="1",
                default_value=0,
            ),
        ),
        "neo4j_transaction_execution_limit_errors": aws.cloudwatch.LogMetricFilter(
            f"{name}-neo4j-transaction-limit-errors-filter",
            name=f"{name}-neo4j-transaction-limit-errors",
            log_group_name=log_group_name,
            pattern='{ $.kind = "event" && $.name = "neo4j.error" && $.error_kind = "errorutil_transaction_execution_limit" }',
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="Neo4jTransactionExecutionLimitErrors",
                namespace=namespace,
                value="1",
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
        "graph_ingest_duration": aws.cloudwatch.LogMetricFilter(
            f"{name}-graph-ingest-duration-filter",
            name=f"{name}-graph-ingest-duration",
            log_group_name=log_group_name,
            pattern='{ $.kind = "span_end" && $.name = "orchestrator.graph_ingest" && $.duration_ms = * }',
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="GraphIngestDurationMs",
                namespace=namespace,
                value="$.duration_ms",
                default_value=0,
            ),
        ),
        "graph_rule_duration": aws.cloudwatch.LogMetricFilter(
            f"{name}-graph-rule-duration-filter",
            name=f"{name}-graph-rule-duration",
            log_group_name=log_group_name,
            pattern='{ $.kind = "span_end" && $.name = "orchestrator.graph_rules" && $.duration_ms = * }',
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name="GraphRuleDurationMs",
                namespace=namespace,
                value="$.duration_ms",
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
    for suffix, metric_name, pattern in [
        ("failed-detail", "OtelCollectorFailures", "failed"),
        ("dropped-detail", "OtelCollectorDropped", "dropped"),
        ("refused-detail", "OtelCollectorRefused", "refused"),
    ]:
        filters[suffix] = aws.cloudwatch.LogMetricFilter(
            f"{name}-otel-collector-{suffix}-filter",
            name=f"{name}-otel-collector-{suffix}",
            log_group_name=log_group_name,
            pattern=pattern,
            metric_transformation=aws.cloudwatch.LogMetricFilterMetricTransformationArgs(
                name=metric_name,
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
    app_log_group_name: str | None = None,
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
                        [{"expression": f"SEARCH('{{{telemetry_namespace},SourceId}} MetricName=\"SourceRuntimeWatermarkLagSeconds\"', 'Maximum', 300)", "label": "Watermark lag", "id": "e1", "yAxis": "right"}],
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
                "x": 0, "y": 60, "width": 12, "height": 6,
                "properties": {
                    "title": "App JetStream Reliability",
                    "metrics": [
                        [telemetry_namespace, "JetStreamAppErrors", {"stat": "Sum", "label": "App errors"}],
                        [".", "JetStreamJSErrors", {"stat": "Sum", "label": "JS errors"}],
                        [".", "JetStreamTimeouts", {"stat": "Sum", "label": "Timeouts/cancels"}],
                        [".", "JetStreamAppendErrors", {"stat": "Sum", "label": "Append errors"}],
                        [".", "JetStreamReplayErrors", {"stat": "Sum", "label": "Replay errors"}],
                        [".", "JetStreamPublishRetries", {"stat": "Sum", "label": "Publish retries"}],
                        [".", "JetStreamPublishRecovered", {"stat": "Sum", "label": "Recovered after retry"}],
                        [".", "JetStreamPublishRetryExhausted", {"stat": "Sum", "label": "Retry exhausted"}],
                        [".", "JetStreamCanaryFailures", {"stat": "Sum", "label": "Canary failures"}],
                        [".", "JetStreamCanaryLatencyMs", {"stat": "p95", "label": "Canary p95 ms", "yAxis": "right"}],
                        [".", "JetStreamReplayLatencyMs", {"stat": "p95", "label": "Replay p95 ms", "yAxis": "right"}],
                        [
                            {
                                "expression": f"SEARCH('{{{telemetry_namespace},ErrorKind,Operation}} MetricName=\"JetStreamAppErrorsByKind\"', 'Sum', 300)",
                                "label": "Errors by kind/op",
                                "id": "e1",
                                "yAxis": "right",
                            }
                        ],
                    ],
                    "period": 300,
                    "region": aws.get_region().region,
                },
            },
            {
                "type": "metric",
                "x": 12, "y": 48, "width": 12, "height": 6,
                "properties": {
                    "title": "Platform Job Lifecycle",
                    "metrics": [
                        [telemetry_namespace, "PlatformJobStarted", {"stat": "Sum", "label": "Started"}],
                        [".", "PlatformJobCompleted", {"stat": "Sum", "label": "Completed"}],
                        [".", "PlatformJobFailed", {"stat": "Sum", "label": "Failed"}],
                        [".", "PlatformJobHeartbeats", {"stat": "Sum", "label": "Heartbeats"}],
                        [".", "PlatformJobPhaseFailed", {"stat": "Sum", "label": "Phase failed"}],
                        [".", "PlatformJobRuntimeFailed", {"stat": "Sum", "label": "Runtime failed"}],
                        [
                            {
                                "expression": f"SEARCH('{{{telemetry_namespace},Phase}} MetricName=\"PlatformJobPhaseFailedByPhase\"', 'Sum', 300)",
                                "label": "Phase failures by phase",
                                "id": "e1",
                                "yAxis": "right",
                            }
                        ],
                    ],
                    "period": 300,
                    "region": aws.get_region().region,
                },
            },
            {
                "type": "metric",
                "x": 12, "y": 60, "width": 12, "height": 6,
                "properties": {
                    "title": "NATS JetStream Operations",
                    "metrics": [
                        [telemetry_namespace, "NatsHealthcheckFailures", {"stat": "Sum"}],
                        [".", "NatsBootstrapErrors", {"stat": "Sum"}],
                        [".", "NatsCorruptStateRecoveries", {"stat": "Sum"}],
                        [".", "NatsRestoreCompletions", {"stat": "Sum"}],
                    ],
                    "period": 300,
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
                        [".", "GraphRuleTimeouts", {"stat": "Sum"}],
                        [".", "GraphIngestDurationMs", {"stat": "p95", "label": "Graph ingest p95 ms", "yAxis": "right"}],
                        [".", "GraphRuleDurationMs", {"stat": "p95", "label": "Graph rule p95 ms", "yAxis": "right"}],
                        [
                            {
                                "expression": f"SEARCH('{{{telemetry_namespace},InstanceId}} MetricName=\"Neo4jAuraInstanceUp\"', 'Minimum', 300)",
                                "label": "Aura instance up",
                                "id": "e1",
                            }
                        ],
                        [
                            {
                                "expression": f"SEARCH('{{{telemetry_namespace},InstanceId}} MetricName=\"Neo4jAuraMemoryGB\"', 'Maximum', 300)",
                                "label": "Aura memory GB",
                                "id": "e2",
                                "yAxis": "right",
                            }
                        ],
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
    jetstream_diagnostic_widgets = _jetstream_diagnostic_widgets(app_log_group_name, 66) if app_log_group_name else []
    tenant_y = 72 if jetstream_diagnostic_widgets else 66
    tenant_diagnostic_widgets = _tenant_runtime_diagnostic_widgets(app_log_group_name, tenant_y) if app_log_group_name else []
    job_y = tenant_y + 6 if tenant_diagnostic_widgets else (72 if jetstream_diagnostic_widgets else 66)
    job_diagnostic_widgets = _job_diagnostic_widgets(app_log_group_name, job_y) if app_log_group_name else []
    next_y = job_y + 6 if job_diagnostic_widgets else job_y
    otel_widgets = (
        _otel_collector_observability_widgets(
            name,
            cluster,
            telemetry_namespace,
            otel_collector_log_group_name,
            next_y,
        )
        if otel_collector_enabled and otel_collector_log_group_name
        else []
    )
    if otel_widgets:
        next_y += 18
    otel_product_widgets = _otel_product_metric_widgets(next_y) if otel_widgets else []
    if otel_product_widgets:
        next_y += 24
    widgets.extend(jetstream_diagnostic_widgets)
    widgets.extend(tenant_diagnostic_widgets)
    widgets.extend(job_diagnostic_widgets)
    widgets.extend(otel_widgets)
    widgets.extend(otel_product_widgets)
    widgets.extend(
        _source_runtime_observability_widgets(
            telemetry_namespace,
            source_runtime_observability,
            start_y=next_y,
        )
    )
    return json.dumps({"widgets": widgets})


def _jetstream_diagnostic_widgets(log_group_name: str, y: int) -> list[dict]:
    region = aws.get_region().region
    event_filter = (
        'kind = "event" and (name = "jetstream.error" or name = "jetstream.publish.retry" '
        'or name = "jetstream.publish.retry_exhausted" or name = "jetstream.publish.recovered" '
        'or name = "jetstream.canary.completed" or name = "jetstream.canary.failed")'
    )
    return [
        {
            "type": "log",
            "x": 0,
            "y": y,
            "width": 12,
            "height": 6,
            "properties": {
                "title": "JetStream App Events",
                "query": (
                    f"SOURCE '{log_group_name}' | fields @timestamp, name, operation, error_kind, error_fingerprint, "
                    "`messaging.jetstream.error.category`, canary_duration_ms, "
                    "`messaging.jetstream.canary.replayed`, `messaging.jetstream.ack.stream`, `messaging.jetstream.ack.sequence`, "
                    "`messaging.jetstream.subject`, `messaging.jetstream.publish.retry_count`, "
                    "`messaging.jetstream.publish.attempts`, trace_id, runtime_id, source_id, tenant_id "
                    f"| filter {event_filter} "
                    "| sort @timestamp desc | limit 50"
                ),
                "region": region,
                "view": "table",
            },
        },
        {
            "type": "log",
            "x": 12,
            "y": y,
            "width": 12,
            "height": 6,
            "properties": {
                "title": "JetStream App Event Groups",
                "query": (
                    f"SOURCE '{log_group_name}' | fields name, operation, error_kind, error_fingerprint, "
                    "`messaging.jetstream.error.category`, `messaging.jetstream.subject`, `messaging.jetstream.publish.retry_count` "
                    f"| filter {event_filter} "
                    "| stats count(*) as events, max(@timestamp) as last_seen by name, operation, error_kind, error_fingerprint, `messaging.jetstream.error.category`, `messaging.jetstream.subject` "
                    "| sort events desc | limit 50"
                ),
                "region": region,
                "view": "table",
            },
        },
    ]


def _job_diagnostic_widgets(log_group_name: str, y: int) -> list[dict]:
    region = aws.get_region().region
    job_filter = 'kind = "event" and name like /platform\\.job/'
    failure_filter = (
        'kind = "event" and (name = "platform.job.failed" or name = "platform.job.phase.failed" '
        'or name = "platform.job.runtime.failed")'
    )
    return [
        {
            "type": "log",
            "x": 0,
            "y": y,
            "width": 12,
            "height": 6,
            "properties": {
                "title": "Platform Job Events",
                "query": (
                    f"SOURCE '{log_group_name}' | fields @timestamp, name, job_id, job_kind, job_phase, "
                    "job_phase_status, job_heartbeat_stage, job_runtime_status, runtime_id, source_id, tenant_id, "
                    f"error_kind, duration_ms, trace_id | filter {job_filter} "
                    "| sort @timestamp desc | limit 50"
                ),
                "region": region,
                "view": "table",
            },
        },
        {
            "type": "log",
            "x": 12,
            "y": y,
            "width": 12,
            "height": 6,
            "properties": {
                "title": "Platform Job Failure Groups",
                "query": (
                    f"SOURCE '{log_group_name}' | fields name, job_kind, job_phase_key, job_runtime_status, "
                    "runtime_id, source_id, tenant_id, error_kind, error_fingerprint "
                    f"| filter {failure_filter} "
                    "| stats count(*) as events, max(@timestamp) as last_seen by name, job_kind, job_phase_key, job_runtime_status, runtime_id, source_id, tenant_id, error_kind, error_fingerprint "
                    "| sort events desc | limit 50"
                ),
                "region": region,
                "view": "table",
            },
        },
    ]


def _tenant_runtime_diagnostic_widgets(log_group_name: str, y: int) -> list[dict]:
    region = aws.get_region().region
    base_filter = '(name = "source_runtime.sync" or name = "source_projection.project")'
    return [
        {
            "type": "log",
            "x": 0,
            "y": y,
            "width": 12,
            "height": 6,
            "properties": {
                "title": "Tenant Runtime Failures",
                "query": (
                    f"SOURCE '{log_group_name}' | fields @timestamp, name, trace_id, tenant_id, source_id, runtime_id, event_kind, status, error_kind "
                    f"| filter {base_filter} and status = \"failed\" "
                    "| sort @timestamp desc | limit 50"
                ),
                "region": region,
                "view": "table",
            },
        },
        {
            "type": "log",
            "x": 12,
            "y": y,
            "width": 12,
            "height": 6,
            "properties": {
                "title": "Tenant Runtime Failure Groups",
                "query": (
                    f"SOURCE '{log_group_name}' | fields name, tenant_id, source_id, runtime_id, event_kind, status, error_kind "
                    f"| filter {base_filter} and status = \"failed\" "
                    "| stats count(*) as events by tenant_id, source_id, runtime_id, event_kind, error_kind "
                    "| sort events desc | limit 50"
                ),
                "region": region,
                "view": "table",
            },
        },
    ]


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
            "y": y + 12,
            "width": 24,
            "height": 6,
            "properties": {
                "title": "OTEL Collector Recent Logs",
                "query": f"SOURCE '{log_group_name}' | fields @timestamp, @message | sort @timestamp desc | limit 40",
                "region": region,
                "view": "table",
            },
        },
        {
            "type": "metric",
            "x": 0,
            "y": y + 6,
            "width": 12,
            "height": 6,
            "properties": {
                "title": "OTEL Collector Queue",
                "metrics": [
                    [
                        {
                            "expression": "SEARCH('{Cerebro/OTEL} MetricName=\"otelcol_exporter_queue_size\"', 'Average', 60)",
                            "label": "Exporter queue size",
                            "id": "e1",
                        }
                    ],
                    [
                        {
                            "expression": "SEARCH('{Cerebro/OTEL} MetricName=\"otelcol_exporter_queue_capacity\"', 'Average', 60)",
                            "label": "Exporter queue capacity",
                            "id": "e2",
                            "yAxis": "right",
                        }
                    ],
                ],
                "period": 60,
                "region": region,
            },
        },
        {
            "type": "metric",
            "x": 12,
            "y": y + 6,
            "width": 12,
            "height": 6,
            "properties": {
                "title": "OTEL Collector Refused / Failed",
                "metrics": [
                    [
                        {
                            "expression": "SEARCH('{Cerebro/OTEL} MetricName=\"otelcol_exporter_send_failed_spans\"', 'Sum', 60)",
                            "label": "Failed spans",
                            "id": "e1",
                        }
                    ],
                    [
                        {
                            "expression": "SEARCH('{Cerebro/OTEL} MetricName=\"otelcol_exporter_send_failed_metric_points\"', 'Sum', 60)",
                            "label": "Failed metric points",
                            "id": "e2",
                        }
                    ],
                    [
                        {
                            "expression": "SEARCH('{Cerebro/OTEL} MetricName=\"otelcol_exporter_enqueue_failed_spans\"', 'Sum', 60)",
                            "label": "Enqueue failed spans",
                            "id": "e3",
                        }
                    ],
                    [
                        {
                            "expression": "SEARCH('{Cerebro/OTEL} MetricName=\"otelcol_exporter_enqueue_failed_metric_points\"', 'Sum', 60)",
                            "label": "Enqueue failed metric points",
                            "id": "e4",
                        }
                    ],
                    [
                        {
                            "expression": "SEARCH('{Cerebro/OTEL} MetricName=\"otelcol_receiver_refused_spans\"', 'Sum', 60)",
                            "label": "Receiver refused spans",
                            "id": "e5",
                        }
                    ],
                    [
                        {
                            "expression": "SEARCH('{Cerebro/OTEL} MetricName=\"otelcol_receiver_refused_metric_points\"', 'Sum', 60)",
                            "label": "Receiver refused metric points",
                            "id": "e6",
                        }
                    ],
                ],
                "period": 60,
                "region": region,
            },
        },
    ]


def _otel_product_metric_widgets(y: int) -> list[dict]:
    region = aws.get_region().region
    return [
        {
            "type": "metric",
            "x": 0,
            "y": y,
            "width": 12,
            "height": 6,
            "properties": {
                "title": "OTEL Product Source Runtime",
                "metrics": [
                    [
                        {
                            "expression": "SEARCH('{Cerebro/OTEL,source_id,status,error_kind,contract_configured} MetricName=\"cerebro.source_runtime.sync.runs\"', 'Sum', 60)",
                            "label": "Sync runs by source/status",
                            "id": "e1",
                        }
                    ],
                    [
                        {
                            "expression": "SEARCH('{Cerebro/OTEL,source_id,status,error_kind,contract_configured} MetricName=\"cerebro.source_runtime.sync.duration\"', 'p95', 60)",
                            "label": "Sync duration p95",
                            "id": "e2",
                            "yAxis": "right",
                        }
                    ],
                ],
                "period": 60,
                "region": region,
            },
        },
        {
            "type": "metric",
            "x": 12,
            "y": y,
            "width": 12,
            "height": 6,
            "properties": {
                "title": "OTEL Source Records / Freshness",
                "metrics": [
                    [
                        {
                            "expression": "SEARCH('{Cerebro/OTEL,source_id,status,error_kind,contract_configured,record.kind} MetricName=\"cerebro.source_runtime.records\"', 'Sum', 60)",
                            "label": "Runtime records by kind",
                            "id": "e1",
                        }
                    ],
                    [
                        {
                            "expression": "SEARCH('{Cerebro/OTEL,source_id,status,error_kind,contract_configured} MetricName=\"cerebro.source_runtime.watermark.lag\"', 'Maximum', 60)",
                            "label": "Watermark lag max",
                            "id": "e2",
                            "yAxis": "right",
                        }
                    ],
                ],
                "period": 60,
                "region": region,
            },
        },
        {
            "type": "metric",
            "x": 0,
            "y": y + 6,
            "width": 12,
            "height": 6,
            "properties": {
                "title": "OTEL Projection Runs",
                "metrics": [
                    [
                        {
                            "expression": "SEARCH('{Cerebro/OTEL,source_id,event_kind,status} MetricName=\"cerebro.source_projection.runs\"', 'Sum', 60)",
                            "label": "Projection runs by source/event/status",
                            "id": "e1",
                        }
                    ],
                    [
                        {
                            "expression": "SEARCH('{Cerebro/OTEL,source_id,event_kind,status} MetricName=\"cerebro.source_projection.duration\"', 'p95', 60)",
                            "label": "Projection duration p95",
                            "id": "e2",
                            "yAxis": "right",
                        }
                    ],
                ],
                "period": 60,
                "region": region,
            },
        },
        {
            "type": "metric",
            "x": 12,
            "y": y + 6,
            "width": 12,
            "height": 6,
            "properties": {
                "title": "OTEL Projection Records",
                "metrics": [
                    [
                        {
                            "expression": "SEARCH('{Cerebro/OTEL,source_id,event_kind,status,record.kind} MetricName=\"cerebro.source_projection.records\"', 'Sum', 60)",
                            "label": "Projection records by kind",
                            "id": "e1",
                        }
                    ],
                ],
                "period": 60,
                "region": region,
            },
        },
        {
            "type": "metric",
            "x": 0,
            "y": y + 12,
            "width": 12,
            "height": 6,
            "properties": {
                "title": "OTEL Graph Rule Evaluations",
                "metrics": [
                    [
                        {
                            "expression": "SEARCH('{Cerebro/OTEL,source_id,rule_id,status,error_kind,truncated} MetricName=\"cerebro.graph_rule.evaluations\"', 'Sum', 60)",
                            "label": "Graph rule evaluations",
                            "id": "e1",
                        }
                    ],
                    [
                        {
                            "expression": "SEARCH('{Cerebro/OTEL,source_id,rule_id,status,error_kind,truncated} MetricName=\"cerebro.graph_rule.duration\"', 'p95', 60)",
                            "label": "Graph rule duration p95",
                            "id": "e2",
                            "yAxis": "right",
                        }
                    ],
                ],
                "period": 60,
                "region": region,
            },
        },
        {
            "type": "metric",
            "x": 12,
            "y": y + 12,
            "width": 12,
            "height": 6,
            "properties": {
                "title": "OTEL Graph Rule Records",
                "metrics": [
                    [
                        {
                            "expression": "SEARCH('{Cerebro/OTEL,source_id,rule_id,status,error_kind,truncated,record.kind} MetricName=\"cerebro.graph_rule.records\"', 'Sum', 60)",
                            "label": "Rows read / findings emitted",
                            "id": "e1",
                        }
                    ],
                ],
                "period": 60,
                "region": region,
            },
        },
        {
            "type": "metric",
            "x": 0,
            "y": y + 18,
            "width": 12,
            "height": 6,
            "properties": {
                "title": "OTEL Orchestrator Phase SLO",
                "metrics": [
                    [
                        {
                            "expression": "SEARCH('{Cerebro/OTEL,phase_key,source_id,status,error_kind,timeout_exceeded} MetricName=\"cerebro.orchestrator.phase.runs\"', 'Sum', 60)",
                            "label": "Phase runs",
                            "id": "e1",
                        }
                    ],
                    [
                        {
                            "expression": "SEARCH('{Cerebro/OTEL,phase_key,source_id,status,error_kind,timeout_exceeded} MetricName=\"cerebro.orchestrator.phase.duration\"', 'p95', 60)",
                            "label": "Phase duration p95",
                            "id": "e2",
                            "yAxis": "right",
                        }
                    ],
                ],
                "period": 60,
                "region": region,
            },
        },
        {
            "type": "metric",
            "x": 12,
            "y": y + 18,
            "width": 12,
            "height": 6,
            "properties": {
                "title": "OTEL Neo4j Operations",
                "metrics": [
                    [
                        {
                            "expression": "SEARCH('{Cerebro/OTEL,operation,status,error_kind,database_configured} MetricName=\"cerebro.neo4j.operations\"', 'Sum', 60)",
                            "label": "Neo4j operations",
                            "id": "e1",
                        }
                    ],
                    [
                        {
                            "expression": "SEARCH('{Cerebro/OTEL,operation,status,error_kind,database_configured} MetricName=\"cerebro.neo4j.operation.duration\"', 'p95', 60)",
                            "label": "Neo4j duration p95",
                            "id": "e2",
                            "yAxis": "right",
                        }
                    ],
                ],
                "period": 60,
                "region": region,
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
        throughput_metrics = [
            [telemetry_namespace, "SourceRuntimeIngestSuccess", "SourceId", source_system, {"stat": "Sum", "label": "sync successes"}],
            [".", "SourceRuntimeIngestFailure", ".", ".", {"stat": "Sum", "label": "sync failures"}],
            [".", "SourceRuntimeRecordsAccepted", ".", ".", {"stat": "Sum", "label": "records accepted"}],
            [".", "SourceRuntimeRecordsRejected", ".", ".", {"stat": "Sum", "label": "records rejected"}],
        ]
        probe_metrics = [
            [telemetry_namespace, "SourceRuntimeContractProbeSuccess", "SourceId", source_system, {"stat": "Sum", "label": "probe success"}],
            [".", "SourceRuntimeContractProbeFailure", ".", ".", {"stat": "Sum", "label": "probe failure/stale/unknown"}],
        ]
        projection_metrics = [
            [telemetry_namespace, "SourceRuntimeProjectionSuccess", "SourceId", source_system, {"stat": "Sum", "label": "entities projected"}],
            [".", "SourceRuntimeProjectionFailure", ".", ".", {"stat": "Sum", "label": "projection failures"}],
        ]
        link_metrics = [
            [telemetry_namespace, "SourceRuntimeOrphanMissingLink", "SourceId", source_system, {"stat": "Sum", "label": "orphan/missing-link"}],
            [".", "SourceRuntimeMissingCanonicalFields", ".", ".", {"stat": "Sum", "label": "missing canonical fields"}],
        ]
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
