"""
AWS CloudWatch monitoring and alarms.
"""

import pulumi
import pulumi_aws as aws


def create_monitoring(
    name: str,
    alb_arn_suffix: pulumi.Output[str],
    target_group_arn_suffix: pulumi.Output[str],
    ecs_cluster_name: pulumi.Output[str],
    ecs_service_name: pulumi.Output[str],
    log_group_name: pulumi.Output[str] = None,
    log_retention_days: int = 30,
    jetstream_stream_name: str = "CEREBRO_EVENTS",
    jetstream_lag_alarm_threshold: int = 10000,
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
        alarm_actions=[alarm_topic.arn],
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
        alarm_actions=[alarm_topic.arn],
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
        alarm_actions=[alarm_topic.arn],
        dimensions={
            "LoadBalancer": alb_arn_suffix,
            "TargetGroup": target_group_arn_suffix,
        },
        tags={"Name": f"{name}-unhealthy-alarm"},
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
        alarm_actions=[alarm_topic.arn],
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
        alarm_actions=[alarm_topic.arn],
        dimensions={
            "ClusterName": ecs_cluster_name,
            "ServiceName": ecs_service_name,
        },
        tags={"Name": f"{name}-memory-alarm"},
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
            alarm_topic_arn=alarm_topic.arn,
        )
        _custom_metric_alarm(
            resource_name=f"{name}-orchestrator-failures-alarm",
            alarm_name=f"{name}-orchestrator-runtime-failures",
            namespace=telemetry_namespace,
            metric_name="OrchestratorRuntimeFailures",
            threshold=0,
            description="Orchestrator runtime failures detected",
            alarm_topic_arn=alarm_topic.arn,
        )
        _custom_metric_alarm(
            resource_name=f"{name}-report-failures-alarm",
            alarm_name=f"{name}-report-generation-failures",
            namespace=telemetry_namespace,
            metric_name="ReportGenerationFailures",
            threshold=0,
            description="Report generation failures detected",
            alarm_topic_arn=alarm_topic.arn,
        )
        _custom_metric_alarm(
            resource_name=f"{name}-graph-ingest-failures-alarm",
            alarm_name=f"{name}-graph-ingest-failures",
            namespace=telemetry_namespace,
            metric_name="GraphIngestFailures",
            threshold=0,
            description="Graph ingestion failures detected",
            alarm_topic_arn=alarm_topic.arn,
        )

    if jetstream_lag_alarm_threshold > 0:
        _custom_metric_alarm(
            resource_name=f"{name}-jetstream-lag-alarm",
            alarm_name=f"{name}-jetstream-consumer-lag",
            namespace=telemetry_namespace,
            metric_name="JetStreamConsumerLag",
            threshold=jetstream_lag_alarm_threshold,
            description="JetStream consumer lag is above the autoscaling readiness threshold",
            alarm_topic_arn=alarm_topic.arn,
            statistic="Maximum",
            dimensions={"Service": name, "Stream": jetstream_stream_name},
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
    alarm_topic_arn: pulumi.Input[str],
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
        alarm_actions=[alarm_topic_arn],
        dimensions=dimensions,
        tags={"Name": alarm_name},
    )


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
        ],
    })
