"""
AWS CloudWatch monitoring and alarms.

Creates:
- CloudWatch dashboards
- CloudWatch alarms for critical metrics
- SNS topics for alarm notifications
- Log metric filters
"""
import pulumi
import pulumi_aws as aws
import json


def create_monitoring(
    name: str,
    alb_arn_suffix: pulumi.Output[str],
    target_group_arn_suffix: pulumi.Output[str],
    ecs_cluster_name: pulumi.Output[str],
    ecs_service_names: list[pulumi.Output[str]],
    dynamodb_table_names: list[pulumi.Output[str]],
    redis_cluster_id: pulumi.Output[str],
    alarm_email: str = None,
    log_retention_days: int = 30,
) -> dict:
    """
    Create monitoring infrastructure with alarms and dashboards.

    Args:
        name: Monitoring stack name prefix
        alb_arn_suffix: ALB ARN suffix for metrics
        target_group_arn_suffix: Target group ARN suffix for metrics
        ecs_cluster_name: ECS cluster name
        ecs_service_names: List of ECS service names
        dynamodb_table_names: List of DynamoDB table names
        redis_cluster_id: Redis cluster ID
        alarm_email: Email address for alarm notifications
        log_retention_days: CloudWatch log retention in days

    Returns:
        Dictionary with monitoring resources
    """
    result = {}

    # Create SNS topic for alarms
    if alarm_email:
        alarm_topic = aws.sns.Topic(
            f"{name}-alarms",
            name=f"{name}-alarms",
            tags={
                "Name": f"{name}-alarms",
            },
        )

        aws.sns.TopicSubscription(
            f"{name}-alarm-email",
            topic=alarm_topic.arn,
            protocol="email",
            endpoint=alarm_email,
        )

        result["alarm_topic"] = alarm_topic

    # ALB Alarms
    _create_alb_alarms(
        name=name,
        alb_arn_suffix=alb_arn_suffix,
        target_group_arn_suffix=target_group_arn_suffix,
        alarm_actions=[alarm_topic.arn] if alarm_email else [],
    )

    # ECS Alarms
    for idx, service_name in enumerate(ecs_service_names):
        _create_ecs_alarms(
            name=name,
            cluster_name=ecs_cluster_name,
            service_name=service_name,
            index=idx,
            alarm_actions=[alarm_topic.arn] if alarm_email else [],
        )

    # DynamoDB Alarms
    for idx, table_name in enumerate(dynamodb_table_names):
        _create_dynamodb_alarms(
            name=name,
            table_name=table_name,
            index=idx,
            alarm_actions=[alarm_topic.arn] if alarm_email else [],
        )

    # Redis Alarms
    _create_redis_alarms(
        name=name,
        cluster_id=redis_cluster_id,
        alarm_actions=[alarm_topic.arn] if alarm_email else [],
    )

    # Create CloudWatch dashboard
    dashboard = _create_dashboard(
        name=name,
        alb_arn_suffix=alb_arn_suffix,
        target_group_arn_suffix=target_group_arn_suffix,
        ecs_cluster_name=ecs_cluster_name,
        ecs_service_names=ecs_service_names,
        dynamodb_table_names=dynamodb_table_names,
        redis_cluster_id=redis_cluster_id,
    )

    result["dashboard"] = dashboard

    return result


def _create_alb_alarms(
    name: str,
    alb_arn_suffix: pulumi.Output[str],
    target_group_arn_suffix: pulumi.Output[str],
    alarm_actions: list[str],
):
    """Create CloudWatch alarms for ALB."""
    # High 5xx error rate
    aws.cloudwatch.MetricAlarm(
        f"{name}-alb-5xx-high",
        comparison_operator="GreaterThanThreshold",
        evaluation_periods=2,
        metric_name="HTTPCode_Target_5XX_Count",
        namespace="AWS/ApplicationELB",
        period=300,
        statistic="Sum",
        threshold=50,
        alarm_description="ALB 5xx errors above threshold",
        alarm_actions=alarm_actions,
        dimensions={
            "LoadBalancer": alb_arn_suffix,
        },
    )

    # Target unhealthy
    aws.cloudwatch.MetricAlarm(
        f"{name}-target-unhealthy",
        # alarm_name parameter deprecated in provider v7
        comparison_operator="LessThanThreshold",
        evaluation_periods=2,
        metric_name="HealthyHostCount",
        namespace="AWS/ApplicationELB",
        period=60,
        statistic="Average",
        threshold=1,
        alarm_description="No healthy targets available",
        alarm_actions=alarm_actions,
        dimensions={
            "TargetGroup": target_group_arn_suffix,
            "LoadBalancer": alb_arn_suffix,
        },
    )

    # High response time
    aws.cloudwatch.MetricAlarm(
        f"{name}-response-time-high",
        # alarm_name parameter deprecated in provider v7
        comparison_operator="GreaterThanThreshold",
        evaluation_periods=2,
        metric_name="TargetResponseTime",
        namespace="AWS/ApplicationELB",
        period=300,
        statistic="Average",
        threshold=1.0,  # 1 second
        alarm_description="ALB response time above threshold",
        alarm_actions=alarm_actions,
        dimensions={
            "LoadBalancer": alb_arn_suffix,
        },
    )


def _create_ecs_alarms(
    name: str,
    cluster_name: pulumi.Output[str],
    service_name: pulumi.Output[str],
    index: int,
    alarm_actions: list[str],
):
    """Create CloudWatch alarms for ECS service."""
    resource_base = _build_ecs_alarm_resource_name(name, index)

    # High CPU utilization
    cpu_alarm_name = pulumi.Output.concat(name, "-", service_name, "-cpu-high")
    aws.cloudwatch.MetricAlarm(
        f"{resource_base}-cpu",
        comparison_operator="GreaterThanThreshold",
        evaluation_periods=2,
        metric_name="CPUUtilization",
        namespace="AWS/ECS",
        period=300,
        statistic="Average",
        threshold=80,
        alarm_description="ECS service CPU above threshold",
        alarm_actions=alarm_actions,
        dimensions={
            "ClusterName": cluster_name,
            "ServiceName": service_name,
        },
    )

    # High memory utilization
    memory_alarm_name = pulumi.Output.concat(name, "-", service_name, "-memory-high")
    aws.cloudwatch.MetricAlarm(
        f"{resource_base}-memory",
        comparison_operator="GreaterThanThreshold",
        evaluation_periods=2,
        metric_name="MemoryUtilization",
        namespace="AWS/ECS",
        period=300,
        statistic="Average",
        threshold=80,
        alarm_description="ECS service memory above threshold",
        alarm_actions=alarm_actions,
        dimensions={
            "ClusterName": cluster_name,
            "ServiceName": service_name,
        },
    )


def _build_ecs_alarm_resource_name(prefix: str, index: int) -> str:
    if index < 0:
        raise ValueError("index must be non-negative")
    safe_prefix = prefix.replace("/", "-")
    return f"{safe_prefix}-ecs-{index}"


def _create_dynamodb_alarms(
    name: str,
    table_name: pulumi.Output[str],
    index: int,
    alarm_actions: list[str],
):
    """Create CloudWatch alarms for DynamoDB table."""
    resource_base = f"{name}-dynamodb-{index}"

    # High read throttling
    aws.cloudwatch.MetricAlarm(
        f"{resource_base}-read-throttle",
        comparison_operator="GreaterThanThreshold",
        evaluation_periods=2,
        metric_name="ReadThrottledRequests",
        namespace="AWS/DynamoDB",
        period=300,
        statistic="Sum",
        threshold=10,
        alarm_description="DynamoDB read throttling detected",
        alarm_actions=alarm_actions,
        dimensions={
            "TableName": table_name,
        },
    )

    # High write throttling
    aws.cloudwatch.MetricAlarm(
        f"{resource_base}-write-throttle",
        comparison_operator="GreaterThanThreshold",
        evaluation_periods=2,
        metric_name="WriteThrottledRequests",
        namespace="AWS/DynamoDB",
        period=300,
        statistic="Sum",
        threshold=10,
        alarm_description="DynamoDB write throttling detected",
        alarm_actions=alarm_actions,
        dimensions={
            "TableName": table_name,
        },
    )

    # High system errors
    aws.cloudwatch.MetricAlarm(
        f"{resource_base}-system-errors",
        comparison_operator="GreaterThanThreshold",
        evaluation_periods=1,
        metric_name="SystemErrors",
        namespace="AWS/DynamoDB",
        period=300,
        statistic="Sum",
        threshold=1,
        alarm_description="DynamoDB system errors detected",
        alarm_actions=alarm_actions,
        dimensions={
            "TableName": table_name,
        },
    )

    # High user errors (client-side issues like validation errors)
    aws.cloudwatch.MetricAlarm(
        f"{resource_base}-user-errors",
        comparison_operator="GreaterThanThreshold",
        evaluation_periods=2,
        metric_name="UserErrors",
        namespace="AWS/DynamoDB",
        period=300,
        statistic="Sum",
        threshold=100,
        alarm_description="DynamoDB user errors above threshold",
        alarm_actions=alarm_actions,
        dimensions={
            "TableName": table_name,
        },
    )

    # High consumed read capacity (for capacity planning)
    aws.cloudwatch.MetricAlarm(
        f"{resource_base}-consumed-rcu",
        comparison_operator="GreaterThanThreshold",
        evaluation_periods=3,
        metric_name="ConsumedReadCapacityUnits",
        namespace="AWS/DynamoDB",
        period=300,
        statistic="Sum",
        threshold=100000,  # Alert if consuming >100K RCU in 5 minutes
        alarm_description="DynamoDB high read consumption",
        alarm_actions=alarm_actions,
        dimensions={
            "TableName": table_name,
        },
    )

    # High consumed write capacity (for capacity planning)
    aws.cloudwatch.MetricAlarm(
        f"{resource_base}-consumed-wcu",
        comparison_operator="GreaterThanThreshold",
        evaluation_periods=3,
        metric_name="ConsumedWriteCapacityUnits",
        namespace="AWS/DynamoDB",
        period=300,
        statistic="Sum",
        threshold=50000,  # Alert if consuming >50K WCU in 5 minutes
        alarm_description="DynamoDB high write consumption",
        alarm_actions=alarm_actions,
        dimensions={
            "TableName": table_name,
        },
    )


def _create_redis_alarms(
    name: str,
    cluster_id: pulumi.Output[str],
    alarm_actions: list[str],
):
    """Create CloudWatch alarms for Redis."""
    # High CPU
    aws.cloudwatch.MetricAlarm(
        f"{name}-redis-cpu-high",
        comparison_operator="GreaterThanThreshold",
        evaluation_periods=2,
        metric_name="CPUUtilization",
        namespace="AWS/ElastiCache",
        period=300,
        statistic="Average",
        threshold=75,
        alarm_description="Redis CPU above threshold",
        alarm_actions=alarm_actions,
        dimensions={
            "ReplicationGroupId": cluster_id,
        },
    )

    # High memory usage
    aws.cloudwatch.MetricAlarm(
        f"{name}-redis-memory-high",
        comparison_operator="GreaterThanThreshold",
        evaluation_periods=2,
        metric_name="DatabaseMemoryUsagePercentage",
        namespace="AWS/ElastiCache",
        period=300,
        statistic="Average",
        threshold=80,
        alarm_description="Redis memory usage above threshold",
        alarm_actions=alarm_actions,
        dimensions={
            "ReplicationGroupId": cluster_id,
        },
    )

    # High evictions
    aws.cloudwatch.MetricAlarm(
        f"{name}-redis-evictions-high",
        comparison_operator="GreaterThanThreshold",
        evaluation_periods=2,
        metric_name="Evictions",
        namespace="AWS/ElastiCache",
        period=300,
        statistic="Sum",
        threshold=1000,
        alarm_description="Redis evictions above threshold",
        alarm_actions=alarm_actions,
        dimensions={
            "ReplicationGroupId": cluster_id,
        },
    )


def _create_dashboard(
    name: str,
    alb_arn_suffix: pulumi.Output[str],
    target_group_arn_suffix: pulumi.Output[str],
    ecs_cluster_name: pulumi.Output[str],
    ecs_service_names: list[pulumi.Output[str]],
    dynamodb_table_names: list[pulumi.Output[str]],
    redis_cluster_id: pulumi.Output[str],
) -> aws.cloudwatch.Dashboard:
    """Create CloudWatch dashboard."""
    region = aws.get_region().name

    dashboard_body = {
        "widgets": [
            {
                "type": "metric",
                "x": 0,
                "y": 0,
                "width": 12,
                "height": 6,
                "properties": {
                    "metrics": [
                        ["AWS/ApplicationELB", "RequestCount", {"stat": "Sum"}],
                        [".", "TargetResponseTime", {"stat": "Average"}],
                        [".", "HTTPCode_Target_5XX_Count", {"stat": "Sum"}],
                        [".", "HTTPCode_Target_4XX_Count", {"stat": "Sum"}],
                    ],
                    "period": 300,
                    "stat": "Average",
                    "region": region,
                    "title": "ALB Metrics",
                },
            },
            {
                "type": "metric",
                "x": 12,
                "y": 0,
                "width": 12,
                "height": 6,
                "properties": {
                    "metrics": [
                        ["AWS/ECS", "CPUUtilization", {"stat": "Average"}],
                        [".", "MemoryUtilization", {"stat": "Average"}],
                    ],
                    "period": 300,
                    "stat": "Average",
                    "region": region,
                    "title": "ECS Metrics",
                },
            },
            {
                "type": "metric",
                "x": 0,
                "y": 6,
                "width": 12,
                "height": 6,
                "properties": {
                    "metrics": [
                        ["AWS/DynamoDB", "ConsumedReadCapacityUnits", {"stat": "Sum"}],
                        [".", "ConsumedWriteCapacityUnits", {"stat": "Sum"}],
                    ],
                    "period": 300,
                    "stat": "Sum",
                    "region": region,
                    "title": "DynamoDB Capacity Consumption",
                },
            },
            {
                "type": "metric",
                "x": 12,
                "y": 6,
                "width": 12,
                "height": 6,
                "properties": {
                    "metrics": [
                        ["AWS/DynamoDB", "ReadThrottledRequests", {"stat": "Sum"}],
                        [".", "WriteThrottledRequests", {"stat": "Sum"}],
                        [".", "SystemErrors", {"stat": "Sum"}],
                        [".", "UserErrors", {"stat": "Sum"}],
                    ],
                    "period": 300,
                    "stat": "Sum",
                    "region": region,
                    "title": "DynamoDB Errors & Throttling",
                },
            },
            {
                "type": "metric",
                "x": 0,
                "y": 12,
                "width": 12,
                "height": 6,
                "properties": {
                    "metrics": [
                        ["AWS/DynamoDB", "SuccessfulRequestLatency", {"stat": "Average"}],
                        [".", "SuccessfulRequestLatency", {"stat": "p99"}],
                    ],
                    "period": 300,
                    "stat": "Average",
                    "region": region,
                    "title": "DynamoDB Latency",
                },
            },
            {
                "type": "metric",
                "x": 12,
                "y": 12,
                "width": 12,
                "height": 6,
                "properties": {
                    "metrics": [
                        ["AWS/ElastiCache", "CPUUtilization", {"stat": "Average"}],
                        [".", "DatabaseMemoryUsagePercentage", {"stat": "Average"}],
                        [".", "Evictions", {"stat": "Sum"}],
                        [".", "CurrConnections", {"stat": "Average"}],
                    ],
                    "period": 300,
                    "stat": "Average",
                    "region": region,
                    "title": "Redis Metrics",
                },
            },
        ]
    }

    return aws.cloudwatch.Dashboard(
        f"{name}-dashboard",
        dashboard_name=f"{name}-dashboard",
        dashboard_body=json.dumps(dashboard_body),
    )