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
    db_instance_id: pulumi.Output[str],
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
        db_instance_id: RDS instance ID
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
    for service_name in ecs_service_names:
        _create_ecs_alarms(
            name=name,
            cluster_name=ecs_cluster_name,
            service_name=service_name,
            alarm_actions=[alarm_topic.arn] if alarm_email else [],
        )

    # RDS Alarms
    _create_rds_alarms(
        name=name,
        db_instance_id=db_instance_id,
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
        db_instance_id=db_instance_id,
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
    alarm_actions: list[str],
):
    """Create CloudWatch alarms for ECS service."""
    # High CPU utilization
    aws.cloudwatch.MetricAlarm(
        pulumi.Output.concat(name, "-", service_name, "-cpu-high"),
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
    aws.cloudwatch.MetricAlarm(
        pulumi.Output.concat(name, "-", service_name, "-memory-high"),
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


def _create_rds_alarms(
    name: str,
    db_instance_id: pulumi.Output[str],
    alarm_actions: list[str],
):
    """Create CloudWatch alarms for RDS."""
    # High CPU
    aws.cloudwatch.MetricAlarm(
        f"{name}-rds-cpu-high",
        comparison_operator="GreaterThanThreshold",
        evaluation_periods=2,
        metric_name="CPUUtilization",
        namespace="AWS/RDS",
        period=300,
        statistic="Average",
        threshold=80,
        alarm_description="RDS CPU above threshold",
        alarm_actions=alarm_actions,
        dimensions={
            "DBInstanceIdentifier": db_instance_id,
        },
    )

    # Low storage space
    aws.cloudwatch.MetricAlarm(
        f"{name}-rds-storage-low",
        comparison_operator="LessThanThreshold",
        evaluation_periods=1,
        metric_name="FreeStorageSpace",
        namespace="AWS/RDS",
        period=300,
        statistic="Average",
        threshold=10 * 1024 * 1024 * 1024,  # 10 GB
        alarm_description="RDS storage space below threshold",
        alarm_actions=alarm_actions,
        dimensions={
            "DBInstanceIdentifier": db_instance_id,
        },
    )

    # High connection count
    aws.cloudwatch.MetricAlarm(
        f"{name}-rds-connections-high",
        comparison_operator="GreaterThanThreshold",
        evaluation_periods=2,
        metric_name="DatabaseConnections",
        namespace="AWS/RDS",
        period=300,
        statistic="Average",
        threshold=400,  # 80% of max_connections=500
        alarm_description="RDS connections above threshold",
        alarm_actions=alarm_actions,
        dimensions={
            "DBInstanceIdentifier": db_instance_id,
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
    db_instance_id: pulumi.Output[str],
    redis_cluster_id: pulumi.Output[str],
) -> aws.cloudwatch.Dashboard:
    """Create CloudWatch dashboard."""
    # Note: Dashboard body is static JSON for simplicity
    # In production, you'd dynamically generate this
    dashboard_body = {
        "widgets": [
            {
                "type": "metric",
                "properties": {
                    "metrics": [
                        ["AWS/ApplicationELB", "RequestCount", {"stat": "Sum"}],
                        [".", "TargetResponseTime", {"stat": "Average"}],
                    ],
                    "period": 300,
                    "stat": "Average",
                    "region": aws.get_region().name,
                    "title": "ALB Metrics",
                },
            },
            {
                "type": "metric",
                "properties": {
                    "metrics": [
                        ["AWS/ECS", "CPUUtilization", {"stat": "Average"}],
                        [".", "MemoryUtilization", {"stat": "Average"}],
                    ],
                    "period": 300,
                    "stat": "Average",
                    "region": aws.get_region().name,
                    "title": "ECS Metrics",
                },
            },
            {
                "type": "metric",
                "properties": {
                    "metrics": [
                        ["AWS/RDS", "CPUUtilization", {"stat": "Average"}],
                        [".", "DatabaseConnections", {"stat": "Average"}],
                        [".", "FreeStorageSpace", {"stat": "Average"}],
                    ],
                    "period": 300,
                    "stat": "Average",
                    "region": aws.get_region().name,
                    "title": "RDS Metrics",
                },
            },
            {
                "type": "metric",
                "properties": {
                    "metrics": [
                        ["AWS/ElastiCache", "CPUUtilization", {"stat": "Average"}],
                        [
                            ".",
                            "DatabaseMemoryUsagePercentage",
                            {"stat": "Average"},
                        ],
                        [".", "Evictions", {"stat": "Sum"}],
                    ],
                    "period": 300,
                    "stat": "Average",
                    "region": aws.get_region().name,
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