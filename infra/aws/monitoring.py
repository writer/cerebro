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
    log_retention_days: int = 30,
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
    dashboard = aws.cloudwatch.Dashboard(
        f"{name}-dashboard",
        dashboard_name=f"{name}-dashboard",
        dashboard_body=pulumi.Output.all(
            alb_arn_suffix, target_group_arn_suffix, ecs_cluster_name, ecs_service_name
        ).apply(lambda args: _dashboard_body(name, *args)),
    )

    return {
        "alarm_topic": alarm_topic,
        "dashboard": dashboard,
    }


def _dashboard_body(name: str, alb_arn: str, tg_arn: str, cluster: str, service: str) -> str:
    import json
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
        ],
    })
