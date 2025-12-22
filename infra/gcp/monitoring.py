"""
GCP Cloud Monitoring infrastructure.

Creates:
- Uptime checks
- Alert policies
- Notification channels
- Log-based metrics
- Custom dashboards
"""

import pulumi
import pulumi_gcp as gcp
import json


def create_monitoring(
    name: str,
    project: str,
    api_service_name: pulumi.Output[str],
    worker_service_name: pulumi.Output[str],
    db_instance_name: pulumi.Output[str],
    redis_instance_name: pulumi.Output[str],
    load_balancer_url: str,
    alert_email: str = None,
) -> dict:
    """
    Create monitoring infrastructure with alerts and dashboards.

    Args:
        name: Monitoring stack name prefix
        project: GCP project ID
        api_service_name: Cloud Run API service name
        worker_service_name: Cloud Run worker service name
        db_instance_name: Cloud SQL instance name
        redis_instance_name: Memorystore Redis instance name
        load_balancer_url: Load balancer URL for uptime checks
        alert_email: Email address for alert notifications

    Returns:
        Dictionary with monitoring resources
    """
    result = {}

    # Create notification channel for email
    if alert_email:
        notification_channel = gcp.monitoring.NotificationChannel(
            f"{name}-email-channel",
            display_name=f"{name} Email Alerts",
            project=project,
            type="email",
            labels={
                "email_address": alert_email,
            },
        )
        result["notification_channel"] = notification_channel

        notification_channels = [notification_channel.id]
    else:
        notification_channels = []

    # Create uptime check for API
    uptime_check = gcp.monitoring.UptimeCheckConfig(
        f"{name}-api-uptime",
        display_name=f"{name} API Uptime",
        project=project,
        timeout="10s",
        period="300s",  # 5 minutes
        http_check=gcp.monitoring.UptimeCheckConfigHttpCheckArgs(
            path="/health",
            port=443,
            use_ssl=True,
            validate_ssl=True,
        ),
        monitored_resource=gcp.monitoring.UptimeCheckConfigMonitoredResourceArgs(
            type="uptime_url",
            labels={
                "project_id": project,
                "host": load_balancer_url,
            },
        ),
    )
    result["uptime_check"] = uptime_check

    # Alert for uptime check failures
    if notification_channels:
        gcp.monitoring.AlertPolicy(
            f"{name}-uptime-alert",
            display_name=f"{name} API Down",
            project=project,
            combiner="OR",
            conditions=[
                gcp.monitoring.AlertPolicyConditionArgs(
                    display_name="Uptime check failed",
                    condition_threshold=gcp.monitoring.AlertPolicyConditionConditionThresholdArgs(
                        filter=uptime_check.uptime_check_id.apply(
                            lambda id: f'metric.type="monitoring.googleapis.com/uptime_check/check_passed" AND resource.type="uptime_url" AND metric.label.check_id="{id}"'
                        ),
                        comparison="COMPARISON_LT",
                        threshold_value=1.0,
                        duration="300s",
                        aggregations=[
                            gcp.monitoring.AlertPolicyConditionConditionThresholdAggregationArgs(
                                alignment_period="60s",
                                per_series_aligner="ALIGN_NEXT_OLDER",
                                cross_series_reducer="REDUCE_COUNT_FALSE",
                                group_by_fields=["resource.label.*"],
                            )
                        ],
                    ),
                )
            ],
            notification_channels=notification_channels,
            alert_strategy=gcp.monitoring.AlertPolicyAlertStrategyArgs(
                auto_close="1800s",  # 30 minutes
            ),
        )

    # Cloud Run API alerts
    _create_cloud_run_alerts(
        name=f"{name}-api",
        project=project,
        service_name=api_service_name,
        notification_channels=notification_channels,
    )

    # Cloud Run Worker alerts
    _create_cloud_run_alerts(
        name=f"{name}-worker",
        project=project,
        service_name=worker_service_name,
        notification_channels=notification_channels,
    )

    # Cloud SQL alerts
    _create_cloud_sql_alerts(
        name=name,
        project=project,
        instance_name=db_instance_name,
        notification_channels=notification_channels,
    )

    # Memorystore Redis alerts
    _create_redis_alerts(
        name=name,
        project=project,
        instance_name=redis_instance_name,
        notification_channels=notification_channels,
    )

    # Create custom dashboard
    dashboard = _create_dashboard(
        name=name,
        project=project,
    )
    result["dashboard"] = dashboard

    return result


def _create_cloud_run_alerts(
    name: str,
    project: str,
    service_name: pulumi.Output[str],
    notification_channels: list[pulumi.Output[str]],
):
    """Create Cloud Run monitoring alerts."""
    if not notification_channels:
        return

    # High error rate alert
    gcp.monitoring.AlertPolicy(
        f"{name}-error-rate",
        display_name=f"{name} High Error Rate",
        project=project,
        combiner="OR",
        conditions=[
            gcp.monitoring.AlertPolicyConditionArgs(
                display_name="5xx error rate > 5%",
                condition_threshold=gcp.monitoring.AlertPolicyConditionConditionThresholdArgs(
                    filter=service_name.apply(
                        lambda sn: f'metric.type="run.googleapis.com/request_count" AND resource.type="cloud_run_revision" AND resource.label.service_name="{sn}" AND metric.label.response_code_class="5xx"'
                    ),
                    comparison="COMPARISON_GT",
                    threshold_value=0.05,  # 5%
                    duration="300s",
                    aggregations=[
                        gcp.monitoring.AlertPolicyConditionConditionThresholdAggregationArgs(
                            alignment_period="60s",
                            per_series_aligner="ALIGN_RATE",
                        )
                    ],
                ),
            )
        ],
        notification_channels=notification_channels,
    )

    # High latency alert
    gcp.monitoring.AlertPolicy(
        f"{name}-latency",
        display_name=f"{name} High Latency",
        project=project,
        combiner="OR",
        conditions=[
            gcp.monitoring.AlertPolicyConditionArgs(
                display_name="P99 latency > 2s",
                condition_threshold=gcp.monitoring.AlertPolicyConditionConditionThresholdArgs(
                    filter=service_name.apply(
                        lambda sn: f'metric.type="run.googleapis.com/request_latencies" AND resource.type="cloud_run_revision" AND resource.label.service_name="{sn}"'
                    ),
                    comparison="COMPARISON_GT",
                    threshold_value=2000,  # 2 seconds in ms
                    duration="300s",
                    aggregations=[
                        gcp.monitoring.AlertPolicyConditionConditionThresholdAggregationArgs(
                            alignment_period="60s",
                            per_series_aligner="ALIGN_DELTA",
                            cross_series_reducer="REDUCE_PERCENTILE_99",
                        )
                    ],
                ),
            )
        ],
        notification_channels=notification_channels,
    )


def _create_cloud_sql_alerts(
    name: str,
    project: str,
    instance_name: pulumi.Output[str],
    notification_channels: list[pulumi.Output[str]],
):
    """Create Cloud SQL monitoring alerts."""
    if not notification_channels:
        return

    # High CPU alert
    gcp.monitoring.AlertPolicy(
        f"{name}-sql-cpu",
        display_name=f"{name} Cloud SQL High CPU",
        project=project,
        combiner="OR",
        conditions=[
            gcp.monitoring.AlertPolicyConditionArgs(
                display_name="CPU > 80%",
                condition_threshold=gcp.monitoring.AlertPolicyConditionConditionThresholdArgs(
                    filter=instance_name.apply(
                        lambda in_: f'metric.type="cloudsql.googleapis.com/database/cpu/utilization" AND resource.type="cloudsql_database" AND resource.label.database_id="{in_}"'
                    ),
                    comparison="COMPARISON_GT",
                    threshold_value=0.8,
                    duration="300s",
                    aggregations=[
                        gcp.monitoring.AlertPolicyConditionConditionThresholdAggregationArgs(
                            alignment_period="60s",
                            per_series_aligner="ALIGN_MEAN",
                        )
                    ],
                ),
            )
        ],
        notification_channels=notification_channels,
    )

    # Low storage alert
    gcp.monitoring.AlertPolicy(
        f"{name}-sql-storage",
        display_name=f"{name} Cloud SQL Low Storage",
        project=project,
        combiner="OR",
        conditions=[
            gcp.monitoring.AlertPolicyConditionArgs(
                display_name="Storage < 20%",
                condition_threshold=gcp.monitoring.AlertPolicyConditionConditionThresholdArgs(
                    filter=instance_name.apply(
                        lambda in_: f'metric.type="cloudsql.googleapis.com/database/disk/utilization" AND resource.type="cloudsql_database" AND resource.label.database_id="{in_}"'
                    ),
                    comparison="COMPARISON_GT",
                    threshold_value=0.8,  # > 80% used = < 20% free
                    duration="300s",
                    aggregations=[
                        gcp.monitoring.AlertPolicyConditionConditionThresholdAggregationArgs(
                            alignment_period="60s",
                            per_series_aligner="ALIGN_MEAN",
                        )
                    ],
                ),
            )
        ],
        notification_channels=notification_channels,
    )


def _create_redis_alerts(
    name: str,
    project: str,
    instance_name: pulumi.Output[str],
    notification_channels: list[pulumi.Output[str]],
):
    """Create Memorystore Redis monitoring alerts."""
    if not notification_channels:
        return

    # High memory usage alert
    gcp.monitoring.AlertPolicy(
        f"{name}-redis-memory",
        display_name=f"{name} Redis High Memory",
        project=project,
        combiner="OR",
        conditions=[
            gcp.monitoring.AlertPolicyConditionArgs(
                display_name="Memory > 80%",
                condition_threshold=gcp.monitoring.AlertPolicyConditionConditionThresholdArgs(
                    filter=instance_name.apply(
                        lambda in_: f'metric.type="redis.googleapis.com/stats/memory/usage_ratio" AND resource.type="redis_instance" AND resource.label.instance_id="{in_}"'
                    ),
                    comparison="COMPARISON_GT",
                    threshold_value=0.8,
                    duration="300s",
                    aggregations=[
                        gcp.monitoring.AlertPolicyConditionConditionThresholdAggregationArgs(
                            alignment_period="60s",
                            per_series_aligner="ALIGN_MEAN",
                        )
                    ],
                ),
            )
        ],
        notification_channels=notification_channels,
    )


def _create_dashboard(
    name: str,
    project: str,
) -> gcp.monitoring.Dashboard:
    """Create custom monitoring dashboard."""
    dashboard_json = {
        "displayName": f"{name} Dashboard",
        "mosaicLayout": {
            "columns": 12,
            "tiles": [
                {
                    "width": 6,
                    "height": 4,
                    "widget": {
                        "title": "Cloud Run Request Count",
                        "xyChart": {
                            "dataSets": [
                                {
                                    "timeSeriesQuery": {
                                        "timeSeriesFilter": {
                                            "filter": 'metric.type="run.googleapis.com/request_count" resource.type="cloud_run_revision"',
                                            "aggregation": {
                                                "alignmentPeriod": "60s",
                                                "perSeriesAligner": "ALIGN_RATE",
                                            },
                                        }
                                    }
                                }
                            ]
                        },
                    },
                },
                {
                    "width": 6,
                    "height": 4,
                    "widget": {
                        "title": "Cloud SQL CPU",
                        "xyChart": {
                            "dataSets": [
                                {
                                    "timeSeriesQuery": {
                                        "timeSeriesFilter": {
                                            "filter": 'metric.type="cloudsql.googleapis.com/database/cpu/utilization" resource.type="cloudsql_database"',
                                            "aggregation": {
                                                "alignmentPeriod": "60s",
                                                "perSeriesAligner": "ALIGN_MEAN",
                                            },
                                        }
                                    }
                                }
                            ]
                        },
                    },
                },
            ],
        },
    }

    return gcp.monitoring.Dashboard(
        f"{name}-dashboard",
        dashboard_json=json.dumps(dashboard_json),
        project=project,
    )
