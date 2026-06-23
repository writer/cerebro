"""Neo4j Aura metadata probe and CloudWatch metrics."""

from __future__ import annotations

import json

import pulumi
import pulumi_aws as aws


def create_aura_probe(
    name: str,
    client_id: pulumi.Input[str],
    client_secret: pulumi.Input[str],
    instance_id: pulumi.Input[str],
    namespace: str,
    alarm_actions: list[pulumi.Input[str]] | None = None,
    schedule_expression: str = "rate(5 minutes)",
) -> dict:
    role = aws.iam.Role(
        f"{name}-neo4j-aura-probe-role",
        name=f"{name}-neo4j-aura-probe",
        assume_role_policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Action": "sts:AssumeRole",
                        "Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                    }
                ],
            }
        ),
        tags={"Name": f"{name}-neo4j-aura-probe-role"},
    )
    aws.iam.RolePolicy(
        f"{name}-neo4j-aura-probe-policy",
        role=role.id,
        policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:PutLogEvents",
                        ],
                        "Resource": "arn:aws:logs:*:*:*",
                    },
                    {
                        "Effect": "Allow",
                        "Action": ["cloudwatch:PutMetricData"],
                        "Resource": "*",
                        "Condition": {"StringEquals": {"cloudwatch:namespace": namespace}},
                    },
                ],
            }
        ),
    )
    function = aws.lambda_.Function(
        f"{name}-neo4j-aura-probe",
        name=f"{name}-neo4j-aura-probe",
        role=role.arn,
        runtime="python3.12",
        handler="index.handler",
        timeout=30,
        memory_size=128,
        code=pulumi.AssetArchive({"index.py": pulumi.StringAsset(_aura_probe_code())}),
        environment=aws.lambda_.FunctionEnvironmentArgs(
            variables={
                "AURA_CLIENT_ID": client_id,
                "AURA_CLIENT_SECRET": client_secret,
                "AURA_INSTANCE_ID": instance_id,
                "METRIC_NAMESPACE": namespace,
            }
        ),
        tags={"Name": f"{name}-neo4j-aura-probe"},
    )
    rule = aws.cloudwatch.EventRule(
        f"{name}-neo4j-aura-probe-schedule",
        name=f"{name}-neo4j-aura-probe",
        schedule_expression=schedule_expression,
        tags={"Name": f"{name}-neo4j-aura-probe-schedule"},
    )
    aws.cloudwatch.EventTarget(
        f"{name}-neo4j-aura-probe-target",
        rule=rule.name,
        arn=function.arn,
        target_id="neo4j-aura-probe",
    )
    aws.lambda_.Permission(
        f"{name}-neo4j-aura-probe-permission",
        action="lambda:InvokeFunction",
        function=function.name,
        principal="events.amazonaws.com",
        source_arn=rule.arn,
    )
    aws.cloudwatch.MetricAlarm(
        f"{name}-neo4j-aura-probe-failures-alarm",
        name=f"{name}-neo4j-aura-probe-failures",
        comparison_operator="GreaterThanThreshold",
        evaluation_periods=1,
        metric_name="Neo4jAuraProbeFailures",
        namespace=namespace,
        period=300,
        statistic="Sum",
        threshold=0,
        treat_missing_data="notBreaching",
        alarm_description="Neo4j Aura metadata probe failures detected.",
        alarm_actions=alarm_actions or [],
        dimensions={"InstanceId": instance_id},
        tags={"Name": f"{name}-neo4j-aura-probe-failures-alarm"},
    )
    aws.cloudwatch.MetricAlarm(
        f"{name}-neo4j-aura-instance-down-alarm",
        name=f"{name}-neo4j-aura-instance-down",
        comparison_operator="LessThanThreshold",
        evaluation_periods=2,
        metric_name="Neo4jAuraInstanceUp",
        namespace=namespace,
        period=300,
        statistic="Minimum",
        threshold=1,
        treat_missing_data="breaching",
        alarm_description="Neo4j Aura instance is not reporting a running status.",
        alarm_actions=alarm_actions or [],
        dimensions={"InstanceId": instance_id},
        tags={"Name": f"{name}-neo4j-aura-instance-down-alarm"},
    )
    return {"function": function, "schedule": rule}


def _aura_probe_code() -> str:
    return r'''
import base64
import json
import os
import urllib.parse
import urllib.request

import boto3


def handler(_event, _context):
    namespace = os.environ["METRIC_NAMESPACE"]
    instance_id = os.environ["AURA_INSTANCE_ID"]
    dimensions = [{"Name": "InstanceId", "Value": instance_id}]
    cloudwatch = boto3.client("cloudwatch")
    try:
        token = aura_token(os.environ["AURA_CLIENT_ID"], os.environ["AURA_CLIENT_SECRET"])
        instance = aura_instance(token, instance_id)
        data = instance.get("data") or {}
        status = str(data.get("status") or "").lower()
        metrics = [
            metric("Neo4jAuraInstanceUp", 1 if status == "running" else 0, "Count", dimensions),
            metric("Neo4jAuraProbeFailures", 0, "Count", dimensions),
        ]
        memory_gb = parse_gb(data.get("memory"))
        if memory_gb is not None:
            metrics.append(metric("Neo4jAuraMemoryGB", memory_gb, "Gigabytes", dimensions))
        storage_gb = parse_gb(first_present(data, "storage", "storage_size", "allocated_storage", "disk_size"))
        if storage_gb is not None:
            metrics.append(metric("Neo4jAuraStorageGB", storage_gb, "Gigabytes", dimensions))
        cloudwatch.put_metric_data(Namespace=namespace, MetricData=metrics)
        return {"status": status, "instance_id": instance_id}
    except Exception:
        cloudwatch.put_metric_data(
            Namespace=namespace,
            MetricData=[metric("Neo4jAuraProbeFailures", 1, "Count", dimensions)],
        )
        raise


def aura_token(client_id, client_secret):
    request = urllib.request.Request(
        "https://api.neo4j.io/oauth/token",
        data=urllib.parse.urlencode({"grant_type": "client_credentials"}).encode(),
        method="POST",
    )
    basic = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    request.add_header("Authorization", f"Basic {basic}")
    request.add_header("Content-Type", "application/x-www-form-urlencoded")
    request.add_header("User-Agent", "CerebroAuraProbe/1")
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.loads(response.read().decode())["access_token"]


def aura_instance(token, instance_id):
    request = urllib.request.Request(f"https://api.neo4j.io/v1/instances/{instance_id}", method="GET")
    request.add_header("Authorization", f"Bearer {token}")
    request.add_header("User-Agent", "CerebroAuraProbe/1")
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.loads(response.read().decode())


def first_present(values, *keys):
    for key in keys:
        value = values.get(key)
        if value not in (None, ""):
            return value
    return None


def parse_gb(value):
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip().lower().replace(" ", "")
    multiplier = 1.0
    if text.endswith("tb"):
        multiplier = 1024.0
        text = text[:-2]
    elif text.endswith("gb"):
        text = text[:-2]
    elif text.endswith("g"):
        text = text[:-1]
    try:
        return float(text) * multiplier
    except ValueError:
        return None


def metric(name, value, unit, dimensions):
    return {"MetricName": name, "Value": value, "Unit": unit, "Dimensions": dimensions}
'''.lstrip()
