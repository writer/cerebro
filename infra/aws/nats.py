"""
NATS JetStream runtime for the Cerebro append log.
"""

import json

import pulumi
import pulumi_aws as aws

import storage


def create_nats_service(
    name: str,
    vpc_id: pulumi.Input[str],
    subnet_ids: list[pulumi.Input[str]],
    app_security_group_id: pulumi.Input[str],
    kms_key_arn: pulumi.Input[str],
    log_group_kms_key_id: pulumi.Input[str] = None,
    log_retention_days: int = 30,
    cpu: int = 512,
    memory: int = 1024,
    stream_name: str = "CEREBRO_EVENTS",
    subject_prefix: str = "events",
    stream_max_bytes: str = "",
    stream_max_age: str = "",
    enable_lag_probe: bool = True,
    lag_probe_interval_seconds: int = 60,
    lag_probe_image: str = "python:3.12-alpine",
) -> dict:
    """Run a private NATS JetStream service backed by EFS."""
    namespace = aws.servicediscovery.PrivateDnsNamespace(
        f"{name}-nats-namespace",
        name=f"{name}.local",
        vpc=vpc_id,
        description=f"Private service discovery for {name}",
    )

    cloudmap_service = aws.servicediscovery.Service(
        f"{name}-nats-discovery",
        name="nats",
        dns_config=aws.servicediscovery.ServiceDnsConfigArgs(
            namespace_id=namespace.id,
            dns_records=[aws.servicediscovery.ServiceDnsConfigDnsRecordArgs(type="A", ttl=10)],
            routing_policy="MULTIVALUE",
        ),
        health_check_custom_config=aws.servicediscovery.ServiceHealthCheckCustomConfigArgs(failure_threshold=1),
    )

    security_group = aws.ec2.SecurityGroup(
        f"{name}-nats-sg",
        vpc_id=vpc_id,
        description=f"NATS JetStream access for {name}",
        ingress=[
            aws.ec2.SecurityGroupIngressArgs(
                protocol="tcp",
                from_port=4222,
                to_port=4222,
                security_groups=[app_security_group_id],
            ),
            aws.ec2.SecurityGroupIngressArgs(
                protocol="tcp",
                from_port=8222,
                to_port=8222,
                security_groups=[app_security_group_id],
            ),
        ],
        egress=[
            aws.ec2.SecurityGroupEgressArgs(
                protocol="-1",
                from_port=0,
                to_port=0,
                cidr_blocks=["0.0.0.0/0"],
            )
        ],
        tags={"Name": f"{name}-nats-sg"},
    )

    efs = storage.create_efs_volume(
        name=f"{name}-nats",
        vpc_id=vpc_id,
        subnet_ids=subnet_ids,
        client_security_group_id=security_group.id,
        kms_key_arn=kms_key_arn,
        access_point_path="/nats",
    )

    cluster = aws.ecs.Cluster(
        f"{name}-nats-cluster",
        name=f"{name}-nats-cluster",
        settings=[aws.ecs.ClusterSettingArgs(name="containerInsights", value="enabled")],
        tags={"Name": f"{name}-nats-cluster"},
    )

    execution_role = _execution_role(name)
    task_role = _task_role(name, efs["file_system"].arn)

    log_group = aws.cloudwatch.LogGroup(
        f"{name}-nats-logs",
        name=f"/ecs/{name}/nats",
        retention_in_days=log_retention_days,
        kms_key_id=log_group_kms_key_id,
        tags={"Name": f"{name}-nats-logs"},
    )

    region = aws.get_region().region

    container_definitions = log_group.name.apply(
        lambda log_group_name: _build_container_definitions(
            name=name,
            log_group_name=log_group_name,
            region=region,
            stream_name=stream_name,
            subject_prefix=subject_prefix,
            stream_max_bytes=stream_max_bytes,
            stream_max_age=stream_max_age,
            lag_probe_image=lag_probe_image,
            lag_probe_interval_seconds=lag_probe_interval_seconds,
            enable_lag_probe=enable_lag_probe,
        )
    )

    task_definition = aws.ecs.TaskDefinition(
        f"{name}-nats-task",
        family=f"{name}-nats",
        cpu=str(cpu),
        memory=str(memory),
        network_mode="awsvpc",
        requires_compatibilities=["FARGATE"],
        runtime_platform=aws.ecs.TaskDefinitionRuntimePlatformArgs(
            operating_system_family="LINUX",
            cpu_architecture="ARM64",
        ),
        execution_role_arn=execution_role.arn,
        task_role_arn=task_role.arn,
        container_definitions=container_definitions,
        volumes=[aws.ecs.TaskDefinitionVolumeArgs(
            name="nats-data",
            efs_volume_configuration=aws.ecs.TaskDefinitionVolumeEfsVolumeConfigurationArgs(
                file_system_id=efs["file_system"].id,
                transit_encryption="ENABLED",
                authorization_config=aws.ecs.TaskDefinitionVolumeEfsVolumeConfigurationAuthorizationConfigArgs(
                    access_point_id=efs["access_point"].id,
                    iam="ENABLED",
                ),
            ),
        )],
        tags={"Name": f"{name}-nats-task"},
    )

    service = aws.ecs.Service(
        f"{name}-nats-service",
        name=f"{name}-nats",
        cluster=cluster.id,
        task_definition=task_definition.arn,
        desired_count=1,
        launch_type="FARGATE",
        network_configuration=aws.ecs.ServiceNetworkConfigurationArgs(
            subnets=subnet_ids,
            security_groups=[security_group.id],
            assign_public_ip=False,
        ),
        service_registries=aws.ecs.ServiceServiceRegistriesArgs(registry_arn=cloudmap_service.arn),
        availability_zone_rebalancing="DISABLED",
        deployment_maximum_percent=100,
        deployment_minimum_healthy_percent=0,
        deployment_circuit_breaker=aws.ecs.ServiceDeploymentCircuitBreakerArgs(enable=True, rollback=True),
        tags={"Name": f"{name}-nats-service"},
        opts=pulumi.ResourceOptions(depends_on=efs["mount_targets"]),
    )

    dns_name = pulumi.Output.concat("nats.", namespace.name)
    return {
        "cluster": cluster,
        "service": service,
        "task_definition": task_definition,
        "security_group": security_group,
        "log_group": log_group,
        "efs": efs,
        "dns_name": dns_name,
        "url": pulumi.Output.concat("nats://", dns_name, ":4222"),
        "stream_name": stream_name,
        "lag_probe_enabled": enable_lag_probe,
    }


def _build_container_definitions(
    name: str,
    log_group_name: str,
    region: str,
    stream_name: str,
    subject_prefix: str,
    stream_max_bytes: str,
    stream_max_age: str,
    lag_probe_image: str,
    lag_probe_interval_seconds: int,
    enable_lag_probe: bool,
) -> str:
    log_options = {
        "awslogs-group": log_group_name,
        "awslogs-region": region,
    }
    containers = [
        {
            "name": "nats",
            "image": "nats:2.10-alpine",
            "essential": True,
            "user": "10001",
            "readonlyRootFilesystem": True,
            "command": ["-js", "-sd", "/data", "-m", "8222"],
            "portMappings": [
                {"containerPort": 4222, "protocol": "tcp"},
                {"containerPort": 8222, "protocol": "tcp"},
            ],
            "mountPoints": [{"sourceVolume": "nats-data", "containerPath": "/data", "readOnly": False}],
            "healthCheck": {
                "command": ["CMD-SHELL", "wget -qO- 'http://127.0.0.1:8222/healthz?js-enabled-only=true' >/dev/null || exit 1"],
                "interval": 60,
                "timeout": 5,
                "retries": 10,
                "startPeriod": 300,
            },
            "logConfiguration": {
                "logDriver": "awslogs",
                "options": {**log_options, "awslogs-stream-prefix": "nats"},
            },
        },
        {
            "name": "jetstream-bootstrap",
            "image": "natsio/nats-box:0.16.0",
            "essential": False,
            "user": "10001",
            "dependsOn": [{"containerName": "nats", "condition": "HEALTHY"}],
            "environment": [
                {"name": "NATS_URL", "value": "nats://127.0.0.1:4222"},
                {"name": "NATS_TIMEOUT", "value": "120s"},
                {"name": "STREAM_NAME", "value": stream_name},
                {"name": "SUBJECT_PREFIX", "value": subject_prefix},
                {"name": "STREAM_MAX_BYTES", "value": str(stream_max_bytes or "")},
                {"name": "STREAM_MAX_AGE", "value": str(stream_max_age or "")},
            ],
            "command": [
                "sh",
                "-ec",
                (
                    'nats_js() { nats --server "$NATS_URL" --timeout "$NATS_TIMEOUT" "$@"; }; '
                    'set -- --subjects "${SUBJECT_PREFIX}.>" --discard old --replicas 1; '
                    'if [ -n "$STREAM_MAX_BYTES" ]; then set -- "$@" --max-bytes "$STREAM_MAX_BYTES"; fi; '
                    'if [ -n "$STREAM_MAX_AGE" ]; then set -- "$@" --max-age "$STREAM_MAX_AGE"; fi; '
                    'if nats_js stream info "$STREAM_NAME" >/dev/null 2>&1; then '
                    'nats_js stream edit "$STREAM_NAME" "$@" --force; '
                    'else nats_js stream add "$STREAM_NAME" "$@" '
                    '--storage file --retention limits --defaults || '
                    'nats_js stream edit "$STREAM_NAME" "$@" --force; fi'
                ),
            ],
            "logConfiguration": {
                "logDriver": "awslogs",
                "options": {**log_options, "awslogs-stream-prefix": "jetstream-bootstrap"},
            },
        },
        {
            "name": "jetstream-lag-probe",
            "image": lag_probe_image,
            "essential": False,
            "user": "10001",
            "readonlyRootFilesystem": True,
            "dependsOn": [{"containerName": "nats", "condition": "HEALTHY"}],
            "environment": [
                {"name": "NATS_MONITOR_URL", "value": "http://127.0.0.1:8222"},
                {"name": "SERVICE_NAME", "value": name},
                {"name": "STREAM_NAME", "value": stream_name},
                {"name": "PROBE_INTERVAL_SECONDS", "value": str(max(15, int(lag_probe_interval_seconds or 60)))},
                {"name": "METRIC_NAMESPACE", "value": f"Cerebro/{name}"},
            ],
            "command": ["python", "-u", "-c", _lag_probe_script()],
            "logConfiguration": {
                "logDriver": "awslogs",
                "options": {**log_options, "awslogs-stream-prefix": "jetstream-lag-probe"},
            },
        } if enable_lag_probe else None,
    ]
    return json.dumps([container for container in containers if container is not None])


def _execution_role(name: str) -> aws.iam.Role:
    role = aws.iam.Role(
        f"{name}-nats-exec-role",
        name=f"{name}-nats-exec-role",
        assume_role_policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        }),
        tags={"Name": f"{name}-nats-exec-role"},
    )
    aws.iam.RolePolicyAttachment(
        f"{name}-nats-exec-policy",
        role=role.name,
        policy_arn="arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy",
    )
    return role


def _lag_probe_script() -> str:
    return r"""
import json
import os
import time
import urllib.request

monitor_url = os.environ.get("NATS_MONITOR_URL", "http://127.0.0.1:8222").rstrip("/")
service_name = os.environ["SERVICE_NAME"]
stream_name = os.environ["STREAM_NAME"]
namespace = os.environ["METRIC_NAMESPACE"]
interval = int(os.environ.get("PROBE_INTERVAL_SECONDS", "60"))

def as_int(value):
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0

def emit(metric_name, value, dimensions, unit="Count"):
    payload = {
        "_aws": {
            "Timestamp": int(time.time() * 1000),
            "CloudWatchMetrics": [{
                "Namespace": namespace,
                "Dimensions": [
                    ["Service", "Stream"],
                    ["Service", "Stream", "Consumer"],
                ] if "Consumer" in dimensions else [["Service", "Stream"]],
                "Metrics": [{"Name": metric_name, "Unit": unit}],
            }],
        },
        metric_name: value,
        **dimensions,
    }
    print(json.dumps(payload), flush=True)

def stream_details(jsz):
    for account in jsz.get("account_details") or []:
        for stream in account.get("stream_detail") or []:
            if stream.get("name") == stream_name:
                yield stream
    for stream in jsz.get("stream_detail") or []:
        if stream.get("name") == stream_name:
            yield stream

while True:
    try:
        with urllib.request.urlopen(f"{monitor_url}/jsz?streams=true&consumers=true", timeout=10) as response:
            jsz = json.loads(response.read().decode("utf-8"))
        found_consumer = False
        for stream in stream_details(jsz):
            state = stream.get("state") or {}
            emit("JetStreamStreamMessages", as_int(state.get("messages")), {"Service": service_name, "Stream": stream_name})
            emit("JetStreamStreamBytes", as_int(state.get("bytes")), {"Service": service_name, "Stream": stream_name}, "Bytes")
            last_seq = as_int(state.get("last_seq"))
            for consumer in stream.get("consumer_detail") or []:
                found_consumer = True
                consumer_name = consumer.get("name") or consumer.get("stream_name") or "unknown"
                ack_floor = consumer.get("ack_floor") or {}
                lag = max(as_int(consumer.get("num_pending")), last_seq - as_int(ack_floor.get("stream_seq")))
                emit(
                    "JetStreamConsumerLag",
                    max(0, lag),
                    {"Service": service_name, "Stream": stream_name, "Consumer": consumer_name},
                )
        if not found_consumer:
            emit("JetStreamConsumerLag", 0, {"Service": service_name, "Stream": stream_name, "Consumer": "_none"})
    except Exception as exc:
        print(json.dumps({"level": "warning", "message": "jetstream lag probe failed", "error": str(exc)}), flush=True)
    time.sleep(interval)
"""


def _task_role(name: str, file_system_arn: pulumi.Input[str]) -> aws.iam.Role:
    role = aws.iam.Role(
        f"{name}-nats-task-role",
        name=f"{name}-nats-task-role",
        assume_role_policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        }),
        tags={"Name": f"{name}-nats-task-role"},
    )
    aws.iam.RolePolicy(
        f"{name}-nats-efs-policy",
        role=role.name,
        policy=pulumi.Output.all(file_system_arn).apply(lambda args: json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["elasticfilesystem:ClientMount", "elasticfilesystem:ClientWrite"],
                "Resource": args[0],
            }],
        })),
    )
    return role
