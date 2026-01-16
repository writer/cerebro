"""
AWS infrastructure for distributed job queue (SQS + DynamoDB).
"""

import json

import pulumi
import pulumi_aws as aws


def create_job_queue(
    name: str,
    kms_key_arn: pulumi.Output[str],
    visibility_timeout: int = 60,
    message_retention: int = 1209600,  # 14 days
    dlq_max_receive_count: int = 3,
) -> dict:
    """
    Create SQS queue with dead-letter queue for job processing.
    """
    # Dead-letter queue for failed jobs
    dlq = aws.sqs.Queue(
        f"{name}-dlq",
        name=f"{name}-jobs-dlq",
        message_retention_seconds=message_retention,
        kms_master_key_id=kms_key_arn,
        tags={"Name": f"{name}-jobs-dlq"},
    )

    # Main job queue
    queue = aws.sqs.Queue(
        f"{name}-queue",
        name=f"{name}-jobs",
        visibility_timeout_seconds=visibility_timeout,
        message_retention_seconds=message_retention,
        receive_wait_time_seconds=20,  # Long polling
        kms_master_key_id=kms_key_arn,
        redrive_policy=dlq.arn.apply(
            lambda arn: json.dumps({
                "deadLetterTargetArn": arn,
                "maxReceiveCount": dlq_max_receive_count,
            })
        ),
        tags={"Name": f"{name}-jobs"},
    )

    return {
        "queue": queue,
        "queue_url": queue.url,
        "queue_arn": queue.arn,
        "dlq": dlq,
        "dlq_url": dlq.url,
        "dlq_arn": dlq.arn,
    }


def create_job_store(
    name: str,
    kms_key_arn: pulumi.Output[str],
    ttl_days: int = 30,
) -> dict:
    """
    Create DynamoDB table for job state tracking.
    """
    table = aws.dynamodb.Table(
        f"{name}-jobs-table",
        name=f"{name}-jobs",
        billing_mode="PAY_PER_REQUEST",
        hash_key="job_id",
        attributes=[
            aws.dynamodb.TableAttributeArgs(name="job_id", type="S"),
            aws.dynamodb.TableAttributeArgs(name="group_id", type="S"),
            aws.dynamodb.TableAttributeArgs(name="status", type="S"),
        ],
        global_secondary_indexes=[
            aws.dynamodb.TableGlobalSecondaryIndexArgs(
                name="group-status-index",
                hash_key="group_id",
                range_key="status",
                projection_type="ALL",
            ),
            aws.dynamodb.TableGlobalSecondaryIndexArgs(
                name="status-index",
                hash_key="status",
                projection_type="KEYS_ONLY",
            ),
        ],
        ttl=aws.dynamodb.TableTtlArgs(
            attribute_name="expires_at",
            enabled=True,
        ),
        server_side_encryption=aws.dynamodb.TableServerSideEncryptionArgs(
            enabled=True,
            kms_key_arn=kms_key_arn,
        ),
        point_in_time_recovery=aws.dynamodb.TablePointInTimeRecoveryArgs(
            enabled=True,
        ),
        tags={"Name": f"{name}-jobs"},
    )

    return {
        "table": table,
        "table_name": table.name,
        "table_arn": table.arn,
    }


def create_worker_service(
    name: str,
    cluster_arn: pulumi.Output[str],
    subnet_ids: list[pulumi.Output[str]],
    security_group_id: pulumi.Output[str],
    container_image: str,
    queue_url: pulumi.Output[str],
    table_name: pulumi.Output[str],
    secrets_arn: pulumi.Output[str],
    kms_key_id: pulumi.Output[str],
    log_group_name: pulumi.Output[str],
    queue_arn: pulumi.Output[str],
    table_arn: pulumi.Output[str],
    worker_cpu: int = 512,
    worker_memory: int = 1024,
    worker_min_instances: int = 1,
    worker_max_instances: int = 10,
    worker_concurrency: int = 4,
    environment: dict = None,
    secret_keys: list[str] = None,
    external_secrets_prefix: str = None,
) -> dict:
    """
    Create ECS Fargate service for job workers.
    """
    region_obj = aws.get_region()
    region = region_obj.name
    caller = aws.get_caller_identity()

    # Worker execution role
    execution_role = aws.iam.Role(
        f"{name}-worker-exec-role",
        assume_role_policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        }),
        tags={"Name": f"{name}-worker-exec-role"},
    )

    aws.iam.RolePolicyAttachment(
        f"{name}-worker-exec-policy",
        role=execution_role.name,
        policy_arn="arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy",
    )

    if external_secrets_prefix:
        secrets_resource = f"arn:aws:secretsmanager:{region}:{caller.account_id}:secret:{external_secrets_prefix}/*"
    else:
        secrets_resource = secrets_arn

    aws.iam.RolePolicy(
        f"{name}-worker-exec-secrets",
        role=execution_role.name,
        policy=pulumi.Output.all(secrets_resource, kms_key_id).apply(
            lambda args: json.dumps({
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["secretsmanager:GetSecretValue"],
                        "Resource": args[0] if isinstance(args[0], str) else f"{args[0]}*",
                    },
                    {
                        "Effect": "Allow",
                        "Action": ["kms:Decrypt"],
                        "Resource": f"arn:aws:kms:*:*:key/{args[1]}",
                    },
                ],
            })
        ),
    )

    # Worker task role with SQS + DynamoDB permissions
    task_role = aws.iam.Role(
        f"{name}-worker-task-role",
        assume_role_policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        }),
        tags={"Name": f"{name}-worker-task-role"},
    )

    # SQS permissions
    aws.iam.RolePolicy(
        f"{name}-worker-sqs",
        role=task_role.name,
        policy=queue_arn.apply(
            lambda arn: json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": [
                        "sqs:ReceiveMessage",
                        "sqs:DeleteMessage",
                        "sqs:GetQueueAttributes",
                        "sqs:ChangeMessageVisibility",
                    ],
                    "Resource": arn,
                }],
            })
        ),
    )

    # DynamoDB permissions
    aws.iam.RolePolicy(
        f"{name}-worker-dynamodb",
        role=task_role.name,
        policy=table_arn.apply(
            lambda arn: json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": [
                        "dynamodb:GetItem",
                        "dynamodb:PutItem",
                        "dynamodb:UpdateItem",
                        "dynamodb:Query",
                    ],
                    "Resource": [arn, f"{arn}/index/*"],
                }],
            })
        ),
    )

    # CloudWatch permissions
    aws.iam.RolePolicy(
        f"{name}-worker-cloudwatch",
        role=task_role.name,
        policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["cloudwatch:PutMetricData"],
                "Resource": "*",
            }],
        }),
    )

    # AWS inspection permissions (read-only for S3, IAM, Lambda, ECS, etc.)
    aws.iam.RolePolicy(
        f"{name}-worker-inspect",
        role=task_role.name,
        policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetBucket*",
                        "s3:GetObject*",
                        "s3:ListBucket",
                        "s3:GetPublicAccessBlock",
                        "s3:GetEncryptionConfiguration",
                    ],
                    "Resource": "*",
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "iam:GetRole",
                        "iam:GetPolicy",
                        "iam:GetPolicyVersion",
                        "iam:ListRolePolicies",
                        "iam:ListAttachedRolePolicies",
                        "iam:GetRolePolicy",
                    ],
                    "Resource": "*",
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "lambda:GetFunction",
                        "lambda:GetFunctionConfiguration",
                        "lambda:GetPolicy",
                    ],
                    "Resource": "*",
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "ecs:DescribeClusters",
                        "ecs:DescribeServices",
                        "ecs:DescribeTaskDefinition",
                    ],
                    "Resource": "*",
                },
            ],
        }),
    )

    # Worker environment
    worker_env = {
        **(environment or {}),
        "JOB_WORKER_CONCURRENCY": str(worker_concurrency),
        "JOB_VISIBILITY_TIMEOUT": "60s",
        "JOB_POLL_WAIT": "20s",
    }

    # Build secrets list
    if external_secrets_prefix:
        secrets_list = [
            {
                "name": key,
                "valueFrom": f"arn:aws:secretsmanager:{region}:{caller.account_id}:secret:{external_secrets_prefix}/{key}"
            }
            for key in (secret_keys or [])
        ]
    else:
        secrets_list = [
            {"name": key, "valueFrom": pulumi.Output.concat(secrets_arn, f":{key}::")}
            for key in (secret_keys or [])
        ]

    container_def = pulumi.Output.all(queue_url, table_name, log_group_name).apply(
        lambda args: json.dumps([{
            "name": "cerebro-worker",
            "image": container_image,
            "essential": True,
            "command": ["worker"],
            "logConfiguration": {
                "logDriver": "awslogs",
                "options": {
                    "awslogs-group": args[2],
                    "awslogs-region": region,
                    "awslogs-stream-prefix": "worker",
                },
            },
            "environment": [
                {"name": k, "value": str(v)} for k, v in worker_env.items()
            ] + [
                {"name": "JOB_QUEUE_URL", "value": args[0]},
                {"name": "JOB_TABLE_NAME", "value": args[1]},
                {"name": "JOB_REGION", "value": region},
            ],
            "secrets": secrets_list,
        }])
    )

    task_definition = aws.ecs.TaskDefinition(
        f"{name}-worker-task",
        family=f"{name}-worker",
        cpu=str(worker_cpu),
        memory=str(worker_memory),
        network_mode="awsvpc",
        requires_compatibilities=["FARGATE"],
        runtime_platform=aws.ecs.TaskDefinitionRuntimePlatformArgs(
            operating_system_family="LINUX",
            cpu_architecture="ARM64",
        ),
        execution_role_arn=execution_role.arn,
        task_role_arn=task_role.arn,
        container_definitions=container_def,
        tags={"Name": f"{name}-worker-task"},
    )

    # Worker service (no load balancer)
    worker_service = aws.ecs.Service(
        f"{name}-worker-service",
        name=f"{name}-worker",
        cluster=cluster_arn,
        task_definition=task_definition.arn,
        desired_count=worker_min_instances,
        launch_type="FARGATE",
        network_configuration=aws.ecs.ServiceNetworkConfigurationArgs(
            subnets=subnet_ids,
            security_groups=[security_group_id],
            assign_public_ip=False,
        ),
        deployment_maximum_percent=200,
        deployment_minimum_healthy_percent=100,
        tags={"Name": f"{name}-worker-service"},
    )

    # Auto-scaling based on SQS queue depth
    scaling_target = aws.appautoscaling.Target(
        f"{name}-worker-scaling-target",
        service_namespace="ecs",
        resource_id=pulumi.Output.concat("service/", cluster_arn.apply(lambda a: a.split("/")[-1]), "/", worker_service.name),
        scalable_dimension="ecs:service:DesiredCount",
        min_capacity=worker_min_instances,
        max_capacity=worker_max_instances,
    )

    # Scale based on queue backlog per worker
    aws.appautoscaling.Policy(
        f"{name}-worker-queue-scaling",
        service_namespace="ecs",
        resource_id=scaling_target.resource_id,
        scalable_dimension="ecs:service:DesiredCount",
        policy_type="TargetTrackingScaling",
        target_tracking_scaling_policy_configuration=aws.appautoscaling.PolicyTargetTrackingScalingPolicyConfigurationArgs(
            target_value=10.0,  # Target ~10 messages per worker
            customized_metric_specification=aws.appautoscaling.PolicyTargetTrackingScalingPolicyConfigurationCustomizedMetricSpecificationArgs(
                metric_name="ApproximateNumberOfMessagesVisible",
                namespace="AWS/SQS",
                statistic="Average",
                dimensions=[
                    aws.appautoscaling.PolicyTargetTrackingScalingPolicyConfigurationCustomizedMetricSpecificationDimensionArgs(
                        name="QueueName",
                        value=f"{name}-jobs",
                    ),
                ],
            ),
            scale_in_cooldown=300,
            scale_out_cooldown=60,
        ),
    )

    return {
        "service": worker_service,
        "task_definition": task_definition,
        "task_role": task_role,
        "execution_role": execution_role,
    }


def create_job_alarms(
    name: str,
    queue_name: str,
    dlq_name: str,
    sns_topic_arn: pulumi.Output[str] = None,
) -> dict:
    """
    Create CloudWatch alarms for job queue monitoring.
    """
    alarms = {}

    # DLQ messages alarm (any message in DLQ is bad)
    alarms["dlq_alarm"] = aws.cloudwatch.MetricAlarm(
        f"{name}-dlq-alarm",
        name=f"{name}-jobs-dlq-messages",
        comparison_operator="GreaterThanThreshold",
        evaluation_periods=1,
        metric_name="ApproximateNumberOfMessagesVisible",
        namespace="AWS/SQS",
        period=60,
        statistic="Sum",
        threshold=0,
        dimensions={"QueueName": dlq_name},
        alarm_actions=[sns_topic_arn] if sns_topic_arn else [],
        ok_actions=[sns_topic_arn] if sns_topic_arn else [],
        tags={"Name": f"{name}-dlq-alarm"},
    )

    # High queue depth alarm
    alarms["queue_depth_alarm"] = aws.cloudwatch.MetricAlarm(
        f"{name}-queue-depth-alarm",
        name=f"{name}-jobs-queue-depth",
        comparison_operator="GreaterThanThreshold",
        evaluation_periods=3,
        metric_name="ApproximateNumberOfMessagesVisible",
        namespace="AWS/SQS",
        period=300,
        statistic="Average",
        threshold=100,
        dimensions={"QueueName": queue_name},
        alarm_actions=[sns_topic_arn] if sns_topic_arn else [],
        ok_actions=[sns_topic_arn] if sns_topic_arn else [],
        tags={"Name": f"{name}-queue-depth-alarm"},
    )

    # Old messages alarm (messages sitting too long)
    alarms["old_messages_alarm"] = aws.cloudwatch.MetricAlarm(
        f"{name}-old-messages-alarm",
        name=f"{name}-jobs-old-messages",
        comparison_operator="GreaterThanThreshold",
        evaluation_periods=1,
        metric_name="ApproximateAgeOfOldestMessage",
        namespace="AWS/SQS",
        period=300,
        statistic="Maximum",
        threshold=3600,  # 1 hour
        dimensions={"QueueName": queue_name},
        alarm_actions=[sns_topic_arn] if sns_topic_arn else [],
        ok_actions=[sns_topic_arn] if sns_topic_arn else [],
        tags={"Name": f"{name}-old-messages-alarm"},
    )

    return alarms
