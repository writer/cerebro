"""
Optional AWS-native runtime resilience controls.
"""

import base64
import io
import json
import zipfile

import pulumi
import pulumi_aws as aws


def create_runtime_controls(name: str, environment: str, disabled_runtime_ids: list[str] = None, enabled: bool = False) -> dict:
    if not enabled:
        return {}

    application = aws.appconfig.Application(
        f"{name}-runtime-controls-app",
        name=f"{name}-runtime-controls",
        description=f"Runtime controls for {name}",
        tags={"Name": f"{name}-runtime-controls"},
    )
    app_environment = aws.appconfig.Environment(
        f"{name}-runtime-controls-env",
        application_id=application.id,
        name=environment,
        description=f"{environment} runtime controls",
        tags={"Name": f"{name}-runtime-controls-{environment}"},
    )
    profile = aws.appconfig.ConfigurationProfile(
        f"{name}-runtime-controls-profile",
        application_id=application.id,
        name="runtime-controls",
        location_uri="hosted",
        type="AWS.Freeform",
        tags={"Name": f"{name}-runtime-controls-profile"},
    )
    hosted_version = aws.appconfig.HostedConfigurationVersion(
        f"{name}-runtime-controls-version",
        application_id=application.id,
        configuration_profile_id=profile.configuration_profile_id,
        content_type="application/json",
        content=json.dumps({
            "version": 1,
            "disabledRuntimeIds": sorted(set(disabled_runtime_ids or [])),
            "maxConcurrentOrchestratorTasks": 1,
        }, separators=(",", ":")),
    )
    strategy = aws.appconfig.DeploymentStrategy(
        f"{name}-runtime-controls-strategy",
        name=f"{name}-runtime-controls-all-at-once",
        deployment_duration_in_minutes=0,
        final_bake_time_in_minutes=0,
        growth_factor=100,
        growth_type="LINEAR",
        replicate_to="NONE",
        tags={"Name": f"{name}-runtime-controls-strategy"},
    )
    deployment = aws.appconfig.Deployment(
        f"{name}-runtime-controls-deployment",
        application_id=application.id,
        configuration_profile_id=profile.configuration_profile_id,
        configuration_version=hosted_version.version_number.apply(str),
        deployment_strategy_id=strategy.id,
        environment_id=app_environment.environment_id,
        description=f"Deploy runtime controls for {name}",
    )
    return {
        "application": application,
        "environment": app_environment,
        "profile": profile,
        "hosted_version": hosted_version,
        "strategy": strategy,
        "deployment": deployment,
    }


def create_orchestrator_step_function(
    name: str,
    cluster_arn: pulumi.Input[str],
    task_definition_arn: pulumi.Input[str],
    subnet_ids: list[pulumi.Input[str]],
    security_group_id: pulumi.Input[str],
    execution_role_arn: pulumi.Input[str],
    task_role_arn: pulumi.Input[str],
    enabled: bool = False,
) -> dict:
    if not enabled:
        return {}

    role = aws.iam.Role(
        f"{name}-orchestrator-sfn-role",
        name=f"{name}-orchestrator-sfn-role",
        assume_role_policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }),
        tags={"Name": f"{name}-orchestrator-sfn-role"},
    )
    aws.iam.RolePolicy(
        f"{name}-orchestrator-sfn-policy",
        role=role.name,
        policy=pulumi.Output.all(task_definition_arn, execution_role_arn, task_role_arn).apply(
            lambda args: json.dumps({
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": ["ecs:RunTask"], "Resource": args[0]},
                    {"Effect": "Allow", "Action": ["ecs:StopTask", "ecs:DescribeTasks"], "Resource": "*"},
                    {"Effect": "Allow", "Action": ["iam:PassRole"], "Resource": [args[1], args[2]]},
                    {"Effect": "Allow", "Action": ["events:PutTargets", "events:PutRule", "events:DescribeRule"], "Resource": "*"},
                ],
            })
        ),
    )
    definition = pulumi.Output.all(cluster_arn, task_definition_arn, subnet_ids, security_group_id).apply(
        lambda args: json.dumps(_state_machine_definition(args[0], args[1], args[2], args[3]))
    )
    state_machine = aws.sfn.StateMachine(
        f"{name}-orchestrator-state-machine",
        name=f"{name}-orchestrator-runtime",
        role_arn=role.arn,
        definition=definition,
        tags={"Name": f"{name}-orchestrator-runtime"},
    )
    return {"role": role, "state_machine": state_machine}


def _state_machine_definition(cluster_arn: str, task_definition_arn: str, subnet_ids: list[str], security_group_id: str) -> dict:
    return {
        "Comment": "Run one Cerebro orchestrator runtime task with bounded retries.",
        "StartAt": "RunOrchestratorTask",
        "States": {
            "RunOrchestratorTask": {
                "Type": "Task",
                "Resource": "arn:aws:states:::ecs:runTask.sync",
                "Parameters": {
                    "Cluster": cluster_arn,
                    "TaskDefinition": task_definition_arn,
                    "LaunchType": "FARGATE",
                    "NetworkConfiguration": {
                        "AwsvpcConfiguration": {
                            "Subnets": subnet_ids,
                            "SecurityGroups": [security_group_id],
                            "AssignPublicIp": "DISABLED",
                        }
                    },
                    "Overrides": {"ContainerOverrides": [{"Name": "cerebro", "Command.$": "$.command"}]},
                },
                "Retry": [{"ErrorEquals": ["ECS.AmazonECSException", "States.TaskFailed"], "IntervalSeconds": 60, "MaxAttempts": 2, "BackoffRate": 2}],
                "End": True,
            }
        },
    }


def create_orchestrator_buffer(
    name: str,
    target_state_machine_arn: pulumi.Input[str] = None,
    enabled: bool = False,
    desired_state: str = "STOPPED",
) -> dict:
    if not enabled:
        return {}
    if not target_state_machine_arn:
        raise ValueError("orchestrator buffer requires a Step Functions state machine target")

    dlq = aws.sqs.Queue(
        f"{name}-orchestrator-buffer-dlq",
        name=f"{name}-orchestrator-buffer-dlq",
        message_retention_seconds=1209600,
        tags={"Name": f"{name}-orchestrator-buffer-dlq"},
    )
    queue = aws.sqs.Queue(
        f"{name}-orchestrator-buffer",
        name=f"{name}-orchestrator-buffer",
        visibility_timeout_seconds=900,
        redrive_policy=dlq.arn.apply(lambda arn: json.dumps({"deadLetterTargetArn": arn, "maxReceiveCount": 3})),
        tags={"Name": f"{name}-orchestrator-buffer"},
    )
    role = aws.iam.Role(
        f"{name}-orchestrator-buffer-pipe-role",
        name=f"{name}-orchestrator-buffer-pipe-role",
        assume_role_policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "pipes.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }),
        tags={"Name": f"{name}-orchestrator-buffer-pipe-role"},
    )
    aws.iam.RolePolicy(
        f"{name}-orchestrator-buffer-pipe-policy",
        role=role.name,
        policy=pulumi.Output.all(queue.arn, target_state_machine_arn).apply(
            lambda args: json.dumps({
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"], "Resource": args[0]},
                    {"Effect": "Allow", "Action": ["states:StartExecution"], "Resource": args[1]},
                ],
            })
        ),
    )
    pipe = aws.pipes.Pipe(
        f"{name}-orchestrator-buffer-pipe",
        name=f"{name}-orchestrator-buffer",
        role_arn=role.arn,
        source=queue.arn,
        target=target_state_machine_arn,
        desired_state=desired_state,
        source_parameters=aws.pipes.PipeSourceParametersArgs(
            sqs_queue_parameters=aws.pipes.PipeSourceParametersSqsQueueParametersArgs(batch_size=1)
        ),
        target_parameters=aws.pipes.PipeTargetParametersArgs(
            input_template='{"command": <$.body.command>}'
        ),
        tags={"Name": f"{name}-orchestrator-buffer"},
    )
    return {"queue": queue, "dlq": dlq, "role": role, "pipe": pipe}


def create_synthetic_canary(
    name: str,
    url: pulumi.Input[str],
    subnet_ids: list[pulumi.Input[str]],
    security_group_id: pulumi.Input[str],
    enabled: bool = False,
    start_canary: bool = False,
) -> dict:
    if not enabled:
        return {}

    artifact_bucket = aws.s3.BucketV2(
        f"{name}-synthetics-artifacts",
        bucket=f"{name}-synthetics-artifacts",
        force_destroy=True,
        tags={"Name": f"{name}-synthetics-artifacts"},
    )
    role = aws.iam.Role(
        f"{name}-synthetics-role",
        name=f"{name}-synthetics-role",
        assume_role_policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }),
        tags={"Name": f"{name}-synthetics-role"},
    )
    aws.iam.RolePolicy(
        f"{name}-synthetics-policy",
        role=role.name,
        policy=artifact_bucket.arn.apply(lambda arn: json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["s3:PutObject", "s3:GetBucketLocation"], "Resource": [arn, f"{arn}/*"]},
                {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], "Resource": "*"},
                {"Effect": "Allow", "Action": ["cloudwatch:PutMetricData"], "Resource": "*"},
                {"Effect": "Allow", "Action": ["ec2:CreateNetworkInterface", "ec2:DescribeNetworkInterfaces", "ec2:DeleteNetworkInterface"], "Resource": "*"},
            ],
        })),
    )
    canary = aws.synthetics.Canary(
        f"{name}-api-canary",
        name=_synthetics_canary_name(name),
        artifact_s3_location=pulumi.Output.concat("s3://", artifact_bucket.bucket),
        execution_role_arn=role.arn,
        handler="index.handler",
        runtime_version="syn-nodejs-puppeteer-6.2",
        schedule=aws.synthetics.CanaryScheduleArgs(expression="rate(5 minutes)"),
        start_canary=start_canary,
        zip_file=url.apply(lambda endpoint: _canary_zip_file(endpoint)),
        vpc_config=aws.synthetics.CanaryVpcConfigArgs(subnet_ids=subnet_ids, security_group_ids=[security_group_id]),
        tags={"Name": f"{name}-api-canary"},
    )
    return {"artifact_bucket": artifact_bucket, "role": role, "canary": canary}


def _synthetics_canary_name(name: str) -> str:
    return "".join(char for char in name.lower() if char.isalnum() or char in "-_")[:21]


def _canary_zip_file(url: str) -> str:
    script = _canary_script(url)
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zip_file:
        zip_file.writestr("index.js", script)
        zip_file.writestr("nodejs/node_modules/index.js", script)
    return base64.b64encode(archive.getvalue()).decode("ascii")


def _canary_script(url: str) -> str:
    endpoint = f"{url.rstrip('/')}/health"
    return f"""
const synthetics = require('Synthetics');
const log = require('SyntheticsLogger');
exports.handler = async () => {{
  const page = await synthetics.getPage();
  const response = await page.goto({json.dumps(endpoint)}, {{ waitUntil: 'networkidle0', timeout: 30000 }});
  if (!response || response.status() >= 500) {{
    throw new Error(`Cerebro health probe failed: ${{response && response.status()}}`);
  }}
  log.info('Cerebro health probe succeeded');
}};
"""


def create_cost_controls(
    name: str,
    sns_topic_arns: list[pulumi.Input[str]] = None,
    email_subscriptions: list[str] = None,
    monthly_budget_usd: int = 0,
    anomaly_detection_enabled: bool = False,
) -> dict:
    resources = {}
    subscribers = []
    for arn in sns_topic_arns or []:
        subscribers.append(aws.costexplorer.AnomalySubscriptionSubscriberArgs(type="SNS", address=arn))
    for email in email_subscriptions or []:
        subscribers.append(aws.costexplorer.AnomalySubscriptionSubscriberArgs(type="EMAIL", address=email))

    if anomaly_detection_enabled and subscribers:
        monitor = aws.costexplorer.AnomalyMonitor(
            f"{name}-cost-anomaly-monitor",
            name=f"{name}-cost-anomaly",
            monitor_type="DIMENSIONAL",
            monitor_dimension="SERVICE",
            tags={"Name": f"{name}-cost-anomaly"},
        )
        subscription = aws.costexplorer.AnomalySubscription(
            f"{name}-cost-anomaly-subscription",
            name=f"{name}-cost-anomaly",
            frequency="DAILY",
            monitor_arn_lists=[monitor.arn],
            subscribers=subscribers,
            tags={"Name": f"{name}-cost-anomaly"},
        )
        resources.update({"anomaly_monitor": monitor, "anomaly_subscription": subscription})

    if monthly_budget_usd > 0 and (sns_topic_arns or email_subscriptions):
        budget = aws.budgets.Budget(
            f"{name}-monthly-budget",
            name=f"{name}-monthly-budget",
            budget_type="COST",
            time_unit="MONTHLY",
            limit_amount=str(monthly_budget_usd),
            limit_unit="USD",
            notifications=[
                aws.budgets.BudgetNotificationArgs(
                    comparison_operator="GREATER_THAN",
                    notification_type="FORECASTED",
                    threshold=80,
                    threshold_type="PERCENTAGE",
                    subscriber_sns_topic_arns=sns_topic_arns or None,
                    subscriber_email_addresses=email_subscriptions or None,
                )
            ],
        )
        resources["budget"] = budget
    return resources
