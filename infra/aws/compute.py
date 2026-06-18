"""
AWS ECS Fargate compute for the Cerebro rewrite runtime.
"""

import hashlib
import json

import pulumi
import pulumi_aws as aws


def create_ecs_cluster(
    name: str,
    vpc_id: pulumi.Input[str],
    subnet_ids: list[pulumi.Input[str]],
    security_group_id: pulumi.Input[str],
    kms_key_id: pulumi.Input[str],
    target_group_arn: pulumi.Input[str],
    container_image: str,
    alb_arn_suffix: pulumi.Input[str] = None,
    target_group_arn_suffix: pulumi.Input[str] = None,
    api_cpu: int = 1024,
    api_memory: int = 2048,
    api_min_instances: int = 1,
    api_max_instances: int = 1,
    api_request_count_per_target_scaling_target: int = 0,
    log_retention_days: int = 30,
    environment: dict = None,
    secret_keys: list[str] = None,
    external_secrets_prefix: str = None,
    bedrock_model_ids: list[str] = None,
    log_group_kms_key_id: pulumi.Input[str] = None,
    s3_source_iam_configs: list[dict] = None,
    efs_file_system_id: pulumi.Input[str] = None,
    efs_access_point_id: pulumi.Input[str] = None,
    efs_container_path: str = None,
    depends_on: list[pulumi.Resource] = None,
    fargate_base: int = 1,
    fargate_weight: int = 1,
    fargate_spot_base: int = 0,
    fargate_spot_weight: int = 0,
    enable_circuit_breaker: bool = True,
    orchestrator_enabled: bool = False,
    orchestrator_schedule_expression: str = "rate(1 hour)",
    orchestrator_cpu: int = 1024,
    orchestrator_memory: int = 2048,
    orchestrator_command: list[str] = None,
    orchestrator_task_count: int = 1,
    orchestrator_schedules: list[dict] = None,
    source_runtimes: list[dict] = None,
    source_runtime_service_bootstrap_ids: list[str] = None,
    otel_collector: dict = None,
) -> dict:
    """Create ECS cluster with an API service."""
    runtime_environment = _source_runtime_environment(environment or {}, source_runtimes or [])
    service_bootstrap_runtimes = _source_runtime_service_bootstrap_runtimes(
        source_runtimes or [],
        source_runtime_service_bootstrap_ids,
    )
    prepared_orchestrator_schedules = []
    if orchestrator_enabled:
        prepared_orchestrator_schedules = _orchestrator_schedules(
            orchestrator_schedule_expression,
            orchestrator_command or ["orchestrator", "run"],
            orchestrator_task_count,
            orchestrator_schedules or [],
        )
        runtime_by_id = _source_runtime_by_id(source_runtimes or [])
        for schedule in prepared_orchestrator_schedules:
            schedule["bootstrap_payload"] = _orchestrator_schedule_bootstrap_payload(
                schedule["command"],
                runtime_by_id,
            )
    bootstrap_payloads = {}
    service_bootstrap_payload = _source_runtime_bootstrap_payload(service_bootstrap_runtimes)
    if service_bootstrap_payload:
        bootstrap_payloads["service"] = service_bootstrap_payload
    orchestrator_bootstrap_payload = (
        _source_runtime_bootstrap_payload(source_runtimes or [])
        if orchestrator_enabled and any(not schedule.get("bootstrap_payload") for schedule in prepared_orchestrator_schedules)
        else ""
    )
    if orchestrator_bootstrap_payload:
        bootstrap_payloads["orchestrator"] = orchestrator_bootstrap_payload
    if not bootstrap_payloads and orchestrator_enabled and source_runtimes:
        bootstrap_payloads["retained"] = json.dumps({"runtimes": []}, sort_keys=True, separators=(",", ":"))
    bootstrap_environment_files = _create_source_runtime_bootstrap_environment_files(name, kms_key_id, bootstrap_payloads)
    execution_secret_keys = list(secret_keys or [])
    otel_collector_config_secret = _otel_collector_config_secret_key(otel_collector, external_secrets_prefix)
    if otel_collector_config_secret:
        execution_secret_keys.append(otel_collector_config_secret)
    secret_prefixes = _secret_prefixes(execution_secret_keys, external_secrets_prefix)
    cluster = aws.ecs.Cluster(
        f"{name}-cluster",
        name=f"{name}-cluster",
        settings=[aws.ecs.ClusterSettingArgs(name="containerInsights", value="enabled")],
        tags={"Name": f"{name}-cluster"},
    )

    capacity_providers = aws.ecs.ClusterCapacityProviders(
        f"{name}-capacity-providers",
        cluster_name=cluster.name,
        capacity_providers=["FARGATE", "FARGATE_SPOT"],
        default_capacity_provider_strategies=[
            aws.ecs.ClusterCapacityProvidersDefaultCapacityProviderStrategyArgs(
                capacity_provider="FARGATE",
                weight=1,
                base=1,
            ),
        ],
    )

    execution_role = _create_execution_role(
        name,
        kms_key_id,
        secret_prefixes,
        [entry["object_prefix_arn"] for entry in bootstrap_environment_files.values()],
        [entry["bucket_arn"] for entry in bootstrap_environment_files.values()],
    )
    execution_role_dependencies = [execution_role.policy] if getattr(execution_role, "policy", None) is not None else []
    otel_collector_enabled = bool(otel_collector and otel_collector.get("enabled"))
    task_role = _create_task_role(
        name,
        s3_source_iam_configs,
        efs_file_system_id,
        _source_runtime_aws_role_arns(source_runtimes or []),
        bedrock_model_ids,
        enable_otel_collector=otel_collector_enabled,
    )
    worker_task_role = None

    log_group = aws.cloudwatch.LogGroup(
        f"{name}-logs",
        name=f"/ecs/{name}",
        retention_in_days=log_retention_days,
        kms_key_id=log_group_kms_key_id,
        tags={"Name": f"{name}-logs"},
    )
    otel_collector_log_group = None
    if otel_collector_enabled:
        otel_collector_log_group = aws.cloudwatch.LogGroup(
            f"{name}-otel-collector-logs",
            name=f"/ecs/{name}/otel-collector",
            retention_in_days=log_retention_days,
            kms_key_id=log_group_kms_key_id,
            tags={"Name": f"{name}-otel-collector-logs"},
        )

    api_task_definition = _create_task_definition(
        name=name,
        container_image=container_image,
        cpu=api_cpu,
        memory=api_memory,
        execution_role_arn=execution_role.arn,
        task_role_arn=task_role.arn,
        log_group_name=log_group.name,
        otel_collector_log_group_name=otel_collector_log_group.name if otel_collector_log_group else None,
        environment=runtime_environment,
        secret_keys=secret_keys or [],
        external_secrets_prefix=external_secrets_prefix,
        efs_file_system_id=efs_file_system_id,
        efs_access_point_id=efs_access_point_id,
        efs_container_path=efs_container_path,
        source_runtime_bootstrap_environment_file_arn=(bootstrap_environment_files.get("service") or {}).get("environment_file_arn"),
        otel_collector=otel_collector,
        depends_on=[
            *((bootstrap_environment_files.get("service") or {}).get("resources") or []),
            *execution_role_dependencies,
        ],
    )

    orchestrator_task_definition = None
    orchestrator_rule = None
    orchestrator_target = None
    orchestrator_rules = []
    orchestrator_targets = []
    orchestrator_scheduler_group = None
    orchestrator_scheduler_dlq = None
    orchestrator_scheduler_schedules = []
    orchestrator_task_definitions = []
    orchestrator_events_role = None
    if orchestrator_enabled:
        worker_task_role = _create_task_role(
            f"{name}-worker",
            s3_source_iam_configs,
            efs_file_system_id,
            _source_runtime_aws_role_arns(source_runtimes or []),
            bedrock_model_ids,
            enable_otel_collector=otel_collector_enabled,
        )
        schedules = prepared_orchestrator_schedules
        task_definition = _create_task_definition(
            name=f"{name}-orchestrator",
            container_image=container_image,
            cpu=orchestrator_cpu,
            memory=orchestrator_memory,
            execution_role_arn=execution_role.arn,
            task_role_arn=worker_task_role.arn,
            log_group_name=log_group.name,
            otel_collector_log_group_name=otel_collector_log_group.name if otel_collector_log_group else None,
            environment=runtime_environment,
            secret_keys=secret_keys or [],
            external_secrets_prefix=external_secrets_prefix,
            efs_file_system_id=efs_file_system_id,
            efs_access_point_id=efs_access_point_id,
            efs_container_path=efs_container_path,
            container_command=[str(part) for part in (orchestrator_command or ["orchestrator", "run"])],
            expose_http=False,
            enable_health_check=False,
            log_stream_prefix="orchestrator",
            source_runtime_bootstrap_environment_file_arn=(bootstrap_environment_files.get("orchestrator") or {}).get("environment_file_arn"),
            enable_source_runtime_bootstrap=bool(source_runtimes or []),
            otel_collector=otel_collector,
            depends_on=[
                *((bootstrap_environment_files.get("orchestrator") or {}).get("resources") or []),
                *execution_role_dependencies,
            ],
        )
        orchestrator_task_definitions.append(task_definition)
        orchestrator_task_definition = orchestrator_task_definitions[0] if orchestrator_task_definitions else None
        if any(schedule["backend"] == "scheduler" for schedule in schedules):
            orchestrator_scheduler_group = aws.scheduler.ScheduleGroup(
                f"{name}-orchestrator-schedules",
                name=f"{name}-orchestrator",
                tags={"Name": f"{name}-orchestrator"},
            )
            orchestrator_scheduler_dlq = aws.sqs.Queue(
                f"{name}-orchestrator-scheduler-dlq",
                name=f"{name}-orchestrator-scheduler-dlq",
                message_retention_seconds=1209600,
                tags={"Name": f"{name}-orchestrator-scheduler-dlq"},
            )
        orchestrator_events_role = _create_orchestrator_events_role(
            name=name,
            task_definition_arns=[task_definition.arn for task_definition in orchestrator_task_definitions],
            execution_role_arn=execution_role.arn,
            task_role_arn=worker_task_role.arn,
            scheduler_dlq_arn=orchestrator_scheduler_dlq.arn if orchestrator_scheduler_dlq else None,
        )
        for schedule in schedules:
            schedule_suffix = schedule["suffix"]
            schedule_resource_prefix = f"{name}-orchestrator" if schedule_suffix == "default" else f"{name}-orchestrator-{schedule_suffix}"
            if schedule["backend"] == "scheduler":
                scheduler_schedule = aws.scheduler.Schedule(
                    f"{schedule_resource_prefix}-schedule",
                    name=schedule_resource_prefix,
                    group_name=orchestrator_scheduler_group.name,
                    schedule_expression=schedule["schedule_expression"],
                    flexible_time_window=aws.scheduler.ScheduleFlexibleTimeWindowArgs(
                        mode="FLEXIBLE",
                        maximum_window_in_minutes=schedule["flexible_window_minutes"],
                    ),
                    target=aws.scheduler.ScheduleTargetArgs(
                        arn=cluster.arn,
                        role_arn=orchestrator_events_role.arn,
                        input=_orchestrator_target_input(
                            schedule["command"],
                            schedule.get("bootstrap_payload") or "",
                        ),
                        ecs_parameters=aws.scheduler.ScheduleTargetEcsParametersArgs(
                            task_definition_arn=orchestrator_task_definition.arn,
                            task_count=schedule["task_count"],
                            launch_type="FARGATE",
                            network_configuration=aws.scheduler.ScheduleTargetEcsParametersNetworkConfigurationArgs(
                                subnets=subnet_ids,
                                security_groups=[security_group_id],
                                assign_public_ip=False,
                            ),
                        ),
                        retry_policy=aws.scheduler.ScheduleTargetRetryPolicyArgs(
                            maximum_event_age_in_seconds=3600,
                            maximum_retry_attempts=2,
                        ),
                        dead_letter_config=aws.scheduler.ScheduleTargetDeadLetterConfigArgs(
                            arn=orchestrator_scheduler_dlq.arn,
                        ),
                    ),
                    state=schedule["state"],
                    opts=pulumi.ResourceOptions(depends_on=[capacity_providers, orchestrator_events_role]),
                )
                orchestrator_scheduler_schedules.append(scheduler_schedule)
            else:
                rule = aws.cloudwatch.EventRule(
                    f"{schedule_resource_prefix}-schedule",
                    name=f"{name}-orchestrator" if schedule_suffix == "default" else schedule_resource_prefix,
                    schedule_expression=schedule["schedule_expression"],
                    state=schedule["state"],
                    tags={"Name": schedule_resource_prefix},
                )
                target = aws.cloudwatch.EventTarget(
                    f"{schedule_resource_prefix}-target",
                    rule=rule.name,
                    arn=cluster.arn,
                    role_arn=orchestrator_events_role.arn,
                    target_id=f"{schedule_suffix}-ecs"[:64],
                    ecs_target=aws.cloudwatch.EventTargetEcsTargetArgs(
                        task_definition_arn=orchestrator_task_definition.arn,
                        task_count=schedule["task_count"],
                        launch_type="FARGATE",
                        network_configuration=aws.cloudwatch.EventTargetEcsTargetNetworkConfigurationArgs(
                            subnets=subnet_ids,
                            security_groups=[security_group_id],
                            assign_public_ip=False,
                        ),
                    ),
                    input=_orchestrator_target_input(
                        schedule["command"],
                        schedule.get("bootstrap_payload") or "",
                    ),
                    opts=pulumi.ResourceOptions(depends_on=[capacity_providers]),
                )
                orchestrator_rules.append(rule)
                orchestrator_targets.append(target)
        orchestrator_rule = orchestrator_rules[0] if orchestrator_rules else None
        orchestrator_target = orchestrator_targets[0] if orchestrator_targets else None

    capacity_provider_strategies = []
    if fargate_base > 0 or fargate_weight > 0:
        capacity_provider_strategies.append(
            aws.ecs.ServiceCapacityProviderStrategyArgs(
                capacity_provider="FARGATE",
                base=fargate_base,
                weight=fargate_weight,
            )
        )
    if fargate_spot_base > 0 or fargate_spot_weight > 0:
        capacity_provider_strategies.append(
            aws.ecs.ServiceCapacityProviderStrategyArgs(
                capacity_provider="FARGATE_SPOT",
                base=fargate_spot_base,
                weight=fargate_spot_weight,
            )
        )

    service_dependencies = [capacity_providers]
    if depends_on:
        service_dependencies.extend(depends_on)

    # Keep rollout capacity at 200/100 even for steady-state singleton services.
    # With 100/0 ECS may terminate the only healthy target before scheduling the
    # replacement, leaving the ALB at 503 and, in practice, the service stuck in
    # SCALE_UP with requestedTaskCount=1/runningTaskCount=0. apiMaxInstances=1
    # still constrains steady-state autoscaling; this only permits a brief
    # old+new overlap during deployments.

    api_service = aws.ecs.Service(
        f"{name}-service",
        name=f"{name}-api",
        cluster=cluster.id,
        task_definition=api_task_definition.arn,
        desired_count=api_min_instances,
        capacity_provider_strategies=capacity_provider_strategies if capacity_provider_strategies else None,
        availability_zone_rebalancing="DISABLED" if api_max_instances == 1 else "ENABLED",
        network_configuration=aws.ecs.ServiceNetworkConfigurationArgs(
            subnets=subnet_ids,
            security_groups=[security_group_id],
            assign_public_ip=False,
        ),
        load_balancers=[aws.ecs.ServiceLoadBalancerArgs(
            target_group_arn=target_group_arn,
            container_name="cerebro",
            container_port=8080,
        )],
        health_check_grace_period_seconds=120,
        deployment_maximum_percent=200,
        deployment_minimum_healthy_percent=100,
        force_new_deployment=True,
        deployment_circuit_breaker=(
            aws.ecs.ServiceDeploymentCircuitBreakerArgs(enable=True, rollback=True)
            if enable_circuit_breaker
            else None
        ),
        tags={"Name": f"{name}-service"},
        opts=pulumi.ResourceOptions(depends_on=service_dependencies),
    )

    scaling_target = aws.appautoscaling.Target(
        f"{name}-scaling-target",
        service_namespace="ecs",
        resource_id=pulumi.Output.concat("service/", cluster.name, "/", api_service.name),
        scalable_dimension="ecs:service:DesiredCount",
        min_capacity=api_min_instances,
        max_capacity=api_max_instances,
    )

    if api_max_instances > api_min_instances:
        aws.appautoscaling.Policy(
            f"{name}-cpu-scaling",
            service_namespace="ecs",
            resource_id=scaling_target.resource_id,
            scalable_dimension="ecs:service:DesiredCount",
            policy_type="TargetTrackingScaling",
            target_tracking_scaling_policy_configuration=aws.appautoscaling.PolicyTargetTrackingScalingPolicyConfigurationArgs(
                target_value=70.0,
                predefined_metric_specification=aws.appautoscaling.PolicyTargetTrackingScalingPolicyConfigurationPredefinedMetricSpecificationArgs(
                    predefined_metric_type="ECSServiceAverageCPUUtilization",
                ),
                scale_in_cooldown=300,
                scale_out_cooldown=60,
            ),
        )
        aws.appautoscaling.Policy(
            f"{name}-memory-scaling",
            service_namespace="ecs",
            resource_id=scaling_target.resource_id,
            scalable_dimension="ecs:service:DesiredCount",
            policy_type="TargetTrackingScaling",
            target_tracking_scaling_policy_configuration=aws.appautoscaling.PolicyTargetTrackingScalingPolicyConfigurationArgs(
                target_value=75.0,
                predefined_metric_specification=aws.appautoscaling.PolicyTargetTrackingScalingPolicyConfigurationPredefinedMetricSpecificationArgs(
                    predefined_metric_type="ECSServiceAverageMemoryUtilization",
                ),
                scale_in_cooldown=300,
                scale_out_cooldown=60,
            ),
        )
        if api_request_count_per_target_scaling_target > 0 and alb_arn_suffix and target_group_arn_suffix:
            aws.appautoscaling.Policy(
                f"{name}-request-count-scaling",
                service_namespace="ecs",
                resource_id=scaling_target.resource_id,
                scalable_dimension="ecs:service:DesiredCount",
                policy_type="TargetTrackingScaling",
                target_tracking_scaling_policy_configuration=aws.appautoscaling.PolicyTargetTrackingScalingPolicyConfigurationArgs(
                    target_value=float(api_request_count_per_target_scaling_target),
                    predefined_metric_specification=aws.appautoscaling.PolicyTargetTrackingScalingPolicyConfigurationPredefinedMetricSpecificationArgs(
                        predefined_metric_type="ALBRequestCountPerTarget",
                        resource_label=pulumi.Output.concat(alb_arn_suffix, "/", target_group_arn_suffix),
                    ),
                    scale_in_cooldown=300,
                    scale_out_cooldown=60,
                ),
            )

    return {
        "cluster": cluster,
        "capacity_providers": capacity_providers,
        "api_service": api_service,
        "task_definition": api_task_definition,
        "orchestrator_task_definition": orchestrator_task_definition,
        "orchestrator_task_definitions": orchestrator_task_definitions,
        "orchestrator_rule": orchestrator_rule,
        "orchestrator_rules": orchestrator_rules,
        "orchestrator_target": orchestrator_target,
        "orchestrator_targets": orchestrator_targets,
        "orchestrator_scheduler_group": orchestrator_scheduler_group,
        "orchestrator_scheduler_dlq": orchestrator_scheduler_dlq,
        "orchestrator_scheduler_schedules": orchestrator_scheduler_schedules,
        "orchestrator_events_role": orchestrator_events_role,
        "execution_role": execution_role,
        "task_role": task_role,
        "worker_task_role": worker_task_role,
        "log_group": log_group,
        "otel_collector_log_group": otel_collector_log_group,
    }


def _source_runtime_environment(environment: dict, source_runtimes: list[dict]) -> dict:
    merged = dict(environment or {})
    role_entries = _source_runtime_aws_role_entries(source_runtimes or [])
    if role_entries and not merged.get("CEREBRO_AWS_ASSUME_ROLE_ARNS"):
        merged["CEREBRO_AWS_ASSUME_ROLE_ARNS"] = ",".join(role_entries)
    return merged


def _otel_collector_config_secret_key(otel_collector: dict | None, default_prefix: str) -> dict | None:
    if not otel_collector or not otel_collector.get("enabled"):
        return None
    source = str(otel_collector.get("config_secret_name") or "").strip()
    if not source:
        return None
    return {
        "name": "AOT_CONFIG_CONTENT",
        "source": source,
        "prefix": str(otel_collector.get("config_secret_prefix") or default_prefix).strip(),
    }


def _source_runtime_aws_role_entries(source_runtimes: list[dict]) -> list[str]:
    role_entries = set()
    for runtime in source_runtimes:
        tenant_id = _runtime_field(runtime, "tenantId", "tenant_id")
        if not tenant_id:
            continue
        runtime_config = runtime.get("config") or {}
        if not isinstance(runtime_config, dict):
            continue
        role_arn = str(runtime_config.get("role_arn", "")).strip()
        if role_arn:
            role_entries.add(f"{tenant_id}={role_arn}")
    return sorted(role_entries)


def _source_runtime_aws_role_arns(source_runtimes: list[dict]) -> list[str]:
    role_arns = set()
    for runtime in source_runtimes:
        config = runtime.get("config") or {}
        if not isinstance(config, dict):
            continue
        role_arn = str(config.get("role_arn", "")).strip()
        if role_arn:
            role_arns.add(role_arn)
    return sorted(role_arns)


def _source_runtime_service_bootstrap_runtimes(
    source_runtimes: list[dict],
    bootstrap_ids: list[str] | None,
) -> list[dict]:
    if bootstrap_ids is None:
        return list(source_runtimes or [])
    if not isinstance(bootstrap_ids, list):
        raise ValueError("sourceRuntimeServiceBootstrapIds must be a list")
    if not bootstrap_ids:
        return []
    requested_ids = [str(runtime_id).strip() for runtime_id in bootstrap_ids]
    if any(not runtime_id for runtime_id in requested_ids):
        raise ValueError("sourceRuntimeServiceBootstrapIds entries must be non-empty strings")
    requested = set(requested_ids)
    available = {_runtime_field(runtime, "id") for runtime in source_runtimes or []}
    missing = sorted(requested - available)
    if missing:
        raise ValueError(
            "sourceRuntimeServiceBootstrapIds references unknown source runtime(s): "
            + ", ".join(missing)
        )
    return [
        runtime
        for runtime in source_runtimes or []
        if _runtime_field(runtime, "id") in requested
    ]


def _source_runtime_by_id(source_runtimes: list[dict]) -> dict[str, dict]:
    return {
        runtime_id: runtime
        for runtime in source_runtimes or []
        if (runtime_id := _runtime_field(runtime, "id"))
    }


def _runtime_id_from_orchestrator_command(command: list[str]) -> str:
    for part in command or []:
        text = str(part).strip()
        if text.startswith("runtime_id="):
            return text.split("=", 1)[1].strip()
    return ""


def _orchestrator_schedule_bootstrap_payload(command: list[str], runtime_by_id: dict[str, dict]) -> str:
    runtime_id = _runtime_id_from_orchestrator_command(command)
    runtime = runtime_by_id.get(runtime_id)
    if not runtime:
        return ""
    return _source_runtime_bootstrap_payload([runtime])


def _orchestrator_target_input(command: list[str], bootstrap_payload: str = "") -> str:
    container_overrides = [{"name": "cerebro", "command": [str(part) for part in command]}]
    if bootstrap_payload:
        container_overrides.append(
            {
                "name": "source-runtime-bootstrap",
                "environmentFiles": [],
                "environment": [{"name": "CEREBRO_SOURCE_RUNTIME_BOOTSTRAP_JSON", "value": bootstrap_payload}],
            }
        )
    return json.dumps(
        {"containerOverrides": container_overrides},
        separators=(",", ":"),
    )


def _create_source_runtime_bootstrap_environment_files(
    name: str,
    kms_key_id: pulumi.Input[str],
    payloads: dict[str, str],
) -> dict[str, dict]:
    if not payloads:
        return {}

    bucket = aws.s3.Bucket(
        f"{name}-source-runtime-bootstrap",
        bucket=f"writer-{name}-source-runtime-bootstrap",
        force_destroy=False,
        tags={"Name": f"writer-{name}-source-runtime-bootstrap"},
    )
    public_access_block = aws.s3.BucketPublicAccessBlock(
        f"{name}-source-runtime-bootstrap-public-access",
        bucket=bucket.id,
        block_public_acls=True,
        block_public_policy=True,
        ignore_public_acls=True,
        restrict_public_buckets=True,
    )
    encryption = aws.s3.BucketServerSideEncryptionConfiguration(
        f"{name}-source-runtime-bootstrap-sse",
        bucket=bucket.id,
        rules=[
            aws.s3.BucketServerSideEncryptionConfigurationRuleArgs(
                apply_server_side_encryption_by_default=aws.s3.BucketServerSideEncryptionConfigurationRuleApplyServerSideEncryptionByDefaultArgs(
                    sse_algorithm="aws:kms",
                    kms_master_key_id=kms_key_id,
                ),
                bucket_key_enabled=True,
            )
        ],
    )
    versioning = aws.s3.BucketVersioning(
        f"{name}-source-runtime-bootstrap-versioning",
        bucket=bucket.id,
        versioning_configuration=aws.s3.BucketVersioningVersioningConfigurationArgs(status="Enabled"),
    )

    environment_files = {}
    for label, payload in sorted(payloads.items()):
        payload_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
        key = f"source-runtime-bootstrap/{label}-{payload_hash}.env"
        obj = aws.s3.BucketObjectv2(
            f"{name}-source-runtime-bootstrap-{label}",
            bucket=bucket.id,
            key=key,
            content=f"CEREBRO_SOURCE_RUNTIME_BOOTSTRAP_JSON={payload}\n",
            content_type="text/plain",
            tags={"Name": f"{name}-source-runtime-bootstrap-{label}"},
            opts=pulumi.ResourceOptions(
                depends_on=[public_access_block, encryption, versioning],
                retain_on_delete=True,
            ),
        )
        environment_files[label] = {
            "environment_file_arn": obj.arn,
            "bucket_arn": bucket.arn,
            "object_arn": obj.arn,
            "object_prefix_arn": pulumi.Output.concat(bucket.arn, "/source-runtime-bootstrap/*"),
            "resources": [obj],
        }
    return environment_files


def _secret_prefix(secret_key, default_prefix: str) -> str:
    if isinstance(secret_key, dict):
        return str(secret_key.get("prefix") or default_prefix).strip()
    return str(default_prefix).strip()


def _secret_prefixes(secret_keys: list, default_prefix: str) -> list[str]:
    prefixes = {_secret_prefix(secret_key, default_prefix) for secret_key in (secret_keys or [])}
    prefixes = {prefix for prefix in prefixes if prefix}
    if not prefixes and default_prefix:
        prefixes.add(str(default_prefix).strip())
    if not prefixes:
        raise ValueError("at least one secret prefix is required")
    return sorted(prefixes)


def _create_execution_role(
    name: str,
    kms_key_id: pulumi.Input[str],
    secret_prefixes: list[str],
    source_runtime_registry_prefix_arns: list[pulumi.Input[str]] = None,
    source_runtime_registry_bucket_arns: list[pulumi.Input[str]] = None,
):
    if not secret_prefixes:
        raise ValueError("secret_prefixes is required")

    role = aws.iam.Role(
        f"{name}-exec-role",
        name=f"{name}-exec-role",
        assume_role_policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        }),
        tags={"Name": f"{name}-exec-role"},
    )

    aws.iam.RolePolicyAttachment(
        f"{name}-exec-policy",
        role=role.name,
        policy_arn="arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy",
    )

    caller = aws.get_caller_identity()
    region = aws.get_region()
    secret_resources = [
        f"arn:aws:secretsmanager:{region.region}:{caller.account_id}:secret:{prefix}/*"
        for prefix in sorted(set(secret_prefixes))
    ]

    def build_policy(args):
        statements = [
            {
                "Effect": "Allow",
                "Action": ["secretsmanager:GetSecretValue"],
                "Resource": args[0],
            },
            {
                "Effect": "Allow",
                "Action": ["kms:Decrypt"],
                "Resource": f"arn:aws:kms:*:*:key/{args[1]}",
            },
        ]
        if source_runtime_registry_prefix_arns:
            statements.append(
                {
                    "Sid": "ReadSourceRuntimeBootstrapRegistryBucket",
                    "Effect": "Allow",
                    "Action": ["s3:GetBucketLocation"],
                    "Resource": args[2 : 2 + len(source_runtime_registry_bucket_arns or [])],
                }
            )
            statements.append(
                {
                    "Sid": "ReadSourceRuntimeBootstrapRegistry",
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": args[2 + len(source_runtime_registry_bucket_arns or []) :],
                }
            )
        return json.dumps({"Version": "2012-10-17", "Statement": statements})

    policy = aws.iam.RolePolicy(
        f"{name}-exec-secrets",
        role=role.name,
        policy=pulumi.Output.all(
            secret_resources,
            kms_key_id,
            *(source_runtime_registry_bucket_arns or []),
            *(source_runtime_registry_prefix_arns or []),
        ).apply(build_policy),
    )
    role.policy = policy
    return role


def _bedrock_model_resource_arns(model_ids: list[str]) -> list[str]:
    cleaned = sorted({str(model_id).strip() for model_id in model_ids if str(model_id).strip()})
    if not cleaned:
        return []
    caller = aws.get_caller_identity()
    resources: set[str] = set()
    for model_id in cleaned:
        if model_id.startswith("arn:aws:bedrock:"):
            resources.add(model_id)
            continue
        if _is_bedrock_inference_profile_id(model_id):
            resources.add(f"arn:aws:bedrock:*:{caller.account_id}:inference-profile/{model_id}")
            foundation_model_id = _foundation_model_id_from_profile(model_id)
            if foundation_model_id:
                resources.add(f"arn:aws:bedrock:*::foundation-model/{foundation_model_id}")
            continue
        resources.add(f"arn:aws:bedrock:*::foundation-model/{model_id}")
    return sorted(resources)


def _is_bedrock_inference_profile_id(model_id: str) -> bool:
    return model_id.startswith(("us.", "global.", "eu.", "apac."))


def _foundation_model_id_from_profile(profile_id: str) -> str:
    for prefix in ("us.", "global.", "eu.", "apac."):
        if profile_id.startswith(prefix):
            return profile_id[len(prefix):]
    return ""


def _create_task_role(
    name: str,
    s3_source_iam_configs: list[dict] = None,
    efs_file_system_id: pulumi.Input[str] = None,
    assume_role_arns: list[str] = None,
    bedrock_model_ids: list[str] = None,
    enable_otel_collector: bool = False,
) -> aws.iam.Role:
    role = aws.iam.Role(
        f"{name}-task-role",
        name=f"{name}-task-role",
        assume_role_policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        }),
        tags={"Name": f"{name}-task-role"},
    )

    aws.iam.RolePolicy(
        f"{name}-task-cloudwatch",
        role=role.name,
        policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["cloudwatch:PutMetricData"],
                "Resource": "*",
            }],
        }),
    )

    if enable_otel_collector:
        aws.iam.RolePolicy(
            f"{name}-task-otel-export",
            role=role.name,
            policy=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": [
                        "xray:PutTraceSegments",
                        "xray:PutTelemetryRecords",
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:DescribeLogStreams",
                        "logs:PutLogEvents",
                        "logs:PutRetentionPolicy",
                    ],
                    "Resource": "*",
                }],
            }),
        )

    if assume_role_arns:
        aws.iam.RolePolicy(
            f"{name}-task-assume-role",
            role=role.name,
            policy=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": ["sts:AssumeRole", "sts:TagSession"],
                    "Resource": sorted(set(assume_role_arns)),
                }],
            }),
        )

    bedrock_resources = _bedrock_model_resource_arns(bedrock_model_ids or [])
    if bedrock_resources:
        aws.iam.RolePolicy(
            f"{name}-task-bedrock",
            role=role.name,
            policy=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
                    "Resource": bedrock_resources,
                }],
            }),
        )

    if s3_source_iam_configs:
        bucket_arns = []
        object_arns = []
        role_arns = []
        for cfg in s3_source_iam_configs:
            bucket_arn = cfg["bucket_arn"]
            bucket_arns.append(bucket_arn)
            prefixes = cfg.get("prefixes") or []
            if prefixes:
                for prefix in prefixes:
                    object_arns.append(f"{bucket_arn}/{prefix}*")
            else:
                object_arns.append(f"{bucket_arn}/*")
            if cfg.get("role_arn"):
                role_arns.append(cfg["role_arn"])

        statements = [
            {"Sid": "ListS3SourceBuckets", "Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": bucket_arns},
            {"Sid": "ReadS3SourceObjects", "Effect": "Allow", "Action": ["s3:GetObject"], "Resource": object_arns},
        ]
        if role_arns:
            statements.append({"Sid": "AssumeS3SourceRoles", "Effect": "Allow", "Action": ["sts:AssumeRole"], "Resource": role_arns})
        aws.iam.RolePolicy(
            f"{name}-task-s3-sources",
            role=role.name,
            policy=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )

    if efs_file_system_id is not None:
        aws.iam.RolePolicy(
            f"{name}-task-efs",
            role=role.name,
            policy=pulumi.Output.all(efs_file_system_id).apply(lambda args: json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": ["elasticfilesystem:ClientMount", "elasticfilesystem:ClientWrite"],
                    "Resource": f"arn:aws:elasticfilesystem:*:*:file-system/{args[0]}",
                }],
            })),
        )

    return role


def _create_orchestrator_events_role(
    name: str,
    task_definition_arns: list[pulumi.Input[str]],
    execution_role_arn: pulumi.Input[str],
    task_role_arn: pulumi.Input[str],
    scheduler_dlq_arn: pulumi.Input[str] = None,
) -> aws.iam.Role:
    role = aws.iam.Role(
        f"{name}-orchestrator-events-role",
        name=f"{name}-orchestrator-events-role",
        assume_role_policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": ["events.amazonaws.com", "scheduler.amazonaws.com"]},
                "Action": "sts:AssumeRole",
            }],
        }),
        tags={"Name": f"{name}-orchestrator-events-role"},
    )

    policy_inputs = [*task_definition_arns, execution_role_arn, task_role_arn]
    if scheduler_dlq_arn is not None:
        policy_inputs.append(scheduler_dlq_arn)

    def _policy(args):
        task_definition_count = len(task_definition_arns)
        statements = [
            {
                "Effect": "Allow",
                "Action": ["ecs:RunTask"],
                "Resource": args[:task_definition_count],
            },
            {
                "Effect": "Allow",
                "Action": ["iam:PassRole"],
                "Resource": [args[task_definition_count], args[task_definition_count + 1]],
            },
        ]
        if scheduler_dlq_arn is not None:
            statements.append({
                "Effect": "Allow",
                "Action": ["sqs:SendMessage"],
                "Resource": args[-1],
            })
        return json.dumps({"Version": "2012-10-17", "Statement": statements})

    aws.iam.RolePolicy(
        f"{name}-orchestrator-events-policy",
        role=role.name,
        policy=pulumi.Output.all(*policy_inputs).apply(_policy),
    )

    return role


def _orchestrator_schedules(
    schedule_expression: str,
    command: list[str],
    task_count: int,
    configured_schedules: list[dict],
) -> list[dict]:
    if not configured_schedules:
        return [{
            "suffix": "default",
            "schedule_expression": schedule_expression,
            "command": [str(part) for part in command],
            "task_count": max(1, int(task_count or 1)),
            "backend": "eventbridge",
            "flexible_window_minutes": 15,
            "state": "ENABLED",
        }]
    schedules = []
    seen = set()
    for index, schedule in enumerate(configured_schedules):
        suffix = _schedule_suffix(schedule.get("name") or f"schedule-{index + 1}")
        if suffix in seen:
            raise ValueError(f"duplicate orchestrator schedule name: {suffix}")
        seen.add(suffix)
        schedule_command = schedule.get("command") or command
        if not isinstance(schedule_command, list) or not schedule_command:
            raise ValueError(f"orchestrator schedule {suffix} command must be a non-empty array")
        schedules.append({
            "suffix": suffix,
            "schedule_expression": schedule.get("scheduleExpression") or schedule.get("schedule_expression") or schedule_expression,
            "command": [str(part) for part in schedule_command],
            "task_count": max(1, int(schedule.get("taskCount") or schedule.get("task_count") or task_count or 1)),
            "backend": _schedule_backend(schedule.get("backend") or schedule.get("scheduleBackend")),
            "flexible_window_minutes": max(1, int(schedule.get("flexibleWindowMinutes") or schedule.get("flexible_window_minutes") or 15)),
            "state": _schedule_state(schedule.get("state") or schedule.get("scheduleState")),
        })
    return schedules


def _schedule_backend(value) -> str:
    backend = str(value or "eventbridge").strip()
    if backend not in {"eventbridge", "scheduler"}:
        raise ValueError("orchestrator schedule backend must be eventbridge or scheduler")
    return backend


def _schedule_state(value) -> str:
    state = str(value or "ENABLED").strip().upper()
    if state not in {"ENABLED", "DISABLED"}:
        raise ValueError("orchestrator schedule state must be ENABLED or DISABLED")
    return state


def _schedule_suffix(value: str) -> str:
    chars = []
    for char in str(value).strip().lower():
        if ("a" <= char <= "z") or ("0" <= char <= "9"):
            chars.append(char)
        elif chars and chars[-1] != "-":
            chars.append("-")
    suffix = "".join(chars).strip("-")
    if not suffix:
        raise ValueError("orchestrator schedule name must include at least one alphanumeric character")
    return suffix


def _create_task_definition(
    name: str,
    container_image: str,
    cpu: int,
    memory: int,
    execution_role_arn: pulumi.Input[str],
    task_role_arn: pulumi.Input[str],
    log_group_name: pulumi.Input[str],
    environment: dict,
    secret_keys: list[str],
    external_secrets_prefix: str,
    otel_collector_log_group_name: pulumi.Input[str] = None,
    efs_file_system_id: pulumi.Input[str] = None,
    efs_access_point_id: pulumi.Input[str] = None,
    efs_container_path: str = None,
    container_command: list[str] = None,
    expose_http: bool = True,
    enable_health_check: bool = True,
    log_stream_prefix: str = "ecs",
    source_runtimes: list[dict] = None,
    source_runtime_bootstrap_environment_file_arn: pulumi.Input[str] = None,
    enable_source_runtime_bootstrap: bool = False,
    otel_collector: dict = None,
    depends_on: list[pulumi.Resource] = None,
) -> aws.ecs.TaskDefinition:
    if not external_secrets_prefix:
        raise ValueError("external_secrets_prefix is required")

    region = aws.get_region().region
    caller = aws.get_caller_identity()
    secret_specs = []
    for secret_key in secret_keys:
        if isinstance(secret_key, dict):
            secret_specs.append((secret_key["name"], secret_key["source"], secret_key.get("prefix") or external_secrets_prefix))
        else:
            secret_specs.append((secret_key, secret_key, external_secrets_prefix))
    otel_collector = otel_collector or {}
    otel_collector_enabled = bool(otel_collector.get("enabled"))
    otel_collector_image = str(otel_collector.get("image") or "").strip()
    otel_collector_config_secret = _otel_collector_config_secret_key(otel_collector, external_secrets_prefix)
    otel_collector_cpu = int(otel_collector.get("cpu") or 0)
    otel_collector_memory = int(otel_collector.get("memory") or 0)
    if otel_collector_enabled:
        if not otel_collector_image:
            raise ValueError("otel collector image is required when the collector is enabled")
        if not otel_collector_config_secret:
            raise ValueError("otel collector config secret is required when the collector is enabled")
    source_runtime_bootstrap_payload = _source_runtime_bootstrap_payload(source_runtimes or [])
    env_items = sorted(environment.items())
    env_values = [value for _, value in env_items]

    def build_container_def(args):
        log_group = args[0]
        collector_log_group = args[1] or log_group
        bootstrap_environment_file_arn = str(args[2] or "")
        resolved_env_values = args[3:]
        env = [
            {"name": key, "value": str(value)}
            for (key, _), value in zip(env_items, resolved_env_values)
        ]
        secret_env = [
            {"name": name, "valueFrom": f"arn:aws:secretsmanager:{region}:{caller.account_id}:secret:{prefix}/{source}"}
            for name, source, prefix in secret_specs
        ]
        log_options = {
            "awslogs-group": log_group,
            "awslogs-region": region,
        }
        collector_container = None
        if otel_collector_enabled:
            collector_container = {
                "name": "otel-collector",
                "image": otel_collector_image,
                "essential": True,
                "environment": [
                    {"name": "AWS_REGION", "value": region},
                    {"name": "AWS_DEFAULT_REGION", "value": region},
                ],
                "secrets": [
                    {
                        "name": otel_collector_config_secret["name"],
                        "valueFrom": (
                            f"arn:aws:secretsmanager:{region}:{caller.account_id}:secret:"
                            f"{otel_collector_config_secret['prefix']}/{otel_collector_config_secret['source']}"
                        ),
                    }
                ],
                "logConfiguration": {
                    "logDriver": "awslogs",
                    "options": {
                        **log_options,
                        "awslogs-group": collector_log_group,
                        "awslogs-stream-prefix": "otel-collector",
                    },
                },
                "healthCheck": {
                    "command": ["CMD", "/healthcheck"],
                    "interval": 30,
                    "timeout": 5,
                    "retries": 3,
                    "startPeriod": 30,
                },
            }
            if otel_collector_cpu > 0:
                collector_container["cpu"] = otel_collector_cpu
            if otel_collector_memory > 0:
                collector_container["memoryReservation"] = otel_collector_memory
        bootstrap_containers = []
        if source_runtime_bootstrap_payload or bootstrap_environment_file_arn or enable_source_runtime_bootstrap:
            bootstrap_container = {
                "name": "source-runtime-bootstrap",
                "image": container_image,
                "essential": False,
                "user": "10001",
                "readonlyRootFilesystem": True,
                "command": [
                    "source-runtime",
                    "bootstrap",
                    "env=CEREBRO_SOURCE_RUNTIME_BOOTSTRAP_JSON",
                ],
                "environment": env,
                "secrets": secret_env,
                "logConfiguration": {
                    "logDriver": "awslogs",
                    "options": {**log_options, "awslogs-stream-prefix": "source-runtime-bootstrap"},
                },
            }
            if collector_container:
                bootstrap_container["dependsOn"] = [{"containerName": "otel-collector", "condition": "HEALTHY"}]
            if bootstrap_environment_file_arn:
                bootstrap_container["environmentFiles"] = [
                    {"value": bootstrap_environment_file_arn, "type": "s3"}
                ]
            elif source_runtime_bootstrap_payload:
                bootstrap_container["environment"] = [
                    *env,
                    {
                        "name": "CEREBRO_SOURCE_RUNTIME_BOOTSTRAP_JSON",
                        "value": source_runtime_bootstrap_payload,
                    },
                ]
            bootstrap_containers.append(bootstrap_container)
        container = {
            "name": "cerebro",
            "image": container_image,
            "essential": True,
            "user": "10001",
            "readonlyRootFilesystem": True,
            "logConfiguration": {
                "logDriver": "awslogs",
                "options": {**log_options, "awslogs-stream-prefix": log_stream_prefix},
            },
            "environment": env,
            "secrets": secret_env,
        }
        container_dependencies = []
        if collector_container:
            container_dependencies.append({"containerName": "otel-collector", "condition": "HEALTHY"})
        if bootstrap_containers:
            container_dependencies.extend(
                {"containerName": bootstrap["name"], "condition": "SUCCESS"}
                for bootstrap in bootstrap_containers
            )
        if container_dependencies:
            container["dependsOn"] = container_dependencies
        if container_command:
            container["command"] = container_command
        if expose_http:
            container["portMappings"] = [{"containerPort": 8080, "protocol": "tcp"}]
        if enable_health_check:
            container["healthCheck"] = {
                "command": ["CMD-SHELL", "wget -qO- http://localhost:8080/health >/dev/null || exit 1"],
                "interval": 30,
                "timeout": 60,
                "retries": 3,
                "startPeriod": 60,
            }
        if efs_container_path:
            container["mountPoints"] = [{"sourceVolume": "cerebro-data", "containerPath": efs_container_path, "readOnly": False}]
        return [*([collector_container] if collector_container else []), *bootstrap_containers, container]

    container_definitions = pulumi.Output.all(
        log_group_name,
        otel_collector_log_group_name or log_group_name,
        source_runtime_bootstrap_environment_file_arn or "",
        *env_values,
    ).apply(lambda args: json.dumps(build_container_def(args)))

    volumes = None
    if efs_file_system_id is not None and efs_access_point_id is not None:
        volumes = [aws.ecs.TaskDefinitionVolumeArgs(
            name="cerebro-data",
            efs_volume_configuration=aws.ecs.TaskDefinitionVolumeEfsVolumeConfigurationArgs(
                file_system_id=efs_file_system_id,
                transit_encryption="ENABLED",
                authorization_config=aws.ecs.TaskDefinitionVolumeEfsVolumeConfigurationAuthorizationConfigArgs(
                    access_point_id=efs_access_point_id,
                    iam="ENABLED",
                ),
            ),
        )]

    return aws.ecs.TaskDefinition(
        f"{name}-task",
        family=name,
        cpu=str(cpu),
        memory=str(memory),
        network_mode="awsvpc",
        requires_compatibilities=["FARGATE"],
        runtime_platform=aws.ecs.TaskDefinitionRuntimePlatformArgs(
            operating_system_family="LINUX",
            cpu_architecture="ARM64",
        ),
        execution_role_arn=execution_role_arn,
        task_role_arn=task_role_arn,
        container_definitions=container_definitions,
        volumes=volumes,
        tags={"Name": f"{name}-task"},
        opts=pulumi.ResourceOptions(depends_on=depends_on) if depends_on else None,
    )


def _source_runtime_bootstrap_payload(source_runtimes: list[dict]) -> str:
    specs = [_source_runtime_spec(runtime) for runtime in source_runtimes]
    if not specs:
        return ""
    return json.dumps({"runtimes": specs}, sort_keys=True, separators=(",", ":"))


def _source_runtime_spec(runtime: dict) -> dict:
    runtime_id = _runtime_field(runtime, "id")
    source_id = _runtime_field(runtime, "sourceId", "source_id")
    if not runtime_id or not source_id:
        raise ValueError("source runtime id and sourceId are required")
    spec = {
        "id": runtime_id,
        "source_id": source_id,
        "config": {},
    }
    tenant_id = _runtime_field(runtime, "tenantId", "tenant_id")
    if tenant_id:
        spec["tenant_id"] = tenant_id
    runtime_config = runtime.get("config") or {}
    if not isinstance(runtime_config, dict):
        raise ValueError(f"source runtime {runtime_id} config must be an object")
    for key in sorted(runtime_config):
        config_key = str(key).strip()
        if not config_key:
            raise ValueError(f"source runtime {runtime_id} config key must be non-empty")
        value = str(runtime_config[key]).strip()
        if _sensitive_source_config_key(config_key) and value and not value.startswith("env:"):
            raise ValueError(f"source runtime {runtime_id} config {key} must use env:VAR")
        spec["config"][config_key] = value
    return spec


def _runtime_field(runtime: dict, *keys: str) -> str:
    for key in keys:
        value = str(runtime.get(key, "")).strip()
        if value:
            return value
    return ""


def _sensitive_source_config_key(key: str) -> bool:
    value = str(key).strip().lower()
    compact = value.replace("_", "").replace("-", "").replace(".", "")
    return (
        "token" in value
        or "secret" in value
        or "password" in value
        or "apikey" in compact
        or "privatekey" in compact
        or value == "key"
        or compact == "key"
    )
