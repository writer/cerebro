"""
AWS DynamoDB infrastructure for Cerebro.

Creates:
- cerebro-core: Single-table design for orgs, accounts, principals, resources, findings, rules
- cerebro-audit: Time-series table for audit events and config snapshots
- cerebro-agents: Agent sessions, messages, tool invocations, review tasks
- cerebro-notifications: Notification configs and delivery logs
"""
import pulumi
import pulumi_aws as aws
from typing import Optional


def create_dynamodb_tables(
    name: str,
    environment: str,
    kms_key_arn: Optional[pulumi.Output[str]] = None,
    enable_point_in_time_recovery: bool = True,
    enable_streams: bool = True,
    audit_ttl_enabled: bool = True,
    tags: Optional[dict] = None,
) -> dict:
    """
    Create all DynamoDB tables for Cerebro.

    Args:
        name: Base name for tables (e.g., "cerebro")
        environment: Environment name (e.g., "production", "staging")
        kms_key_arn: KMS key ARN for encryption (uses AWS-managed key if None)
        enable_point_in_time_recovery: Enable PITR for all tables
        enable_streams: Enable DynamoDB Streams for change data capture
        audit_ttl_enabled: Enable TTL on audit table for automatic expiration
        tags: Additional tags to apply to all resources

    Returns:
        Dictionary with table resources and metadata
    """
    base_tags = {
        "Environment": environment,
        "ManagedBy": "Pulumi",
        "Application": "Cerebro",
    }
    if tags:
        base_tags.update(tags)

    tables = {}

    # =========================================================================
    # Table 1: cerebro-core (Single-Table Design)
    # =========================================================================
    # Stores: Organizations, Accounts, Principals, Resources, Findings, Rules,
    #         Policies, Suppressions, IAM Edges, Identity Clusters
    #
    # Key Design:
    #   PK: ORG#<org_id>, ACCT#<account_id>, PRIN#<principal_id>, etc.
    #   SK: META, ACCT#<id>, PRIN#<id>, RES#<id>, FIND#<id>, etc.
    #
    # GSI1: Cross-entity lookups (e.g., get all findings for an account)
    # GSI2: Status/type filtering (e.g., findings by status+severity)
    # GSI3: External ID lookups (e.g., find principal by email)
    # =========================================================================

    core_table = aws.dynamodb.Table(
        f"{name}-core-table",
        name=f"{name}-core-{environment}",
        billing_mode="PAY_PER_REQUEST",
        hash_key="PK",
        range_key="SK",
        attributes=[
            aws.dynamodb.TableAttributeArgs(name="PK", type="S"),
            aws.dynamodb.TableAttributeArgs(name="SK", type="S"),
            aws.dynamodb.TableAttributeArgs(name="GSI1PK", type="S"),
            aws.dynamodb.TableAttributeArgs(name="GSI1SK", type="S"),
            aws.dynamodb.TableAttributeArgs(name="GSI2PK", type="S"),
            aws.dynamodb.TableAttributeArgs(name="GSI2SK", type="S"),
            aws.dynamodb.TableAttributeArgs(name="GSI3PK", type="S"),
            aws.dynamodb.TableAttributeArgs(name="GSI3SK", type="S"),
        ],
        global_secondary_indexes=[
            aws.dynamodb.TableGlobalSecondaryIndexArgs(
                name="GSI1",
                hash_key="GSI1PK",
                range_key="GSI1SK",
                projection_type="ALL",
            ),
            aws.dynamodb.TableGlobalSecondaryIndexArgs(
                name="GSI2",
                hash_key="GSI2PK",
                range_key="GSI2SK",
                projection_type="ALL",
            ),
            aws.dynamodb.TableGlobalSecondaryIndexArgs(
                name="GSI3",
                hash_key="GSI3PK",
                range_key="GSI3SK",
                projection_type="ALL",
            ),
        ],
        point_in_time_recovery=aws.dynamodb.TablePointInTimeRecoveryArgs(
            enabled=enable_point_in_time_recovery,
        ),
        server_side_encryption=aws.dynamodb.TableServerSideEncryptionArgs(
            enabled=True,
            kms_key_arn=kms_key_arn,
        ),
        stream_enabled=enable_streams,
        stream_view_type="NEW_AND_OLD_IMAGES" if enable_streams else None,
        deletion_protection_enabled=environment == "production",
        tags=base_tags,
    )
    tables["core"] = core_table

    # =========================================================================
    # Table 2: cerebro-audit (Time-Series)
    # =========================================================================
    # Stores: Audit Events, Config Snapshots, Frontend Observation Events
    #
    # Key Design:
    #   PK: ACCT#<account_id> or RES#<resource_id>
    #   SK: EVENT#<timestamp>#<event_id> or SNAP#<timestamp>#<snapshot_id>
    #
    # GSI1: Provider+action filtering for audit events
    #
    # TTL: expires_at field for automatic data retention
    # =========================================================================

    audit_table = aws.dynamodb.Table(
        f"{name}-audit-table",
        name=f"{name}-audit-{environment}",
        billing_mode="PAY_PER_REQUEST",
        hash_key="PK",
        range_key="SK",
        attributes=[
            aws.dynamodb.TableAttributeArgs(name="PK", type="S"),
            aws.dynamodb.TableAttributeArgs(name="SK", type="S"),
            aws.dynamodb.TableAttributeArgs(name="GSI1PK", type="S"),
            aws.dynamodb.TableAttributeArgs(name="GSI1SK", type="S"),
        ],
        global_secondary_indexes=[
            aws.dynamodb.TableGlobalSecondaryIndexArgs(
                name="GSI1",
                hash_key="GSI1PK",
                range_key="GSI1SK",
                projection_type="ALL",
            ),
        ],
        ttl=aws.dynamodb.TableTtlArgs(
            attribute_name="expires_at",
            enabled=audit_ttl_enabled,
        ),
        point_in_time_recovery=aws.dynamodb.TablePointInTimeRecoveryArgs(
            enabled=enable_point_in_time_recovery,
        ),
        server_side_encryption=aws.dynamodb.TableServerSideEncryptionArgs(
            enabled=True,
            kms_key_arn=kms_key_arn,
        ),
        stream_enabled=enable_streams,
        stream_view_type="NEW_AND_OLD_IMAGES" if enable_streams else None,
        deletion_protection_enabled=environment == "production",
        tags=base_tags,
    )
    tables["audit"] = audit_table

    # =========================================================================
    # Table 3: cerebro-agents
    # =========================================================================
    # Stores: Agent Sessions, Messages, Conversation Items, Memory Entries,
    #         Tool Invocations, Approvals, Review Tasks, Recommendations
    #
    # Key Design:
    #   PK: ORG#<org_id> or SESSION#<session_id>
    #   SK: SESSION#<id>, MSG#<timestamp>#<id>, TOOL#<timestamp>#<id>, etc.
    #
    # GSI1: User-based lookups, tool name filtering
    # GSI2: Status filtering for review tasks
    # =========================================================================

    agents_table = aws.dynamodb.Table(
        f"{name}-agents-table",
        name=f"{name}-agents-{environment}",
        billing_mode="PAY_PER_REQUEST",
        hash_key="PK",
        range_key="SK",
        attributes=[
            aws.dynamodb.TableAttributeArgs(name="PK", type="S"),
            aws.dynamodb.TableAttributeArgs(name="SK", type="S"),
            aws.dynamodb.TableAttributeArgs(name="GSI1PK", type="S"),
            aws.dynamodb.TableAttributeArgs(name="GSI1SK", type="S"),
            aws.dynamodb.TableAttributeArgs(name="GSI2PK", type="S"),
            aws.dynamodb.TableAttributeArgs(name="GSI2SK", type="S"),
        ],
        global_secondary_indexes=[
            aws.dynamodb.TableGlobalSecondaryIndexArgs(
                name="GSI1",
                hash_key="GSI1PK",
                range_key="GSI1SK",
                projection_type="ALL",
            ),
            aws.dynamodb.TableGlobalSecondaryIndexArgs(
                name="GSI2",
                hash_key="GSI2PK",
                range_key="GSI2SK",
                projection_type="ALL",
            ),
        ],
        point_in_time_recovery=aws.dynamodb.TablePointInTimeRecoveryArgs(
            enabled=enable_point_in_time_recovery,
        ),
        server_side_encryption=aws.dynamodb.TableServerSideEncryptionArgs(
            enabled=True,
            kms_key_arn=kms_key_arn,
        ),
        stream_enabled=enable_streams,
        stream_view_type="NEW_AND_OLD_IMAGES" if enable_streams else None,
        deletion_protection_enabled=environment == "production",
        tags=base_tags,
    )
    tables["agents"] = agents_table

    # =========================================================================
    # Table 4: cerebro-notifications
    # =========================================================================
    # Stores: Slack Webhooks, Email Configs, Webhook Configs,
    #         Slack/Email/Webhook Notifications (delivery logs)
    #
    # Key Design:
    #   PK: ORG#<org_id> or WEBHOOK#<webhook_id> or CONFIG#<config_id>
    #   SK: SLACK#<id>, EMAIL#<id>, NOTIF#<timestamp>#<id>, etc.
    #
    # GSI1: Org-based notification lookups
    # =========================================================================

    notifications_table = aws.dynamodb.Table(
        f"{name}-notifications-table",
        name=f"{name}-notifications-{environment}",
        billing_mode="PAY_PER_REQUEST",
        hash_key="PK",
        range_key="SK",
        attributes=[
            aws.dynamodb.TableAttributeArgs(name="PK", type="S"),
            aws.dynamodb.TableAttributeArgs(name="SK", type="S"),
            aws.dynamodb.TableAttributeArgs(name="GSI1PK", type="S"),
            aws.dynamodb.TableAttributeArgs(name="GSI1SK", type="S"),
        ],
        global_secondary_indexes=[
            aws.dynamodb.TableGlobalSecondaryIndexArgs(
                name="GSI1",
                hash_key="GSI1PK",
                range_key="GSI1SK",
                projection_type="ALL",
            ),
        ],
        point_in_time_recovery=aws.dynamodb.TablePointInTimeRecoveryArgs(
            enabled=enable_point_in_time_recovery,
        ),
        server_side_encryption=aws.dynamodb.TableServerSideEncryptionArgs(
            enabled=True,
            kms_key_arn=kms_key_arn,
        ),
        stream_enabled=enable_streams,
        stream_view_type="NEW_AND_OLD_IMAGES" if enable_streams else None,
        deletion_protection_enabled=environment == "production",
        tags=base_tags,
    )
    tables["notifications"] = notifications_table

    # =========================================================================
    # Table 5: cerebro-users (Auth/Identity)
    # =========================================================================
    # Stores: Users, Refresh Tokens, API Keys, Serval Integrations
    #
    # Key Design:
    #   PK: ORG#<org_id> or USER#<user_id>
    #   SK: USER#<id>, TOKEN#<id>, APIKEY#<id>, SERVAL#<id>
    #
    # GSI1: Email lookups for authentication
    # =========================================================================

    users_table = aws.dynamodb.Table(
        f"{name}-users-table",
        name=f"{name}-users-{environment}",
        billing_mode="PAY_PER_REQUEST",
        hash_key="PK",
        range_key="SK",
        attributes=[
            aws.dynamodb.TableAttributeArgs(name="PK", type="S"),
            aws.dynamodb.TableAttributeArgs(name="SK", type="S"),
            aws.dynamodb.TableAttributeArgs(name="GSI1PK", type="S"),
            aws.dynamodb.TableAttributeArgs(name="GSI1SK", type="S"),
        ],
        global_secondary_indexes=[
            aws.dynamodb.TableGlobalSecondaryIndexArgs(
                name="GSI1",
                hash_key="GSI1PK",
                range_key="GSI1SK",
                projection_type="ALL",
            ),
        ],
        point_in_time_recovery=aws.dynamodb.TablePointInTimeRecoveryArgs(
            enabled=enable_point_in_time_recovery,
        ),
        server_side_encryption=aws.dynamodb.TableServerSideEncryptionArgs(
            enabled=True,
            kms_key_arn=kms_key_arn,
        ),
        stream_enabled=enable_streams,
        stream_view_type="NEW_AND_OLD_IMAGES" if enable_streams else None,
        deletion_protection_enabled=environment == "production",
        tags=base_tags,
    )
    tables["users"] = users_table

    return {
        "tables": tables,
        "core_table": core_table,
        "core_table_name": core_table.name,
        "core_table_arn": core_table.arn,
        "core_stream_arn": core_table.stream_arn if enable_streams else None,
        "audit_table": audit_table,
        "audit_table_name": audit_table.name,
        "audit_table_arn": audit_table.arn,
        "audit_stream_arn": audit_table.stream_arn if enable_streams else None,
        "agents_table": agents_table,
        "agents_table_name": agents_table.name,
        "agents_table_arn": agents_table.arn,
        "agents_stream_arn": agents_table.stream_arn if enable_streams else None,
        "notifications_table": notifications_table,
        "notifications_table_name": notifications_table.name,
        "notifications_table_arn": notifications_table.arn,
        "notifications_stream_arn": notifications_table.stream_arn if enable_streams else None,
        "users_table": users_table,
        "users_table_name": users_table.name,
        "users_table_arn": users_table.arn,
        "users_stream_arn": users_table.stream_arn if enable_streams else None,
    }


def create_dynamodb_iam_policy(
    name: str,
    table_arns: list[pulumi.Output[str]],
    kms_key_arn: Optional[pulumi.Output[str]] = None,
    read_only: bool = False,
) -> aws.iam.Policy:
    """
    Create an IAM policy for DynamoDB access.

    Args:
        name: Policy name
        table_arns: List of DynamoDB table ARNs to grant access to
        kms_key_arn: KMS key ARN if tables use CMK encryption
        read_only: If True, only grant read permissions

    Returns:
        IAM Policy resource
    """
    if read_only:
        actions = [
            "dynamodb:GetItem",
            "dynamodb:BatchGetItem",
            "dynamodb:Query",
            "dynamodb:Scan",
            "dynamodb:DescribeTable",
        ]
    else:
        actions = [
            "dynamodb:GetItem",
            "dynamodb:PutItem",
            "dynamodb:UpdateItem",
            "dynamodb:DeleteItem",
            "dynamodb:BatchGetItem",
            "dynamodb:BatchWriteItem",
            "dynamodb:Query",
            "dynamodb:Scan",
            "dynamodb:TransactGetItems",
            "dynamodb:TransactWriteItems",
            "dynamodb:DescribeTable",
            "dynamodb:DescribeStream",
            "dynamodb:GetRecords",
            "dynamodb:GetShardIterator",
        ]

    statements = [
        {
            "Sid": "DynamoDBTableAccess",
            "Effect": "Allow",
            "Action": actions,
            "Resource": [
                *table_arns,
                *[pulumi.Output.concat(arn, "/index/*") for arn in table_arns],
            ],
        },
    ]

    if not read_only:
        statements.append({
            "Sid": "DynamoDBStreamAccess",
            "Effect": "Allow",
            "Action": [
                "dynamodb:DescribeStream",
                "dynamodb:GetRecords",
                "dynamodb:GetShardIterator",
                "dynamodb:ListStreams",
            ],
            "Resource": [
                pulumi.Output.concat(arn, "/stream/*") for arn in table_arns
            ],
        })

    if kms_key_arn:
        statements.append({
            "Sid": "KMSAccess",
            "Effect": "Allow",
            "Action": [
                "kms:Decrypt",
                "kms:GenerateDataKey",
                "kms:DescribeKey",
            ],
            "Resource": kms_key_arn,
        })

    policy_document = pulumi.Output.all(*table_arns).apply(
        lambda arns: {
            "Version": "2012-10-17",
            "Statement": statements,
        }
    )

    return aws.iam.Policy(
        f"{name}-dynamodb-policy",
        name=f"{name}-dynamodb-access",
        policy=policy_document.apply(lambda doc: pulumi.Output.json_dumps(doc)),
    )


def create_streams_lambda(
    name: str,
    stream_arn: pulumi.Output[str],
    handler_code: str,
    environment_variables: Optional[dict] = None,
    timeout: int = 60,
    memory_size: int = 256,
) -> dict:
    """
    Create a Lambda function to process DynamoDB Streams.

    Args:
        name: Function name
        stream_arn: DynamoDB Stream ARN to process
        handler_code: Python handler code
        environment_variables: Environment variables for the function
        timeout: Function timeout in seconds
        memory_size: Function memory in MB

    Returns:
        Dictionary with Lambda resources
    """
    lambda_role = aws.iam.Role(
        f"{name}-lambda-role",
        assume_role_policy="""{
            "Version": "2012-10-17",
            "Statement": [{
                "Action": "sts:AssumeRole",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Effect": "Allow"
            }]
        }""",
    )

    aws.iam.RolePolicyAttachment(
        f"{name}-lambda-basic",
        role=lambda_role.name,
        policy_arn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )

    aws.iam.RolePolicyAttachment(
        f"{name}-lambda-dynamodb",
        role=lambda_role.name,
        policy_arn="arn:aws:iam::aws:policy/service-role/AWSLambdaDynamoDBExecutionRole",
    )

    lambda_function = aws.lambda_.Function(
        f"{name}-lambda",
        name=name,
        role=lambda_role.arn,
        runtime="python3.11",
        handler="index.handler",
        code=pulumi.AssetArchive({
            "index.py": pulumi.StringAsset(handler_code),
        }),
        timeout=timeout,
        memory_size=memory_size,
        environment=aws.lambda_.FunctionEnvironmentArgs(
            variables=environment_variables or {},
        ),
    )

    event_source_mapping = aws.lambda_.EventSourceMapping(
        f"{name}-stream-mapping",
        event_source_arn=stream_arn,
        function_name=lambda_function.name,
        starting_position="LATEST",
        batch_size=100,
        maximum_batching_window_in_seconds=5,
    )

    return {
        "role": lambda_role,
        "function": lambda_function,
        "event_source_mapping": event_source_mapping,
    }
