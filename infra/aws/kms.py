"""
AWS KMS key management for encryption at rest.

Creates customer-managed KMS keys for encrypting:
- RDS databases
- ElastiCache clusters
- Secrets Manager secrets
- EBS volumes
- CloudWatch Logs
- S3 buckets
"""

import pulumi
import pulumi_aws as aws


def create_kms_key(
    name: str,
    description: str,
    enable_key_rotation: bool = True,
    deletion_window_in_days: int = 30,
    tags: dict[str, str] | None = None,
) -> aws.kms.Key:
    """
    Create a customer-managed KMS key.

    Args:
        name: Key name/alias prefix
        description: Key description
        enable_key_rotation: Enable automatic annual key rotation
        deletion_window_in_days: Waiting period before key deletion (7-30 days)

    Returns:
        KMS Key resource
    """
    resource_tags = tags or {}

    # Create KMS key
    key = aws.kms.Key(
        f"{name}-kms-key",
        description=description,
        enable_key_rotation=enable_key_rotation,
        deletion_window_in_days=deletion_window_in_days,
        tags={
            **resource_tags,
            "Name": f"{name}-kms-key",
            "ManagedBy": "Pulumi",
        },
    )

    # Create key alias for easier reference
    aws.kms.Alias(
        f"{name}-kms-alias",
        name=f"alias/{name}",
        target_key_id=key.id,
    )

    return key


def create_key_policy(
    name: str,
    key_id: pulumi.Output[str],
    admin_arns: list[str] = None,
    user_arns: list[str] = None,
) -> aws.kms.KeyPolicy:
    """
    Create a KMS key policy with admin and user permissions.

    Args:
        name: Policy name prefix
        key_id: KMS key ID
        admin_arns: List of ARNs with admin permissions
        user_arns: List of ARNs with encrypt/decrypt permissions

    Returns:
        KMS Key Policy resource
    """
    import json

    # Get current AWS account and region
    current = aws.get_caller_identity()
    region = aws.get_region()

    # Default to account root if no admins specified
    if admin_arns is None:
        admin_arns = [f"arn:aws:iam::{current.account_id}:root"]

    if user_arns is None:
        user_arns = []

    # Build policy document
    policy_statements = [
        # Enable IAM policies
        {
            "Sid": "Enable IAM User Permissions",
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{current.account_id}:root"},
            "Action": "kms:*",
            "Resource": "*",
        },
        # Key administrators
        {
            "Sid": "Allow administration of the key",
            "Effect": "Allow",
            "Principal": {"AWS": admin_arns},
            "Action": [
                "kms:Create*",
                "kms:Describe*",
                "kms:Enable*",
                "kms:List*",
                "kms:Put*",
                "kms:Update*",
                "kms:Revoke*",
                "kms:Disable*",
                "kms:Get*",
                "kms:Delete*",
                "kms:TagResource",
                "kms:UntagResource",
                "kms:ScheduleKeyDeletion",
                "kms:CancelKeyDeletion",
            ],
            "Resource": "*",
        },
    ]

    # Add user permissions if specified
    if user_arns:
        policy_statements.append(
            {
                "Sid": "Allow use of the key",
                "Effect": "Allow",
                "Principal": {"AWS": user_arns},
                "Action": [
                    "kms:Encrypt",
                    "kms:Decrypt",
                    "kms:ReEncrypt*",
                    "kms:GenerateDataKey*",
                    "kms:DescribeKey",
                ],
                "Resource": "*",
            }
        )

    policy_doc = {"Version": "2012-10-17", "Statement": policy_statements}

    return aws.kms.KeyPolicy(
        f"{name}-kms-policy",
        key_id=key_id,
        policy=json.dumps(policy_doc),
    )


def create_cloudwatch_logs_key(
    name: str,
    tags: dict[str, str] | None = None,
) -> dict[str, aws.kms.Key | aws.kms.Alias]:
    """
    Create a KMS key specifically for CloudWatch Logs encryption.

    The key policy allows the CloudWatch Logs service to use the key.

    Args:
        name: Key name prefix
        tags: Resource tags

    Returns:
        Dictionary containing key and alias
    """
    resource_tags = tags or {}

    # Get AWS account ID and region
    caller_identity = aws.get_caller_identity()
    region = aws.get_region()

    key = aws.kms.Key(
        f"{name}-cloudwatch-logs-key",
        description=f"KMS key for CloudWatch Logs encryption - {name}",
        enable_key_rotation=True,
        policy=pulumi.Output.all(
            account_id=caller_identity.account_id,
            region_name=region.name,
        ).apply(
            lambda args: pulumi.Output.json_dumps(
                {
                    "Version": "2012-10-17",
                    "Id": "cloudwatch-logs-key-policy",
                    "Statement": [
                        {
                            "Sid": "Enable IAM User Permissions",
                            "Effect": "Allow",
                            "Principal": {
                                "AWS": f"arn:aws:iam::{args['account_id']}:root"
                            },
                            "Action": "kms:*",
                            "Resource": "*",
                        },
                        {
                            "Sid": "Allow CloudWatch Logs",
                            "Effect": "Allow",
                            "Principal": {
                                "Service": f"logs.{args['region_name']}.amazonaws.com"
                            },
                            "Action": [
                                "kms:Encrypt",
                                "kms:Decrypt",
                                "kms:ReEncrypt*",
                                "kms:GenerateDataKey*",
                                "kms:DescribeKey",
                            ],
                            "Resource": "*",
                            "Condition": {
                                "ArnLike": {
                                    "kms:EncryptionContext:aws:logs:arn": f"arn:aws:logs:{args['region_name']}:{args['account_id']}:*"
                                }
                            },
                        },
                    ],
                }
            )
        ),
        tags={
            **resource_tags,
            "Name": f"{name}-cloudwatch-logs-key",
        },
    )

    alias = aws.kms.Alias(
        f"{name}-cloudwatch-logs-key-alias",
        name=f"alias/{name}/cloudwatch-logs",
        target_key_id=key.key_id,
    )

    return {"key": key, "alias": alias}


def create_s3_key(
    name: str,
    tags: dict[str, str] | None = None,
) -> dict[str, aws.kms.Key | aws.kms.Alias]:
    """
    Create a KMS key specifically for S3 bucket encryption.

    Args:
        name: Key name prefix
        tags: Resource tags

    Returns:
        Dictionary containing key and alias
    """
    resource_tags = tags or {}

    # Get AWS account ID
    caller_identity = aws.get_caller_identity()

    key = aws.kms.Key(
        f"{name}-s3-key",
        description=f"KMS key for S3 bucket encryption - {name}",
        enable_key_rotation=True,
        policy=pulumi.Output.from_input(caller_identity.account_id).apply(
            lambda account_id: pulumi.Output.json_dumps(
                {
                    "Version": "2012-10-17",
                    "Id": "s3-key-policy",
                    "Statement": [
                        {
                            "Sid": "Enable IAM User Permissions",
                            "Effect": "Allow",
                            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                            "Action": "kms:*",
                            "Resource": "*",
                        }
                    ],
                }
            )
        ),
        tags={
            **resource_tags,
            "Name": f"{name}-s3-key",
        },
    )

    alias = aws.kms.Alias(
        f"{name}-s3-key-alias",
        name=f"alias/{name}/s3",
        target_key_id=key.key_id,
    )

    return {"key": key, "alias": alias}
