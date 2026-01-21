"""
AWS KMS key management.
"""

import json

import pulumi_aws as aws


def create_kms_key(name: str, description: str) -> dict:
    """
    Create KMS key for secrets/app data encryption.

    Key policy allows:
    - Account root for admin access
    - ECS tasks for decryption (via Secrets Manager)
    - Secrets Manager service for encryption
    - SQS service for encryption
    - DynamoDB service for encryption

    Returns:
        dict with key, key_id, key_arn, and alias
    """
    caller = aws.get_caller_identity()
    region = aws.get_region()

    key = aws.kms.Key(
        f"{name}-kms",
        description=description,
        deletion_window_in_days=30,
        enable_key_rotation=True,
        policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "Enable IAM User Permissions",
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{caller.account_id}:root"},
                        "Action": "kms:*",
                        "Resource": "*",
                    },
                    {
                        "Sid": "Allow Secrets Manager",
                        "Effect": "Allow",
                        "Principal": {"Service": "secretsmanager.amazonaws.com"},
                        "Action": [
                            "kms:Encrypt",
                            "kms:Decrypt",
                            "kms:ReEncrypt*",
                            "kms:GenerateDataKey*",
                            "kms:DescribeKey",
                        ],
                        "Resource": "*",
                        "Condition": {
                            "StringEquals": {
                                "kms:ViaService": f"secretsmanager.{region.region}.amazonaws.com",
                                "kms:CallerAccount": caller.account_id,
                            },
                        },
                    },
                    {
                        "Sid": "Allow SQS",
                        "Effect": "Allow",
                        "Principal": {"Service": "sqs.amazonaws.com"},
                        "Action": [
                            "kms:Encrypt",
                            "kms:Decrypt",
                            "kms:ReEncrypt*",
                            "kms:GenerateDataKey*",
                            "kms:DescribeKey",
                        ],
                        "Resource": "*",
                        "Condition": {
                            "StringEquals": {
                                "kms:ViaService": f"sqs.{region.region}.amazonaws.com",
                                "kms:CallerAccount": caller.account_id,
                            },
                        },
                    },
                    {
                        "Sid": "Allow DynamoDB",
                        "Effect": "Allow",
                        "Principal": {"Service": "dynamodb.amazonaws.com"},
                        "Action": [
                            "kms:Encrypt",
                            "kms:Decrypt",
                            "kms:ReEncrypt*",
                            "kms:GenerateDataKey*",
                            "kms:DescribeKey",
                        ],
                        "Resource": "*",
                        "Condition": {
                            "StringEquals": {
                                "kms:ViaService": f"dynamodb.{region.region}.amazonaws.com",
                                "kms:CallerAccount": caller.account_id,
                            },
                        },
                    },
                ],
            }
        ),
        tags={"Name": name},
    )

    alias = aws.kms.Alias(
        f"{name}-kms-alias",
        name=f"alias/{name}/primary",
        target_key_id=key.key_id,
    )

    return {
        "key": key,
        "key_id": key.key_id,
        "key_arn": key.arn,
        "alias": alias,
    }


def create_cloudwatch_logs_key(name: str) -> dict:
    """
    Create a customer-managed KMS key for CloudWatch Logs encryption.

    The key policy allows account admins and CloudWatch Logs service to use the key.
    """
    caller = aws.get_caller_identity()
    region = aws.get_region()

    key = aws.kms.Key(
        f"{name}-cloudwatch-logs-key",
        description=f"KMS key for CloudWatch Logs encryption - {name}",
        enable_key_rotation=True,
        deletion_window_in_days=30,
        policy=json.dumps({
            "Version": "2012-10-17",
            "Id": "cloudwatch-logs-key-policy",
            "Statement": [
                {
                    "Sid": "Enable IAM User Permissions",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": f"arn:aws:iam::{caller.account_id}:root",
                    },
                    "Action": "kms:*",
                    "Resource": "*",
                },
                {
                    "Sid": "Allow CloudWatch Logs",
                    "Effect": "Allow",
                    "Principal": {
                        "Service": f"logs.{region.region}.amazonaws.com",
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
                            "kms:EncryptionContext:aws:logs:arn": f"arn:aws:logs:{region.region}:{caller.account_id}:*",
                        },
                    },
                },
            ],
        }),
        tags={"Name": f"{name}-cloudwatch-logs-key"},
    )

    alias = aws.kms.Alias(
        f"{name}-cloudwatch-logs-key-alias",
        name=f"alias/{name}/cloudwatch-logs",
        target_key_id=key.key_id,
    )

    return {
        "key": key,
        "key_id": key.key_id,
        "key_arn": key.arn,
        "alias": alias,
    }
