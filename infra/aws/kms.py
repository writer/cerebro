"""
AWS KMS key management.
"""

import json

import pulumi_aws as aws


def create_kms_key(name: str, description: str) -> aws.kms.Key:
    """Create KMS key for encryption."""
    return aws.kms.Key(
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
                        "Principal": {"AWS": f"arn:aws:iam::{aws.get_caller_identity().account_id}:root"},
                        "Action": "kms:*",
                        "Resource": "*",
                    },
                    {
                        "Sid": "Allow ECS to use the key",
                        "Effect": "Allow",
                        "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                        "Action": ["kms:Decrypt", "kms:GenerateDataKey"],
                        "Resource": "*",
                    },
                ],
            }
        ),
        tags={"Name": name},
    )
