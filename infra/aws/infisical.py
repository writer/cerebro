"""Infisical integration for AWS Secrets Manager sync."""

from typing import Optional

import pulumi
import pulumi_aws as aws


def create_infisical_sync_role(
    name: str,
    assume_role_principal_arn: str,
    external_id: Optional[str] = None,
    kms_key_arn: pulumi.Output = None,
) -> dict:
    """
    Create IAM role for Infisical to sync secrets to AWS Secrets Manager.
    
    Args:
        name: Resource name prefix
        assume_role_principal_arn: ARN of Infisical's AWS principal
        external_id: Optional external ID for additional security
        kms_key_arn: KMS key ARN for encryption (required for production use)
    
    Returns:
        Dict with role and policy resources
    
    Raises:
        ValueError: If kms_key_arn is not provided
    """
    if not kms_key_arn:
        raise ValueError("kms_key_arn is required for Infisical sync role - wildcard KMS access is not allowed")
    role_name = f"{name}-infisical-sync"
    
    # Build trust policy
    trust_statement = {
        "Effect": "Allow",
        "Principal": {"AWS": assume_role_principal_arn},
        "Action": "sts:AssumeRole",
    }
    if external_id:
        trust_statement["Condition"] = {
            "StringEquals": {"sts:ExternalId": external_id}
        }
    
    assume_role_policy = {
        "Version": "2012-10-17",
        "Statement": [trust_statement],
    }
    
    role = aws.iam.Role(
        f"{name}-infisical-sync-role",
        name=role_name,
        assume_role_policy=pulumi.Output.json_dumps(assume_role_policy),
        tags={
            "Name": role_name,
            "Purpose": "Infisical Secrets Manager Sync",
            "ManagedBy": "pulumi",
        },
    )
    
    # Get account info for policy
    caller = aws.get_caller_identity()
    region = aws.get_region()
    
    # Build permissions policy
    policy_statements = [
        {
            "Sid": "ListSecrets",
            "Effect": "Allow",
            "Action": [
                "secretsmanager:ListSecrets",
                "secretsmanager:BatchGetSecretValue",
            ],
            "Resource": "*",
        },
        {
            "Sid": "ManageSecrets",
            "Effect": "Allow",
            "Action": [
                "secretsmanager:GetSecretValue",
                "secretsmanager:CreateSecret",
                "secretsmanager:UpdateSecret",
                "secretsmanager:DeleteSecret",
                "secretsmanager:DescribeSecret",
                "secretsmanager:TagResource",
                "secretsmanager:UntagResource",
            ],
            "Resource": f"arn:aws:secretsmanager:{region.region}:{caller.account_id}:secret:{name}/*",
        },
        {
            "Sid": "ListKMSAliases",
            "Effect": "Allow",
            "Action": "kms:ListAliases",
            "Resource": "*",
        },
    ]
    
    # Build policy with KMS key (required, validated above)
    policy_json = kms_key_arn.apply(
        lambda arn: pulumi.Output.json_dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ListSecrets",
                    "Effect": "Allow",
                    "Action": [
                        "secretsmanager:ListSecrets",
                        "secretsmanager:BatchGetSecretValue",
                    ],
                    "Resource": "*",
                },
                {
                    "Sid": "ManageSecrets",
                    "Effect": "Allow",
                    "Action": [
                        "secretsmanager:GetSecretValue",
                        "secretsmanager:CreateSecret",
                        "secretsmanager:UpdateSecret",
                        "secretsmanager:DeleteSecret",
                        "secretsmanager:DescribeSecret",
                        "secretsmanager:TagResource",
                        "secretsmanager:UntagResource",
                    ],
                    "Resource": f"arn:aws:secretsmanager:{region.region}:{caller.account_id}:secret:{name}/*",
                },
                {
                    "Sid": "ListKMSAliases",
                    "Effect": "Allow",
                    "Action": "kms:ListAliases",
                    "Resource": "*",
                },
                {
                    "Sid": "KMSPermissions",
                    "Effect": "Allow",
                    "Action": [
                        "kms:Encrypt",
                        "kms:Decrypt",
                        "kms:DescribeKey",
                        "kms:GenerateDataKey",
                    ],
                    "Resource": arn,
                },
            ],
        })
    )
    
    policy = aws.iam.RolePolicy(
        f"{name}-infisical-sync-policy",
        role=role.name,
        policy=policy_json,
    )
    
    return {
        "role": role,
        "role_arn": role.arn,
        "role_name": role.name,
        "policy": policy,
    }
