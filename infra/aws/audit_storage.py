"""
S3 audit bucket for Cerebro bulk-closeout summaries.

The bucket stores per-run JSON summaries under the ``closeout/`` prefix and is
KMS-encrypted via the stack's existing runtime KMS key. Public access is fully
blocked. The task role receives a narrowly-scoped inline policy granting only
``s3:PutObject`` on the ``closeout/*`` prefix plus the KMS encrypt permissions
required to write objects to the bucket; no decrypt or delete permissions are
granted.
"""

import json

import pulumi
import pulumi_aws as aws


def create_audit_bucket(
    name: str,
    bucket_name: str,
    kms_key_arn: pulumi.Input[str],
    task_role: aws.iam.Role,
) -> dict:
    """Provision the closeout audit bucket plus its task-role grant.

    Args:
        name: Logical Pulumi resource-name prefix (e.g. ``cerebro-sec-dev``).
        bucket_name: Concrete S3 bucket name (e.g. ``cerebro-sec-dev-audit``).
        kms_key_arn: ARN of the existing stack KMS key to use for SSE.
        task_role: IAM role that will receive the inline closeout-writer policy.

    Returns dict with the created Pulumi resources and the KMS key ARN.
    """
    bucket = aws.s3.Bucket(
        f"{name}-audit-bucket",
        bucket=bucket_name,
        force_destroy=False,
        tags={"Name": bucket_name},
    )

    public_access_block = aws.s3.BucketPublicAccessBlock(
        f"{name}-audit-bucket-public-access",
        bucket=bucket.id,
        block_public_acls=True,
        block_public_policy=True,
        ignore_public_acls=True,
        restrict_public_buckets=True,
    )

    encryption = aws.s3.BucketServerSideEncryptionConfiguration(
        f"{name}-audit-bucket-sse",
        bucket=bucket.id,
        rules=[
            aws.s3.BucketServerSideEncryptionConfigurationRuleArgs(
                apply_server_side_encryption_by_default=aws.s3.BucketServerSideEncryptionConfigurationRuleApplyServerSideEncryptionByDefaultArgs(
                    sse_algorithm="aws:kms",
                    kms_master_key_id=kms_key_arn,
                ),
                bucket_key_enabled=True,
            )
        ],
    )

    closeout_object_arn = bucket.arn.apply(lambda arn: f"{arn}/closeout/*")

    role_policy = aws.iam.RolePolicy(
        f"{name}-audit-bucket-writer",
        name=f"{name}-audit-bucket-writer",
        role=task_role.name,
        policy=pulumi.Output.all(closeout_object_arn, kms_key_arn).apply(
            lambda args: json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "PutCloseoutAudit",
                            "Effect": "Allow",
                            "Action": ["s3:PutObject"],
                            "Resource": args[0],
                        },
                        {
                            "Sid": "EncryptCloseoutAuditWithKms",
                            "Effect": "Allow",
                            "Action": [
                                "kms:Encrypt",
                                "kms:GenerateDataKey",
                                "kms:DescribeKey",
                            ],
                            "Resource": args[1],
                        },
                    ],
                }
            )
        ),
    )

    return {
        "bucket": bucket,
        "public_access_block": public_access_block,
        "encryption": encryption,
        "role_policy": role_policy,
        "kms_key_arn": kms_key_arn,
    }
