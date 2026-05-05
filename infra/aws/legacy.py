"""
Transitional resources for retiring pre-rewrite infrastructure safely.
"""

import pulumi
import pulumi_aws as aws


def retain_jobs_table_without_deletion_protection(
    name: str,
    kms_key_arn: pulumi.Output[str],
) -> aws.dynamodb.Table:
    """Keep the legacy jobs table in state long enough to disable AWS deletion protection."""
    return aws.dynamodb.Table(
        f"{name}-jobs-table",
        name=f"{name}-jobs",
        billing_mode="PAY_PER_REQUEST",
        hash_key="job_id",
        deletion_protection_enabled=False,
        attributes=[
            aws.dynamodb.TableAttributeArgs(name="job_id", type="S"),
            aws.dynamodb.TableAttributeArgs(name="group_id", type="S"),
            aws.dynamodb.TableAttributeArgs(name="status", type="S"),
            aws.dynamodb.TableAttributeArgs(name="lease_expires_at", type="N"),
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
            aws.dynamodb.TableGlobalSecondaryIndexArgs(
                name="status-lease-index",
                hash_key="status",
                range_key="lease_expires_at",
                projection_type="ALL",
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
