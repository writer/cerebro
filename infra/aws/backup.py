"""
AWS Backup module for Cerebro.

Provides automated backup plans for databases and other resources.
"""

import pulumi
import pulumi_aws as aws


def create_backup_plan(
    name: str,
    resource_arns: list[pulumi.Input[str]],
    backup_retention_days: int = 35,
    backup_schedule: str = "cron(0 5 ? * * *)",
    copy_to_region: str | None = None,
    tags: dict[str, str] | None = None,
) -> dict[str, pulumi.Output]:
    """
    Create an AWS Backup plan with daily and weekly backup rules.

    Args:
        name: Resource name prefix
        resource_arns: List of resource ARNs to back up
        backup_retention_days: Days to retain daily backups (default: 35)
        backup_schedule: Cron schedule for daily backups (default: 5 AM UTC)
        copy_to_region: Optional region to copy backups for DR
        tags: Resource tags

    Returns:
        Dictionary containing backup resources
    """
    resource_tags = tags or {}

    # Backup vault
    vault = aws.backup.Vault(
        f"{name}-vault",
        name=f"{name}-vault",
        tags=resource_tags,
    )

    # Build backup rules
    rules = [
        aws.backup.PlanRuleArgs(
            rule_name="daily-backup",
            target_vault_name=vault.name,
            schedule=backup_schedule,
            lifecycle=aws.backup.PlanRuleLifecycleArgs(
                delete_after=backup_retention_days,
            ),
        ),
        aws.backup.PlanRuleArgs(
            rule_name="weekly-backup",
            target_vault_name=vault.name,
            schedule="cron(0 5 ? * SUN *)",  # 5 AM UTC every Sunday
            lifecycle=aws.backup.PlanRuleLifecycleArgs(
                cold_storage_after=30,
                delete_after=365,
            ),
        ),
    ]

    # Add cross-region copy if specified
    if copy_to_region:
        # Get account ID for destination vault ARN
        caller_identity = aws.get_caller_identity()
        destination_vault_arn = f"arn:aws:backup:{copy_to_region}:{caller_identity.account_id}:backup-vault:Default"

        rules[0] = aws.backup.PlanRuleArgs(
            rule_name="daily-backup",
            target_vault_name=vault.name,
            schedule=backup_schedule,
            lifecycle=aws.backup.PlanRuleLifecycleArgs(
                delete_after=backup_retention_days,
            ),
            copy_actions=[
                aws.backup.PlanRuleCopyActionArgs(
                    destination_vault_arn=destination_vault_arn,
                    lifecycle=aws.backup.PlanRuleCopyActionLifecycleArgs(
                        delete_after=backup_retention_days,
                    ),
                ),
            ],
        )

    # Backup plan
    plan = aws.backup.Plan(
        f"{name}-plan",
        name=f"{name}-plan",
        rules=rules,
        tags=resource_tags,
    )

    # IAM role for AWS Backup
    backup_role = aws.iam.Role(
        f"{name}-backup-role",
        name=f"{name}-backup-role",
        assume_role_policy=pulumi.Output.from_input(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "backup.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ).apply(lambda p: pulumi.Output.json_dumps(p)),
        tags=resource_tags,
    )

    # Attach backup service role policy
    aws.iam.RolePolicyAttachment(
        f"{name}-backup-policy",
        role=backup_role.name,
        policy_arn="arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup",
    )

    # Attach restore service role policy
    aws.iam.RolePolicyAttachment(
        f"{name}-restore-policy",
        role=backup_role.name,
        policy_arn="arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores",
    )

    # Backup selection
    selection = aws.backup.Selection(
        f"{name}-selection",
        name=f"{name}-selection",
        plan_id=plan.id,
        iam_role_arn=backup_role.arn,
        resources=resource_arns,
    )

    return {
        "vault": vault,
        "plan": plan,
        "selection": selection,
        "backup_role": backup_role,
    }
