"""
AWS WAF for API protection.
"""

import json

import pulumi
import pulumi_aws as aws


def create_waf(
    name: str,
    alb_arn: pulumi.Output[str],
    additional_alb_arns: list[pulumi.Input[str]] | None = None,
    rate_limit: int = 2000,
    enable_logging: bool = True,
    log_retention_days: int = 30,
    log_group_kms_key_id: pulumi.Output[str] = None,
) -> dict:
    """
    Create WAF Web ACL with common protections.

    Args:
        name: WAF name prefix
        alb_arn: ALB ARN to associate
        additional_alb_arns: Optional additional ALB ARNs to associate
        rate_limit: Requests per 5 minutes per IP
        enable_logging: Enable WAF request logging to CloudWatch
        log_retention_days: Days to retain WAF logs
        log_group_kms_key_id: Optional KMS key for log encryption
    """
    web_acl = aws.wafv2.WebAcl(
        f"{name}-waf",
        name=f"{name}-waf",
        scope="REGIONAL",
        default_action=aws.wafv2.WebAclDefaultActionArgs(
            allow=aws.wafv2.WebAclDefaultActionAllowArgs(),
        ),
        visibility_config=aws.wafv2.WebAclVisibilityConfigArgs(
            cloudwatch_metrics_enabled=True,
            metric_name=f"{name}-waf",
            sampled_requests_enabled=True,
        ),
        rules=[
            # Rate limiting
            aws.wafv2.WebAclRuleArgs(
                name="rate-limit",
                priority=1,
                action=aws.wafv2.WebAclRuleActionArgs(
                    block=aws.wafv2.WebAclRuleActionBlockArgs(),
                ),
                statement=aws.wafv2.WebAclRuleStatementArgs(
                    rate_based_statement=aws.wafv2.WebAclRuleStatementRateBasedStatementArgs(
                        limit=rate_limit,
                        aggregate_key_type="IP",
                    ),
                ),
                visibility_config=aws.wafv2.WebAclRuleVisibilityConfigArgs(
                    cloudwatch_metrics_enabled=True,
                    metric_name="rate-limit",
                    sampled_requests_enabled=True,
                ),
            ),
            # AWS Managed Rules - Common Rule Set
            aws.wafv2.WebAclRuleArgs(
                name="aws-common-rules",
                priority=2,
                override_action=aws.wafv2.WebAclRuleOverrideActionArgs(
                    none=aws.wafv2.WebAclRuleOverrideActionNoneArgs(),
                ),
                statement=aws.wafv2.WebAclRuleStatementArgs(
                    managed_rule_group_statement=aws.wafv2.WebAclRuleStatementManagedRuleGroupStatementArgs(
                        name="AWSManagedRulesCommonRuleSet",
                        vendor_name="AWS",
                    ),
                ),
                visibility_config=aws.wafv2.WebAclRuleVisibilityConfigArgs(
                    cloudwatch_metrics_enabled=True,
                    metric_name="aws-common-rules",
                    sampled_requests_enabled=True,
                ),
            ),
            # AWS Managed Rules - Known Bad Inputs
            aws.wafv2.WebAclRuleArgs(
                name="aws-bad-inputs",
                priority=3,
                override_action=aws.wafv2.WebAclRuleOverrideActionArgs(
                    none=aws.wafv2.WebAclRuleOverrideActionNoneArgs(),
                ),
                statement=aws.wafv2.WebAclRuleStatementArgs(
                    managed_rule_group_statement=aws.wafv2.WebAclRuleStatementManagedRuleGroupStatementArgs(
                        name="AWSManagedRulesKnownBadInputsRuleSet",
                        vendor_name="AWS",
                    ),
                ),
                visibility_config=aws.wafv2.WebAclRuleVisibilityConfigArgs(
                    cloudwatch_metrics_enabled=True,
                    metric_name="aws-bad-inputs",
                    sampled_requests_enabled=True,
                ),
            ),
            # AWS Managed Rules - SQL Injection
            aws.wafv2.WebAclRuleArgs(
                name="aws-sqli",
                priority=4,
                override_action=aws.wafv2.WebAclRuleOverrideActionArgs(
                    none=aws.wafv2.WebAclRuleOverrideActionNoneArgs(),
                ),
                statement=aws.wafv2.WebAclRuleStatementArgs(
                    managed_rule_group_statement=aws.wafv2.WebAclRuleStatementManagedRuleGroupStatementArgs(
                        name="AWSManagedRulesSQLiRuleSet",
                        vendor_name="AWS",
                    ),
                ),
                visibility_config=aws.wafv2.WebAclRuleVisibilityConfigArgs(
                    cloudwatch_metrics_enabled=True,
                    metric_name="aws-sqli",
                    sampled_requests_enabled=True,
                ),
            ),
        ],
        tags={"Name": f"{name}-waf"},
    )

    # Associate WAF with ALB
    waf_association = aws.wafv2.WebAclAssociation(
        f"{name}-waf-association",
        resource_arn=alb_arn,
        web_acl_arn=web_acl.arn,
    )
    additional_associations = [
        aws.wafv2.WebAclAssociation(
            f"{name}-waf-association-{index}",
            resource_arn=additional_alb_arn,
            web_acl_arn=web_acl.arn,
        )
        for index, additional_alb_arn in enumerate(additional_alb_arns or [], start=1)
    ]

    # WAF Logging to CloudWatch
    log_group = None
    log_resource_policy = None
    if enable_logging:
        region = aws.get_region()

        log_group = aws.cloudwatch.LogGroup(
            f"{name}-waf-logs",
            name=f"aws-waf-logs-{name}",
            retention_in_days=log_retention_days,
            kms_key_id=log_group_kms_key_id,
            tags={"Name": f"{name}-waf-logs"},
        )

        # CloudWatch Logs resource policy to allow WAF to write logs
        log_resource_policy = aws.cloudwatch.LogResourcePolicy(
            f"{name}-waf-logs-policy",
            policy_name=f"{name}-waf-logs-policy",
            policy_document=log_group.arn.apply(
                lambda arn: json.dumps({
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "AllowWAFLogging",
                            "Effect": "Allow",
                            "Principal": {
                                "Service": "delivery.logs.amazonaws.com",
                            },
                            "Action": [
                                "logs:CreateLogStream",
                                "logs:PutLogEvents",
                            ],
                            "Resource": f"{arn}:*",
                            "Condition": {
                                "StringEquals": {
                                    "aws:SourceService": "wafv2",
                                },
                                "ArnLike": {
                                    "aws:SourceArn": f"arn:aws:wafv2:{region.region}:*:*/*/*",
                                },
                            },
                        },
                    ],
                })
            ),
        )

        aws.wafv2.WebAclLoggingConfiguration(
            f"{name}-waf-logging",
            log_destination_configs=[log_group.arn],
            resource_arn=web_acl.arn,
            opts=pulumi.ResourceOptions(depends_on=[log_resource_policy]),
        )

    return {
        "web_acl": web_acl,
        "association": waf_association,
        "additional_associations": additional_associations,
        "log_group": log_group,
    }
