"""
AWS WAF for API protection.
"""

import pulumi
import pulumi_aws as aws


def create_waf(
    name: str,
    alb_arn: pulumi.Output[str],
    rate_limit: int = 2000,
) -> dict:
    """
    Create WAF Web ACL with common protections.

    Args:
        name: WAF name prefix
        alb_arn: ALB ARN to associate
        rate_limit: Requests per 5 minutes per IP
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
    aws.wafv2.WebAclAssociation(
        f"{name}-waf-association",
        resource_arn=alb_arn,
        web_acl_arn=web_acl.arn,
    )

    return {
        "web_acl": web_acl,
    }
