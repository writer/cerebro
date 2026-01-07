"""
AWS WAF (Web Application Firewall) module for Cerebro.

Provides protection against common web exploits and rate limiting.
"""

from typing import Dict, Optional

import pulumi
import pulumi_aws as aws


def create_waf(
    name: str,
    alb_arn: pulumi.Input[str],
    rate_limit: int = 2000,
    log_group_kms_key_id: Optional[pulumi.Input[str]] = None,
    tags: Optional[Dict[str, str]] = None,
) -> Dict[str, pulumi.Output]:
    """
    Create a WAF WebACL with common security rules.

    Args:
        name: Resource name prefix
        alb_arn: ARN of the ALB to protect
        rate_limit: Request rate limit per IP (default: 2000/5min)
        log_group_kms_key_id: Optional KMS key for log encryption
        tags: Resource tags

    Returns:
        Dictionary containing WAF resources
    """
    resource_tags = tags or {}

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
            # AWS Managed Common Rule Set
            aws.wafv2.WebAclRuleArgs(
                name="AWSManagedRulesCommonRuleSet",
                priority=1,
                override_action=aws.wafv2.WebAclRuleOverrideActionArgs(
                    none=aws.wafv2.WebAclRuleOverrideActionNoneArgs(),
                ),
                statement=aws.wafv2.WebAclRuleStatementArgs(
                    managed_rule_group_statement=aws.wafv2.WebAclRuleStatementManagedRuleGroupStatementArgs(
                        name="AWSManagedRulesCommonRuleSet",
                        vendor_name="AWS",
                        # Exclude agent API from body inspection - AI prompts trigger false positives
                        scope_down_statement=aws.wafv2.WebAclRuleStatementArgs(
                            not_statement=aws.wafv2.WebAclRuleStatementNotStatementArgs(
                                statements=[
                                    aws.wafv2.WebAclRuleStatementArgs(
                                        byte_match_statement=aws.wafv2.WebAclRuleStatementByteMatchStatementArgs(
                                            search_string="/api/agents",
                                            field_to_match=aws.wafv2.WebAclRuleStatementByteMatchStatementFieldToMatchArgs(
                                                uri_path=aws.wafv2.WebAclRuleStatementByteMatchStatementFieldToMatchUriPathArgs(),
                                            ),
                                            positional_constraint="STARTS_WITH",
                                            text_transformations=[
                                                aws.wafv2.WebAclRuleStatementByteMatchStatementTextTransformationArgs(
                                                    priority=0,
                                                    type="LOWERCASE",
                                                ),
                                            ],
                                        ),
                                    ),
                                ],
                            ),
                        ),
                    ),
                ),
                visibility_config=aws.wafv2.WebAclRuleVisibilityConfigArgs(
                    cloudwatch_metrics_enabled=True,
                    metric_name="AWSManagedRulesCommonRuleSet",
                    sampled_requests_enabled=True,
                ),
            ),
            # AWS Managed Known Bad Inputs Rule Set
            aws.wafv2.WebAclRuleArgs(
                name="AWSManagedRulesKnownBadInputsRuleSet",
                priority=2,
                override_action=aws.wafv2.WebAclRuleOverrideActionArgs(
                    none=aws.wafv2.WebAclRuleOverrideActionNoneArgs(),
                ),
                statement=aws.wafv2.WebAclRuleStatementArgs(
                    managed_rule_group_statement=aws.wafv2.WebAclRuleStatementManagedRuleGroupStatementArgs(
                        name="AWSManagedRulesKnownBadInputsRuleSet",
                        vendor_name="AWS",
                        scope_down_statement=aws.wafv2.WebAclRuleStatementArgs(
                            not_statement=aws.wafv2.WebAclRuleStatementNotStatementArgs(
                                statements=[
                                    aws.wafv2.WebAclRuleStatementArgs(
                                        byte_match_statement=aws.wafv2.WebAclRuleStatementByteMatchStatementArgs(
                                            search_string="/api/agents",
                                            field_to_match=aws.wafv2.WebAclRuleStatementByteMatchStatementFieldToMatchArgs(
                                                uri_path=aws.wafv2.WebAclRuleStatementByteMatchStatementFieldToMatchUriPathArgs(),
                                            ),
                                            positional_constraint="STARTS_WITH",
                                            text_transformations=[
                                                aws.wafv2.WebAclRuleStatementByteMatchStatementTextTransformationArgs(
                                                    priority=0,
                                                    type="LOWERCASE",
                                                ),
                                            ],
                                        ),
                                    ),
                                ],
                            ),
                        ),
                    ),
                ),
                visibility_config=aws.wafv2.WebAclRuleVisibilityConfigArgs(
                    cloudwatch_metrics_enabled=True,
                    metric_name="AWSManagedRulesKnownBadInputsRuleSet",
                    sampled_requests_enabled=True,
                ),
            ),
            # AWS Managed SQL Injection Rule Set
            aws.wafv2.WebAclRuleArgs(
                name="AWSManagedRulesSQLiRuleSet",
                priority=3,
                override_action=aws.wafv2.WebAclRuleOverrideActionArgs(
                    none=aws.wafv2.WebAclRuleOverrideActionNoneArgs(),
                ),
                statement=aws.wafv2.WebAclRuleStatementArgs(
                    managed_rule_group_statement=aws.wafv2.WebAclRuleStatementManagedRuleGroupStatementArgs(
                        name="AWSManagedRulesSQLiRuleSet",
                        vendor_name="AWS",
                        scope_down_statement=aws.wafv2.WebAclRuleStatementArgs(
                            not_statement=aws.wafv2.WebAclRuleStatementNotStatementArgs(
                                statements=[
                                    aws.wafv2.WebAclRuleStatementArgs(
                                        byte_match_statement=aws.wafv2.WebAclRuleStatementByteMatchStatementArgs(
                                            search_string="/api/agents",
                                            field_to_match=aws.wafv2.WebAclRuleStatementByteMatchStatementFieldToMatchArgs(
                                                uri_path=aws.wafv2.WebAclRuleStatementByteMatchStatementFieldToMatchUriPathArgs(),
                                            ),
                                            positional_constraint="STARTS_WITH",
                                            text_transformations=[
                                                aws.wafv2.WebAclRuleStatementByteMatchStatementTextTransformationArgs(
                                                    priority=0,
                                                    type="LOWERCASE",
                                                ),
                                            ],
                                        ),
                                    ),
                                ],
                            ),
                        ),
                    ),
                ),
                visibility_config=aws.wafv2.WebAclRuleVisibilityConfigArgs(
                    cloudwatch_metrics_enabled=True,
                    metric_name="AWSManagedRulesSQLiRuleSet",
                    sampled_requests_enabled=True,
                ),
            ),
            # Rate Limiting Rule
            aws.wafv2.WebAclRuleArgs(
                name="RateLimitRule",
                priority=4,
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
                    metric_name="RateLimitRule",
                    sampled_requests_enabled=True,
                ),
            ),
        ],
        tags=resource_tags,
    )

    # Associate WAF with ALB
    web_acl_association = aws.wafv2.WebAclAssociation(
        f"{name}-waf-association",
        resource_arn=alb_arn,
        web_acl_arn=web_acl.arn,
    )

    # WAF Logging
    log_group = aws.cloudwatch.LogGroup(
        f"{name}-waf-logs",
        name=f"aws-waf-logs-{name}",
        retention_in_days=30,
        kms_key_id=log_group_kms_key_id,
        tags=resource_tags,
    )

    logging_config = aws.wafv2.WebAclLoggingConfiguration(
        f"{name}-waf-logging",
        log_destination_configs=[log_group.arn],
        resource_arn=web_acl.arn,
    )

    return {
        "web_acl": web_acl,
        "web_acl_association": web_acl_association,
        "log_group": log_group,
        "logging_config": logging_config,
    }
