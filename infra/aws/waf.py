"""
AWS WAF for API protection.
"""

import json

import pulumi
import pulumi_aws as aws


MCP_OAUTH_LOOPBACK_ORIGINS = (
    ("ipv4", "http://127.0.0.1"),
    ("localhost", "http://localhost"),
    ("ipv6", "http://[::1]"),
)


def _redacted_header(name: str) -> aws.wafv2.WebAclLoggingConfigurationRedactedFieldArgs:
    return aws.wafv2.WebAclLoggingConfigurationRedactedFieldArgs(
        single_header=aws.wafv2.WebAclLoggingConfigurationRedactedFieldSingleHeaderArgs(
            name=name,
        ),
    )


def _text_transformations(*types: str) -> list[aws.wafv2.WebAclRuleStatementByteMatchStatementTextTransformationArgs]:
    return [
        aws.wafv2.WebAclRuleStatementByteMatchStatementTextTransformationArgs(
            priority=index,
            type=transformation_type,
        )
        for index, transformation_type in enumerate(types)
    ]


def _byte_match_statement(
    field_to_match: aws.wafv2.WebAclRuleStatementByteMatchStatementFieldToMatchArgs,
    search_string: str,
    positional_constraint: str = "EXACTLY",
    transformations: tuple[str, ...] = ("NONE",),
) -> aws.wafv2.WebAclRuleStatementArgs:
    return aws.wafv2.WebAclRuleStatementArgs(
        byte_match_statement=aws.wafv2.WebAclRuleStatementByteMatchStatementArgs(
            field_to_match=field_to_match,
            positional_constraint=positional_constraint,
            search_string=search_string,
            text_transformations=_text_transformations(*transformations),
        ),
    )


def _method_match(method: str) -> aws.wafv2.WebAclRuleStatementArgs:
    return _byte_match_statement(
        aws.wafv2.WebAclRuleStatementByteMatchStatementFieldToMatchArgs(
            method=aws.wafv2.WebAclRuleStatementByteMatchStatementFieldToMatchMethodArgs(),
        ),
        method,
    )


def _uri_path_match(path: str) -> aws.wafv2.WebAclRuleStatementArgs:
    return _byte_match_statement(
        aws.wafv2.WebAclRuleStatementByteMatchStatementFieldToMatchArgs(
            uri_path=aws.wafv2.WebAclRuleStatementByteMatchStatementFieldToMatchUriPathArgs(),
        ),
        path,
    )


def _redirect_uri_loopback_match(loopback_origin: str) -> aws.wafv2.WebAclRuleStatementArgs:
    return _byte_match_statement(
        aws.wafv2.WebAclRuleStatementByteMatchStatementFieldToMatchArgs(
            single_query_argument=aws.wafv2.WebAclRuleStatementByteMatchStatementFieldToMatchSingleQueryArgumentArgs(
                name="redirect_uri",
            ),
        ),
        loopback_origin,
        positional_constraint="STARTS_WITH",
        transformations=("URL_DECODE", "LOWERCASE"),
    )


def _registration_body_match(search_string: str) -> aws.wafv2.WebAclRuleStatementArgs:
    return _byte_match_statement(
        aws.wafv2.WebAclRuleStatementByteMatchStatementFieldToMatchArgs(
            body=aws.wafv2.WebAclRuleStatementByteMatchStatementFieldToMatchBodyArgs(
                oversize_handling="CONTINUE",
            ),
        ),
        search_string,
        positional_constraint="CONTAINS",
        transformations=("LOWERCASE",),
    )


def _registration_body_loopback_match(loopback_origin: str) -> aws.wafv2.WebAclRuleStatementArgs:
    return _byte_match_statement(
        aws.wafv2.WebAclRuleStatementByteMatchStatementFieldToMatchArgs(
            body=aws.wafv2.WebAclRuleStatementByteMatchStatementFieldToMatchBodyArgs(
                oversize_handling="CONTINUE",
            ),
        ),
        loopback_origin,
        positional_constraint="CONTAINS",
        transformations=("URL_DECODE", "LOWERCASE"),
    )


def _mcp_oauth_loopback_allow_rule(
    name: str,
    priority: int,
    statements: list[aws.wafv2.WebAclRuleStatementArgs],
) -> aws.wafv2.WebAclRuleArgs:
    return aws.wafv2.WebAclRuleArgs(
        name=name,
        priority=priority,
        action=aws.wafv2.WebAclRuleActionArgs(
            allow=aws.wafv2.WebAclRuleActionAllowArgs(),
        ),
        statement=aws.wafv2.WebAclRuleStatementArgs(
            and_statement=aws.wafv2.WebAclRuleStatementAndStatementArgs(
                statements=statements,
            ),
        ),
        visibility_config=aws.wafv2.WebAclRuleVisibilityConfigArgs(
            cloudwatch_metrics_enabled=True,
            metric_name=name,
            sampled_requests_enabled=False,
        ),
    )


def _mcp_oauth_loopback_authorize_rule(suffix: str, loopback_origin: str, priority: int) -> aws.wafv2.WebAclRuleArgs:
    return _mcp_oauth_loopback_allow_rule(
        name=f"allow-mcp-oauth-loopback-authorize-{suffix}",
        priority=priority,
        statements=[
            _method_match("GET"),
            _uri_path_match("/oauth/authorize"),
            _redirect_uri_loopback_match(loopback_origin),
        ],
    )


def _mcp_oauth_loopback_register_rule(suffix: str, loopback_origin: str, priority: int) -> aws.wafv2.WebAclRuleArgs:
    return _mcp_oauth_loopback_allow_rule(
        name=f"allow-mcp-oauth-loopback-register-{suffix}",
        priority=priority,
        statements=[
            _method_match("POST"),
            _uri_path_match("/oauth/register"),
            _registration_body_match('"redirect_uris"'),
            _registration_body_loopback_match(loopback_origin),
        ],
    )


def _mcp_oauth_loopback_token_rule(suffix: str, loopback_origin: str, priority: int) -> aws.wafv2.WebAclRuleArgs:
    return _mcp_oauth_loopback_allow_rule(
        name=f"allow-mcp-oauth-loopback-token-{suffix}",
        priority=priority,
        statements=[
            _method_match("POST"),
            _uri_path_match("/oauth/token"),
            _registration_body_match("redirect_uri="),
            _registration_body_loopback_match(loopback_origin),
        ],
    )


def _mcp_oauth_loopback_allow_rules() -> list[aws.wafv2.WebAclRuleArgs]:
    """Allow MCP OAuth loopback redirects through managed SSRF/RFI rules."""
    rules: list[aws.wafv2.WebAclRuleArgs] = []
    priority = 2
    for suffix, loopback_origin in MCP_OAUTH_LOOPBACK_ORIGINS:
        rules.append(_mcp_oauth_loopback_authorize_rule(suffix, loopback_origin, priority))
        priority += 1
    for suffix, loopback_origin in MCP_OAUTH_LOOPBACK_ORIGINS:
        rules.append(_mcp_oauth_loopback_token_rule(suffix, loopback_origin, priority))
        priority += 1
    for suffix, loopback_origin in MCP_OAUTH_LOOPBACK_ORIGINS:
        rules.append(_mcp_oauth_loopback_register_rule(suffix, loopback_origin, priority))
        priority += 1
    return rules


def _count_rule_override(rule_name: str) -> aws.wafv2.WebAclRuleStatementManagedRuleGroupStatementRuleActionOverrideArgs:
    return aws.wafv2.WebAclRuleStatementManagedRuleGroupStatementRuleActionOverrideArgs(
        name=rule_name,
        action_to_use=aws.wafv2.WebAclRuleStatementManagedRuleGroupStatementRuleActionOverrideActionToUseArgs(
            count=aws.wafv2.WebAclRuleStatementManagedRuleGroupStatementRuleActionOverrideActionToUseCountArgs(),
        ),
    )


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
            sampled_requests_enabled=False,
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
                    sampled_requests_enabled=False,
                ),
            ),
            *_mcp_oauth_loopback_allow_rules(),
            # AWS Managed Rules - Common Rule Set
            aws.wafv2.WebAclRuleArgs(
                name="aws-common-rules",
                priority=20,
                override_action=aws.wafv2.WebAclRuleOverrideActionArgs(
                    none=aws.wafv2.WebAclRuleOverrideActionNoneArgs(),
                ),
                statement=aws.wafv2.WebAclRuleStatementArgs(
                    managed_rule_group_statement=aws.wafv2.WebAclRuleStatementManagedRuleGroupStatementArgs(
                        name="AWSManagedRulesCommonRuleSet",
                        vendor_name="AWS",
                        rule_action_overrides=[
                            _count_rule_override("SizeRestrictions_BODY"),
                        ],
                    ),
                ),
                visibility_config=aws.wafv2.WebAclRuleVisibilityConfigArgs(
                    cloudwatch_metrics_enabled=True,
                    metric_name="aws-common-rules",
                    sampled_requests_enabled=False,
                ),
            ),
            # AWS Managed Rules - Known Bad Inputs
            aws.wafv2.WebAclRuleArgs(
                name="aws-bad-inputs",
                priority=30,
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
                    sampled_requests_enabled=False,
                ),
            ),
            # AWS Managed Rules - SQL Injection
            aws.wafv2.WebAclRuleArgs(
                name="aws-sqli",
                priority=40,
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
                    sampled_requests_enabled=False,
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
            redacted_fields=[
                _redacted_header("authorization"),
                _redacted_header("cookie"),
                _redacted_header("x-api-key"),
                _redacted_header("x-amz-security-token"),
            ],
            resource_arn=web_acl.arn,
            opts=pulumi.ResourceOptions(depends_on=[log_resource_policy]),
        )

    return {
        "web_acl": web_acl,
        "association": waf_association,
        "additional_associations": additional_associations,
        "log_group": log_group,
    }
