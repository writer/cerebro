"""
GitHub Actions OIDC IAM Role for CI/CD deployments.

Creates an IAM role that GitHub Actions can assume via OIDC to:
- Push Docker images to ECR
- Deploy to ECS
- Access required AWS services
"""

import json
from typing import List, Optional, Union

import pulumi
from pulumi import Output
import pulumi_aws as aws


def create_github_actions_role(
    name: str,
    github_org: str,
    github_repo: str,
    ecr_repository_arn: str,
    ecs_cluster_arn: Union[str, Output[str]],
    ecs_service_arn: Union[str, Output[str]],
    log_group_arns: Optional[List[Union[str, Output[str]]]] = None,
) -> aws.iam.Role:
    """Create IAM role for GitHub Actions with OIDC authentication."""

    # Get the existing OIDC provider (created at org level)
    oidc_provider = aws.iam.get_open_id_connect_provider(
        url="https://token.actions.githubusercontent.com"
    )

    # Trust policy allowing GitHub Actions to assume this role
    assume_role_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {
                "Federated": oidc_provider.arn
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
                },
                "StringLike": {
                    "token.actions.githubusercontent.com:sub": f"repo:{github_org}/{github_repo}:*"
                }
            }
        }]
    })

    role = aws.iam.Role(
        f"{name}-github-actions-role",
        name=f"github-actions-{name}",
        assume_role_policy=assume_role_policy,
        description=f"GitHub Actions role for {github_org}/{github_repo}",
        tags={
            "Name": f"github-actions-{name}",
            "Repository": f"{github_org}/{github_repo}",
            "Purpose": "CI/CD deployment",
        },
    )

    # Build policy document using Output.all to handle dynamic values
    def build_policy(service_arn: str, log_arns: Optional[List[str]]) -> str:
        statements = [
            {
                "Sid": "ECRAuth",
                "Effect": "Allow",
                "Action": ["ecr:GetAuthorizationToken"],
                "Resource": "*"
            },
            {
                "Sid": "ECRPush",
                "Effect": "Allow",
                "Action": [
                    "ecr:GetDownloadUrlForLayer",
                    "ecr:BatchGetImage",
                    "ecr:BatchCheckLayerAvailability",
                    "ecr:PutImage",
                    "ecr:InitiateLayerUpload",
                    "ecr:UploadLayerPart",
                    "ecr:CompleteLayerUpload",
                    "ecr:DescribeRepositories",
                    "ecr:ListImages",
                ],
                "Resource": ecr_repository_arn
            },
            {
                "Sid": "ECSDescribe",
                "Effect": "Allow",
                "Action": [
                    "ecs:DescribeClusters",
                    "ecs:DescribeServices",
                    "ecs:DescribeTaskDefinition",
                    "ecs:DescribeTasks",
                    "ecs:ListTasks",
                ],
                "Resource": "*"
            },
            {
                "Sid": "ECSUpdate",
                "Effect": "Allow",
                "Action": ["ecs:UpdateService"],
                "Resource": service_arn
            },
        ]
        
        if log_arns:
            statements.append({
                "Sid": "CloudWatchLogs",
                "Effect": "Allow",
                "Action": [
                    "logs:GetLogEvents",
                    "logs:DescribeLogStreams",
                ],
                "Resource": [f"{arn}:*" for arn in log_arns]
            })
        
        return json.dumps({"Version": "2012-10-17", "Statement": statements})

    # Handle Output types for dynamic values
    if log_group_arns:
        policy_document = Output.all(ecs_service_arn, *log_group_arns).apply(
            lambda args: build_policy(args[0], list(args[1:]))
        )
    else:
        policy_document = Output.from_input(ecs_service_arn).apply(
            lambda arn: build_policy(arn, None)
        )

    policy = aws.iam.Policy(
        f"{name}-github-actions-policy",
        name=f"github-actions-{name}-deployment",
        policy=policy_document,
        description=f"Deployment policy for {github_org}/{github_repo}",
        tags={
            "Name": f"github-actions-{name}-deployment",
            "Repository": f"{github_org}/{github_repo}",
        },
    )

    aws.iam.RolePolicyAttachment(
        f"{name}-github-actions-policy-attachment",
        role=role.name,
        policy_arn=policy.arn,
    )

    return role


def create_github_actions_infra_role(
    name: str,
    github_org: str,
    github_repo: str,
) -> aws.iam.Role:
    """Create IAM role for GitHub Actions Pulumi infrastructure deployments."""

    oidc_provider = aws.iam.get_open_id_connect_provider(
        url="https://token.actions.githubusercontent.com"
    )

    assume_role_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {
                "Federated": oidc_provider.arn
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
                },
                "StringLike": {
                    "token.actions.githubusercontent.com:sub": f"repo:{github_org}/{github_repo}:*"
                }
            }
        }]
    })

    role = aws.iam.Role(
        f"{name}-github-actions-infra-role",
        name=f"github-actions-{name}-infra",
        assume_role_policy=assume_role_policy,
        description=f"GitHub Actions infra role for {github_org}/{github_repo}",
        tags={
            "Name": f"github-actions-{name}-infra",
            "Repository": f"{github_org}/{github_repo}",
            "Purpose": "Infrastructure deployment",
        },
    )

    # Attach AdministratorAccess for Pulumi (scoped to this account)
    # In production, you'd want to scope this down further
    aws.iam.RolePolicyAttachment(
        f"{name}-github-actions-infra-admin",
        role=role.name,
        policy_arn="arn:aws:iam::aws:policy/AdministratorAccess",
    )

    return role
