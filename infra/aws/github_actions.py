"""
GitHub Actions deployment role for CI/CD.

Uses the centralized OIDC federation from aws-git-roles:
- OIDC provider and per-repo roles live in management account (533267360238)
- Broker role handles cross-account assume with session tag enforcement
- This module creates only the deployment role in the target account

Architecture:
    GitHub Actions -> OIDC Role (mgmt) -> Broker Role (mgmt) -> Deployment Role (this account)

The OIDC role ARN for cerebro is:
    arn:aws:iam::533267360238:role/533267360238-writerinternal-cerebro-gha-oidc-role
"""

import json
from typing import List, Optional, Union

import pulumi
from pulumi import Output
import pulumi_aws as aws


MANAGEMENT_ACCOUNT_ID = "533267360238"
BROKER_ROLE_NAME = "writer-aws-deployment-broker-role"
BROKER_ROLE_ARN = f"arn:aws:iam::{MANAGEMENT_ACCOUNT_ID}:role/{BROKER_ROLE_NAME}"


def create_deployment_role(
    name: str,
    ecr_repository_arn: str,
    ecs_cluster_arn: Union[str, Output[str]],
    ecs_service_arns: List[Union[str, Output[str]]],
    log_group_arns: Optional[List[Union[str, Output[str]]]] = None,
    sqs_queue_arns: Optional[List[Union[str, Output[str]]]] = None,
    dynamodb_table_arns: Optional[List[Union[str, Output[str]]]] = None,
) -> aws.iam.Role:
    """Create deployment role that can be assumed via the centralized broker.
    
    This role trusts the broker role in the management account. The broker
    enforces session tags to prevent cross-repo impersonation.
    """
    assume_role_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {
                "AWS": BROKER_ROLE_ARN
            },
            "Action": ["sts:AssumeRole", "sts:TagSession"],
        }]
    })

    role = aws.iam.Role(
        f"{name}-deployment-role",
        name="writer-aws-deployment-role",
        assume_role_policy=assume_role_policy,
        description=f"Deployment role for {name} (assumed via broker)",
        max_session_duration=3600,
        tags={
            "Name": "writer-aws-deployment-role",
            "Purpose": "CI/CD deployment",
        },
    )

    def build_policy(
        service_arns: List[str],
        log_arns: Optional[List[str]],
        queue_arns: Optional[List[str]],
        table_arns: Optional[List[str]],
    ) -> str:
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
                "Resource": service_arns
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
        
        if queue_arns:
            statements.append({
                "Sid": "SQSAccess",
                "Effect": "Allow",
                "Action": [
                    "sqs:SendMessage",
                    "sqs:ReceiveMessage",
                    "sqs:DeleteMessage",
                    "sqs:GetQueueAttributes",
                ],
                "Resource": queue_arns
            })
        
        if table_arns:
            statements.append({
                "Sid": "DynamoDBAccess",
                "Effect": "Allow",
                "Action": [
                    "dynamodb:PutItem",
                    "dynamodb:GetItem",
                    "dynamodb:UpdateItem",
                    "dynamodb:Query",
                ],
                "Resource": table_arns + [f"{arn}/index/*" for arn in table_arns]
            })
        
        return json.dumps({"Version": "2012-10-17", "Statement": statements})

    # Collect all Output objects for resolution
    all_outputs = list(ecs_service_arns)
    service_count = len(ecs_service_arns)
    
    log_count = 0
    if log_group_arns:
        all_outputs.extend(log_group_arns)
        log_count = len(log_group_arns)
    
    queue_count = 0
    if sqs_queue_arns:
        all_outputs.extend(sqs_queue_arns)
        queue_count = len(sqs_queue_arns)
    
    table_count = 0
    if dynamodb_table_arns:
        all_outputs.extend(dynamodb_table_arns)
        table_count = len(dynamodb_table_arns)

    def resolve_policy(args):
        idx = 0
        services = list(args[idx:idx + service_count])
        idx += service_count
        
        logs = list(args[idx:idx + log_count]) if log_count else None
        idx += log_count
        
        queues = list(args[idx:idx + queue_count]) if queue_count else None
        idx += queue_count
        
        tables = list(args[idx:idx + table_count]) if table_count else None
        
        return build_policy(services, logs, queues, tables)

    policy_document = Output.all(*all_outputs).apply(resolve_policy)

    policy = aws.iam.Policy(
        f"{name}-deployment-policy",
        name=f"{name}-deployment",
        policy=policy_document,
        description=f"Deployment policy for {name}",
        tags={
            "Name": f"{name}-deployment",
        },
    )

    aws.iam.RolePolicyAttachment(
        f"{name}-deployment-policy-attachment",
        role=role.name,
        policy_arn=policy.arn,
    )

    return role


def create_infra_deployment_role(name: str) -> aws.iam.Role:
    """Create infrastructure deployment role for Pulumi.
    
    This role is assumed via the broker for infrastructure changes.
    Has AdministratorAccess scoped to this account.
    """
    assume_role_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {
                "AWS": BROKER_ROLE_ARN
            },
            "Action": ["sts:AssumeRole", "sts:TagSession"],
        }]
    })

    role = aws.iam.Role(
        f"{name}-infra-deployment-role",
        name="writer-aws-infra-deployment-role",
        assume_role_policy=assume_role_policy,
        description=f"Infrastructure deployment role for {name} (assumed via broker)",
        max_session_duration=3600,
        tags={
            "Name": "writer-aws-infra-deployment-role",
            "Purpose": "Infrastructure deployment",
        },
    )

    # AdministratorAccess for Pulumi - scoped to this account only
    aws.iam.RolePolicyAttachment(
        f"{name}-infra-admin",
        role=role.name,
        policy_arn="arn:aws:iam::aws:policy/AdministratorAccess",
    )

    return role
