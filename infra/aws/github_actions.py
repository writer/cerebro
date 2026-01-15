"""
GitHub Actions deployment policies for CI/CD.

Uses the centralized OIDC federation from aws-git-roles:
- OIDC provider and per-repo roles live in management account (533267360238)
- Broker role handles cross-account assume with session tag enforcement
- writer-aws-deployment-role is created by aws-account-automation (CloudFormation)
- This module only attaches policies for cerebro-specific permissions

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


def attach_deployment_policies(
    name: str,
    ecr_repository_arn: str,
    ecs_cluster_arn: Union[str, Output[str]],
    ecs_service_arns: List[Union[str, Output[str]]],
    log_group_arns: Optional[List[Union[str, Output[str]]]] = None,
    sqs_queue_arns: Optional[List[Union[str, Output[str]]]] = None,
    dynamodb_table_arns: Optional[List[Union[str, Output[str]]]] = None,
) -> aws.iam.Policy:
    """Attach deployment policies to the existing writer-aws-deployment-role.
    
    The role is created by aws-account-automation CloudFormation stackset.
    We just add cerebro-specific permissions for ECR, ECS, SQS, DynamoDB.
    """

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

    # Attach to the existing role managed by aws-account-automation
    aws.iam.RolePolicyAttachment(
        f"{name}-deployment-policy-attachment",
        role="writer-aws-deployment-role",
        policy_arn=policy.arn,
    )

    return policy
