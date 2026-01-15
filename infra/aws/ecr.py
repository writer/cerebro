"""
AWS ECR repository for Cerebro container images.
"""

import pulumi
import pulumi_aws as aws


def create_ecr_repository(
    name: str,
    image_tag_mutability: str = "MUTABLE",
    scan_on_push: bool = True,
    lifecycle_policy_days: int = 30,
    kms_key_arn: str = None,
) -> aws.ecr.Repository:
    """
    Create an ECR repository with security best practices.
    
    Args:
        name: Repository name
        image_tag_mutability: MUTABLE or IMMUTABLE
        scan_on_push: Enable vulnerability scanning on push
        lifecycle_policy_days: Days to keep untagged images before cleanup
        kms_key_arn: Optional KMS key ARN for encryption (uses KMS if provided, AES256 otherwise)
    
    Returns:
        ECR Repository resource
    """
    encryption_configs = [aws.ecr.RepositoryEncryptionConfigurationArgs(
        encryption_type="KMS",
        kms_key=kms_key_arn,
    )] if kms_key_arn else [aws.ecr.RepositoryEncryptionConfigurationArgs(
        encryption_type="AES256",
    )]
    
    repository = aws.ecr.Repository(
        f"{name}-ecr",
        name=name,
        image_tag_mutability=image_tag_mutability,
        image_scanning_configuration=aws.ecr.RepositoryImageScanningConfigurationArgs(
            scan_on_push=scan_on_push,
        ),
        encryption_configurations=encryption_configs,
        tags={"Name": name},
        opts=pulumi.ResourceOptions(protect=True),
    )

    # Lifecycle policy to clean up untagged images
    aws.ecr.LifecyclePolicy(
        f"{name}-ecr-lifecycle",
        repository=repository.name,
        policy=pulumi.Output.json_dumps({
            "rules": [
                {
                    "rulePriority": 1,
                    "description": f"Remove untagged images older than {lifecycle_policy_days} days",
                    "selection": {
                        "tagStatus": "untagged",
                        "countType": "sinceImagePushed",
                        "countUnit": "days",
                        "countNumber": lifecycle_policy_days,
                    },
                    "action": {"type": "expire"},
                },
                {
                    "rulePriority": 2,
                    "description": "Keep only last 50 tagged images",
                    "selection": {
                        "tagStatus": "tagged",
                        "tagPrefixList": ["v", "sha-"],
                        "countType": "imageCountMoreThan",
                        "countNumber": 50,
                    },
                    "action": {"type": "expire"},
                },
            ]
        }),
    )

    return repository
