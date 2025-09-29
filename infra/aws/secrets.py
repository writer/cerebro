"""
AWS Secrets Manager for secure credential storage.

Stores sensitive configuration including:
- Database passwords
- Redis passwords
- API keys
- JWT secret keys
"""
import pulumi
import pulumi_aws as aws
import json


def create_secrets(
    name: str,
    secrets: dict[str, pulumi.Output | str],
    kms_key_id: pulumi.Output[str] = None,
    recovery_window_in_days: int = 30,
) -> aws.secretsmanager.Secret:
    """
    Create a Secrets Manager secret with multiple key-value pairs.

    Args:
        name: Secret name
        secrets: Dictionary of secret key-value pairs
        kms_key_id: KMS key ID for encryption (optional)
        recovery_window_in_days: Recovery window before permanent deletion

    Returns:
        Secrets Manager Secret resource
    """
    # Create secret
    secret_kwargs = {
        "name": name,
        "description": f"Secrets for {name}",
        "recovery_window_in_days": recovery_window_in_days,
        "tags": {
            "Name": name,
            "ManagedBy": "Pulumi",
        },
    }

    # Add KMS encryption if provided
    if kms_key_id:
        secret_kwargs["kms_key_id"] = kms_key_id

    secret = aws.secretsmanager.Secret(
        f"{name}-secret",
        **secret_kwargs,
    )

    # Create secret version with all key-value pairs
    # Pulumi Output.all() handles mixing Output and string types
    secret_dict = pulumi.Output.all(**secrets).apply(
        lambda resolved: json.dumps(resolved)
    )

    aws.secretsmanager.SecretVersion(
        f"{name}-secret-version",
        secret_id=secret.id,
        secret_string=secret_dict,
    )

    return secret


def create_rds_secret(
    name: str,
    username: str,
    password: pulumi.Output[str],
    host: pulumi.Output[str],
    port: int = 5432,
    database: str = "postgres",
    kms_key_id: pulumi.Output[str] = None,
) -> aws.secretsmanager.Secret:
    """
    Create an RDS-formatted secret for database connections.

    AWS RDS can automatically rotate secrets in this format.

    Args:
        name: Secret name
        username: Database username
        password: Database password
        host: Database endpoint
        port: Database port
        database: Database name
        kms_key_id: KMS key ID for encryption

    Returns:
        Secrets Manager Secret resource
    """
    # RDS secret format
    secret_data = pulumi.Output.all(
        password=password,
        host=host,
    ).apply(
        lambda args: json.dumps(
            {
                "engine": "postgres",
                "username": username,
                "password": args["password"],
                "host": args["host"],
                "port": port,
                "dbname": database,
            }
        )
    )

    secret_kwargs = {
        "name": name,
        "description": f"RDS credentials for {name}",
        "tags": {
            "Name": name,
            "Type": "RDS",
            "ManagedBy": "Pulumi",
        },
    }

    if kms_key_id:
        secret_kwargs["kms_key_id"] = kms_key_id

    secret = aws.secretsmanager.Secret(
        f"{name}-rds-secret",
        **secret_kwargs,
    )

    aws.secretsmanager.SecretVersion(
        f"{name}-rds-secret-version",
        secret_id=secret.id,
        secret_string=secret_data,
    )

    return secret


def grant_secret_access(
    name: str,
    secret_arn: pulumi.Output[str],
    principal_arns: list[str],
) -> aws.secretsmanager.SecretPolicy:
    """
    Grant read access to a secret for specific IAM principals.

    Args:
        name: Policy name
        secret_arn: Secret ARN
        principal_arns: List of IAM role/user ARNs to grant access

    Returns:
        Secret Policy resource
    """
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": principal_arns},
                "Action": [
                    "secretsmanager:GetSecretValue",
                    "secretsmanager:DescribeSecret",
                ],
                "Resource": "*",
            }
        ],
    }

    return aws.secretsmanager.SecretPolicy(
        f"{name}-secret-policy",
        secret_arn=secret_arn,
        policy=json.dumps(policy_doc),
    )