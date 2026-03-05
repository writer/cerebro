"""
AWS Secrets Manager.
"""

import pulumi
import pulumi_aws as aws


def create_secrets(
    name: str,
    secrets: dict,
    kms_key_arn: pulumi.Output[str] = None,
) -> aws.secretsmanager.Secret:
    """
    Create Secrets Manager secret with key-value pairs.

    Args:
        name: Secret name
        secrets: Dictionary of secret key-value pairs
        kms_key_arn: Optional KMS key ARN for encryption
    """
    secret = aws.secretsmanager.Secret(
        f"{name}-secrets",
        name=f"{name}/config",
        kms_key_id=kms_key_arn,
        tags={"Name": name},
    )

    # Create secret version with all values
    aws.secretsmanager.SecretVersion(
        f"{name}-secrets-version",
        secret_id=secret.id,
        secret_string=pulumi.Output.json_dumps(secrets),
    )

    return secret
