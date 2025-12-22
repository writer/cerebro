"""
GCP Secret Manager for secure credential storage.

Creates:
- Secret Manager secrets
- Secret versions with encrypted data
- IAM bindings for secret access
"""

import pulumi
import pulumi_gcp as gcp
import json


def create_secrets(
    name: str,
    project: str,
    secrets: dict[str, pulumi.Output | str],
    kms_key_name: pulumi.Output[str] = None,
    replication_locations: list[str] = None,
) -> dict:
    """
    Create Secret Manager secrets.

    Args:
        name: Secret name prefix
        project: GCP project ID
        secrets: Dictionary of secret key-value pairs
        kms_key_name: KMS crypto key name for encryption
        replication_locations: List of locations for replication

    Returns:
        Dictionary with secret resources
    """
    secret_resources = {}

    # Default to automatic replication if not specified
    replication_config = gcp.secretmanager.SecretReplicationArgs(
        auto=gcp.secretmanager.SecretReplicationAutoArgs()
    )

    # User-managed replication if locations specified
    if replication_locations:
        replicas = [
            gcp.secretmanager.SecretReplicationUserManagedReplicaArgs(
                location=loc,
                customer_managed_encryption=(
                    gcp.secretmanager.SecretReplicationUserManagedReplicaCustomerManagedEncryptionArgs(
                        kms_key_name=kms_key_name
                    )
                    if kms_key_name
                    else None
                ),
            )
            for loc in replication_locations
        ]
        replication_config = gcp.secretmanager.SecretReplicationArgs(
            user_managed=gcp.secretmanager.SecretReplicationUserManagedArgs(
                replicas=replicas
            )
        )

    # Create each secret
    for key, value in secrets.items():
        secret_name = f"{name}-{key.lower().replace('_', '-')}"

        # Create secret
        secret = gcp.secretmanager.Secret(
            secret_name,
            secret_id=secret_name,
            project=project,
            replication=replication_config,
            labels={
                "managed-by": "pulumi",
                "type": "application",
            },
        )

        # Create secret version with value
        # Handle both Output and string values
        if isinstance(value, pulumi.Output):
            secret_data = value.apply(lambda v: str(v))
        else:
            secret_data = str(value)

        gcp.secretmanager.SecretVersion(
            f"{secret_name}-v1",
            secret=secret.id,
            secret_data=secret_data,
        )

        secret_resources[key] = secret

    return secret_resources


def create_json_secret(
    name: str,
    project: str,
    secret_data: dict,
    kms_key_name: pulumi.Output[str] = None,
) -> gcp.secretmanager.Secret:
    """
    Create a secret with JSON data.

    Useful for storing structured configuration.

    Args:
        name: Secret name
        project: GCP project ID
        secret_data: Dictionary to store as JSON
        kms_key_name: KMS crypto key name for encryption

    Returns:
        Secret resource
    """
    replication_config = gcp.secretmanager.SecretReplicationArgs(
        auto=gcp.secretmanager.SecretReplicationAutoArgs()
    )

    if kms_key_name:
        # For KMS encryption, need user-managed replication
        replication_config = gcp.secretmanager.SecretReplicationArgs(
            user_managed=gcp.secretmanager.SecretReplicationUserManagedArgs(
                replicas=[
                    gcp.secretmanager.SecretReplicationUserManagedReplicaArgs(
                        location="us-central1",
                        customer_managed_encryption=gcp.secretmanager.SecretReplicationUserManagedReplicaCustomerManagedEncryptionArgs(
                            kms_key_name=kms_key_name
                        ),
                    )
                ]
            )
        )

    secret = gcp.secretmanager.Secret(
        f"{name}-json-secret",
        secret_id=name,
        project=project,
        replication=replication_config,
        labels={
            "managed-by": "pulumi",
            "type": "json",
        },
    )

    # Convert dict to JSON string
    json_data = json.dumps(secret_data)

    gcp.secretmanager.SecretVersion(
        f"{name}-json-v1",
        secret=secret.id,
        secret_data=json_data,
    )

    return secret


def grant_secret_access(
    name: str,
    secret_id: pulumi.Output[str],
    service_account_email: str,
    role: str = "roles/secretmanager.secretAccessor",
) -> gcp.secretmanager.SecretIamBinding:
    """
    Grant access to a secret for a service account.

    Args:
        name: Binding name
        secret_id: Secret ID
        service_account_email: Service account email
        role: IAM role to grant

    Returns:
        IAM binding resource
    """
    return gcp.secretmanager.SecretIamBinding(
        f"{name}-secret-binding",
        secret_id=secret_id,
        role=role,
        members=[f"serviceAccount:{service_account_email}"],
    )
