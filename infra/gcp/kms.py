"""
GCP Cloud KMS for encryption at rest.

Creates:
- KMS key rings
- Crypto keys with automatic rotation
- IAM bindings for key access
"""
import pulumi
import pulumi_gcp as gcp


def create_kms_key(
    name: str,
    project: str,
    location: str = "us-central1",
    rotation_period: str = "7776000s",  # 90 days
) -> dict:
    """
    Create Cloud KMS key ring and crypto key.

    Args:
        name: Key name prefix
        project: GCP project ID
        location: KMS location (regional or multi-regional)
        rotation_period: Automatic rotation period (seconds)

    Returns:
        Dictionary with KMS resources
    """
    # Create key ring (container for keys)
    key_ring = gcp.kms.KeyRing(
        f"{name}-keyring",
        name=f"{name}-keyring",
        project=project,
        location=location,
    )

    # Create crypto key
    crypto_key = gcp.kms.CryptoKey(
        f"{name}-key",
        name=f"{name}-key",
        key_ring=key_ring.id,
        rotation_period=rotation_period,
        purpose="ENCRYPT_DECRYPT",
        version_template=gcp.kms.CryptoKeyVersionTemplateArgs(
            algorithm="GOOGLE_SYMMETRIC_ENCRYPTION",
            protection_level="SOFTWARE",  # Use HSM for higher security
        ),
        labels={
            "managed-by": "pulumi",
            "environment": name.split("-")[1] if "-" in name else "production",
        },
    )

    return {
        "key_ring": key_ring,
        "crypto_key": crypto_key,
        "crypto_key_id": crypto_key.id,
        "key_ring_id": key_ring.id,
    }


def grant_kms_access(
    name: str,
    crypto_key_id: pulumi.Output[str],
    service_account_email: str,
    role: str = "roles/cloudkms.cryptoKeyEncrypterDecrypter",
) -> gcp.kms.CryptoKeyIAMBinding:
    """
    Grant KMS access to a service account.

    Args:
        name: Binding name
        crypto_key_id: Crypto key ID
        service_account_email: Service account email
        role: IAM role to grant

    Returns:
        IAM binding resource
    """
    return gcp.kms.CryptoKeyIAMBinding(
        f"{name}-kms-binding",
        crypto_key_id=crypto_key_id,
        role=role,
        members=[f"serviceAccount:{service_account_email}"],
    )


def create_hsm_key(
    name: str,
    project: str,
    location: str = "us-central1",
    rotation_period: str = "7776000s",
) -> dict:
    """
    Create Cloud KMS key with HSM protection.

    HSM keys provide FIPS 140-2 Level 3 validated hardware protection.

    Args:
        name: Key name prefix
        project: GCP project ID
        location: KMS location
        rotation_period: Automatic rotation period

    Returns:
        Dictionary with KMS resources
    """
    # Create key ring
    key_ring = gcp.kms.KeyRing(
        f"{name}-hsm-keyring",
        name=f"{name}-hsm-keyring",
        project=project,
        location=location,
    )

    # Create HSM-protected crypto key
    crypto_key = gcp.kms.CryptoKey(
        f"{name}-hsm-key",
        name=f"{name}-hsm-key",
        key_ring=key_ring.id,
        rotation_period=rotation_period,
        purpose="ENCRYPT_DECRYPT",
        version_template=gcp.kms.CryptoKeyVersionTemplateArgs(
            algorithm="GOOGLE_SYMMETRIC_ENCRYPTION",
            protection_level="HSM",  # Hardware Security Module
        ),
        labels={
            "managed-by": "pulumi",
            "protection": "hsm",
        },
    )

    return {
        "key_ring": key_ring,
        "crypto_key": crypto_key,
        "crypto_key_id": crypto_key.id,
        "key_ring_id": key_ring.id,
    }