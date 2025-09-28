"""KMS factory for creating appropriate KMS instances."""

import logging
from typing import Optional

from cerebro.core.config import settings
from .base import BaseKMS
from .aws_kms import AWSKMS
from .gcp_kms import GCPKMS
from .azure_kms import AzureKeyVaultKMS
from .vault_kms import VaultTransitKMS
from .local_kms import LocalPlaintextKMS

logger = logging.getLogger(__name__)


def get_kms() -> BaseKMS:
    """Get KMS instance based on configuration."""
    kms_provider = getattr(settings, 'kms_provider', 'local')
    
    if kms_provider == "aws":
        key_id = getattr(settings, 'aws_kms_key_id', None)
        if not key_id:
            raise ValueError("AWS KMS key ID not configured (AWS_KMS_KEY_ID)")
        
        return AWSKMS(
            key_id=key_id,
            region=getattr(settings, 'aws_kms_region', settings.aws_default_region),
            access_key_id=settings.aws_access_key_id,
            secret_access_key=settings.aws_secret_access_key
        )
    
    elif kms_provider == "gcp":
        key_name = getattr(settings, 'gcp_kms_key_name', None)
        if not key_name:
            raise ValueError("GCP KMS key name not configured (GCP_KMS_KEY_NAME)")
        
        return GCPKMS(
            key_name=key_name,
            credentials_path=settings.google_application_credentials
        )
    
    elif kms_provider == "azure":
        vault_url = getattr(settings, 'azure_vault_url', None)
        key_name = getattr(settings, 'azure_key_name', None)
        
        if not vault_url or not key_name:
            raise ValueError("Azure Key Vault URL and key name not configured")
        
        return AzureKeyVaultKMS(
            vault_url=vault_url,
            key_name=key_name
        )
    
    elif kms_provider == "vault":
        vault_url = getattr(settings, 'vault_url', None)
        mount_path = getattr(settings, 'vault_mount_path', 'transit')
        key_name = getattr(settings, 'vault_key_name', None)
        
        if not vault_url or not key_name:
            raise ValueError("Vault URL and key name not configured")
        
        return VaultTransitKMS(
            vault_url=vault_url,
            mount_path=mount_path,
            key_name=key_name
        )
    
    elif kms_provider == "local":
        logger.warning("Using LocalPlaintextKMS - only suitable for development")
        return LocalPlaintextKMS()
    
    else:
        raise ValueError(f"Unknown KMS provider: {kms_provider}")


async def test_kms_connection() -> bool:
    """Test KMS connectivity."""
    try:
        kms = get_kms()
        success = await kms.test_connection()
        
        if success:
            logger.info(f"KMS connection test passed for provider: {kms.name}")
        else:
            logger.error(f"KMS connection test failed for provider: {kms.name}")
        
        return success
        
    except Exception as e:
        logger.error(f"KMS connection test error: {e}")
        return False


def get_available_kms_providers() -> list:
    """Get list of available KMS providers based on configuration."""
    providers = []
    
    # Check AWS
    if (hasattr(settings, 'aws_kms_key_id') and 
        hasattr(settings, 'aws_access_key_id')):
        providers.append("aws")
    
    # Check GCP
    if (hasattr(settings, 'gcp_kms_key_name') and 
        hasattr(settings, 'google_application_credentials')):
        providers.append("gcp")
    
    # Check Azure
    if (hasattr(settings, 'azure_vault_url') and 
        hasattr(settings, 'azure_key_name')):
        providers.append("azure")
    
    # Check Vault
    if (hasattr(settings, 'vault_url') and 
        hasattr(settings, 'vault_key_name')):
        providers.append("vault")
    
    # Local is always available for development
    providers.append("local")
    
    return providers
