"""Azure finding producers."""

from .keyvault_logging_disabled import AzureKeyVaultLoggingDisabledProducer
from .nsg_admin_port_exposure import AzureNsgAdminPortExposureProducer
from .sqlserver_public_access import AzureSQLServerPublicAccessProducer
from .storage_public_write import AzureStoragePublicWriteProducer
from .storage_secret_artifacts import AzureStorageSecretArtifactsProducer
from .user_mfa_disabled import AzureUserMfaProducer

__all__ = [
    "AzureKeyVaultLoggingDisabledProducer",
    "AzureNsgAdminPortExposureProducer",
    "AzureSQLServerPublicAccessProducer",
    "AzureStoragePublicWriteProducer",
    "AzureStorageSecretArtifactsProducer",
    "AzureUserMfaProducer",
]
