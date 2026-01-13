"""Azure finding producers."""

from .aks_rbac_disabled import AzureAKSRbacDisabledProducer
from .cosmosdb_public_network import AzureCosmosDBPublicNetworkProducer
from .defender_storage_disabled import AzureDefenderStorageDisabledProducer
from .keyvault_logging_disabled import AzureKeyVaultLoggingDisabledProducer
from .nsg_admin_port_exposure import AzureNsgAdminPortExposureProducer
from .sqlserver_public_access import AzureSQLServerPublicAccessProducer
from .storage_network_access_allow import AzureStorageNetworkAccessAllowProducer
from .storage_public_write import AzureStoragePublicWriteProducer
from .storage_secret_artifacts import AzureStorageSecretArtifactsProducer
from .user_mfa_disabled import AzureUserMfaProducer

__all__ = [
    "AzureAKSRbacDisabledProducer",
    "AzureCosmosDBPublicNetworkProducer",
    "AzureDefenderStorageDisabledProducer",
    "AzureKeyVaultLoggingDisabledProducer",
    "AzureNsgAdminPortExposureProducer",
    "AzureSQLServerPublicAccessProducer",
    "AzureStorageNetworkAccessAllowProducer",
    "AzureStoragePublicWriteProducer",
    "AzureStorageSecretArtifactsProducer",
    "AzureUserMfaProducer",
]
