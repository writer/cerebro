"""Azure provider for storage resources."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import AsyncGenerator, Dict, List, Optional

from azure.core.exceptions import AzureError, HttpResponseError
from azure.identity import DefaultAzureCredential
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.storage.v2023_01_01.models import StorageAccount
from azure.storage.blob import BlobServiceClient

from ..base import BaseProvider, ConfigurationSnapshot, ProviderError, ResourceInfo
from ..utils.connector import call_sync_with_retries

logger = logging.getLogger(__name__)


def _extract_resource_group(resource_id: Optional[str]) -> Optional[str]:
    if not resource_id:
        return None
    parts = resource_id.split("/")
    try:
        index = parts.index("resourceGroups")
        return parts[index + 1]
    except (ValueError, IndexError):
        return None


class AzureProvider(BaseProvider):
    """Collect Azure Storage accounts and containers."""

    def __init__(
        self,
        account_id: str,
        subscription_id: str,
        **kwargs,
    ) -> None:
        super().__init__(account_id, **kwargs)
        if not subscription_id:
            raise ProviderError("Azure subscription_id is required")

        self.subscription_id = subscription_id
        self._credential = kwargs.get("credential") or DefaultAzureCredential()
        self._storage_client: Optional[StorageManagementClient] = None

    async def authenticate(self) -> bool:
        try:
            if self._storage_client is None:
                self._storage_client = StorageManagementClient(
                    credential=self._credential,
                    subscription_id=self.subscription_id,
                )

            # Ensure we can enumerate storage accounts (no-op if subscription empty)
            await call_sync_with_retries(
                lambda: list(self._storage_client.storage_accounts.list()) or True,
                exceptions=(AzureError, HttpResponseError),
                logger=logger,
            )
            return True
        except Exception as exc:  # pragma: no cover - network failures
            logger.error("Azure authentication failed: %s", exc)
            raise ProviderError("Azure authentication failed") from exc

    async def discover_resources(
        self,
        resource_types: Optional[List[str]] = None,
    ) -> AsyncGenerator[ResourceInfo, None]:
        await self.authenticate()
        assert self._storage_client is not None

        accounts: List[StorageAccount] = await call_sync_with_retries(
            lambda: list(self._storage_client.storage_accounts.list()),
            exceptions=(AzureError, HttpResponseError),
            logger=logger,
        )

        for account in accounts:
            resource_group = _extract_resource_group(account.id)
            account_props = await self._get_account_properties(
                account.name, resource_group
            )

            if not resource_types or "azure.storage.account" in resource_types:
                metadata = {
                    "account_name": account.name,
                    "resource_group": resource_group,
                    "kind": account.kind,
                    "sku": getattr(account.sku, "name", None),
                    "allow_blob_public_access": getattr(
                        account_props, "allow_blob_public_access", None
                    ),
                    "minimum_tls_version": getattr(
                        account_props, "minimum_tls_version", None
                    ),
                    "https_traffic_only": getattr(
                        account_props, "enable_https_traffic_only", None
                    ),
                    "network_rules": self._serialize_network_rules(
                        getattr(account_props, "network_rule_set", None)
                    ),
                    "region": account.primary_location or account.location or "global",
                    "tags": account.tags or {},
                    "account_id": str(self.account_id),
                    "created_at": (
                        getattr(account, "creation_time", None).isoformat()
                        if getattr(account, "creation_time", None)
                        else datetime.utcnow().isoformat()
                    ),
                }

                yield ResourceInfo(
                    external_id=account.id,
                    name=account.name,
                    resource_type="azure.storage.account",
                    metadata=metadata,
                )

            if resource_types and "azure.storage.container" not in resource_types:
                continue

            account_key = await self._get_account_key(account.name, resource_group)
            if not account_key:
                continue

            blob_service_client = BlobServiceClient(
                account_url=f"https://{account.name}.blob.core.windows.net",
                credential=account_key,
            )

            containers = await call_sync_with_retries(
                lambda: list(
                    blob_service_client.list_containers(include_metadata=True)
                ),
                exceptions=(AzureError,),
                logger=logger,
            )

            for container in containers:
                container_name = getattr(container, "name", None)
                if not container_name:
                    continue

                metadata = {
                    "resource_group": resource_group,
                    "account_name": account.name,
                    "public_access": getattr(container, "public_access", None),
                    "has_immutability_policy": getattr(
                        container, "has_immutability_policy", None
                    ),
                    "has_legal_hold": getattr(container, "has_legal_hold", None),
                    "default_encryption_scope": getattr(
                        container, "default_encryption_scope", None
                    ),
                    "deny_encryption_scope_override": getattr(
                        container, "deny_encryption_scope_override", None
                    ),
                    "allow_blob_public_access": getattr(
                        account_props, "allow_blob_public_access", None
                    ),
                    "region": account.primary_location or account.location or "global",
                    "tags": getattr(container, "metadata", {}) or {},
                    "account_id": str(self.account_id),
                    "created_at": (
                        getattr(container, "last_modified", None).isoformat()
                        if getattr(container, "last_modified", None)
                        else datetime.utcnow().isoformat()
                    ),
                }

                yield ResourceInfo(
                    external_id=f"{account.id}/containers/{container_name}",
                    name=container_name,
                    resource_type="azure.storage.container",
                    metadata=metadata,
                )

    async def get_resource_configuration(
        self,
        resource: ResourceInfo,
    ) -> ConfigurationSnapshot:
        await self.authenticate()
        assert self._storage_client is not None

        if resource.resource_type == "azure.storage.account":
            normalized = await self._build_account_configuration(resource)
        elif resource.resource_type == "azure.storage.container":
            normalized = await self._build_container_configuration(resource)
        else:
            normalized = {}

        return ConfigurationSnapshot(
            resource_external_id=resource.external_id,
            captured_at=datetime.utcnow(),
            normalized_config=normalized,
        )

    async def _build_account_configuration(
        self, resource: ResourceInfo
    ) -> Dict[str, object]:
        resource_group = (
            resource.metadata.get("resource_group") if resource.metadata else None
        )
        account_name = (
            resource.metadata.get("account_name") if resource.metadata else None
        )
        if not account_name:
            # Derive from ID
            account_name = resource.name

        props = await self._get_account_properties(account_name, resource_group)

        if not props:
            return {}

        network_rules = self._serialize_network_rules(
            getattr(props, "network_rule_set", None)
        )

        return {
            "allow_blob_public_access": getattr(
                props, "allow_blob_public_access", None
            ),
            "minimum_tls_version": getattr(props, "minimum_tls_version", None),
            "https_traffic_only": getattr(props, "enable_https_traffic_only", None),
            "encryption": self._serialize_encryption(
                getattr(props, "encryption", None)
            ),
            "network_rules": network_rules,
            "identity": self._serialize_identity(getattr(props, "identity", None)),
        }

    async def _build_container_configuration(
        self, resource: ResourceInfo
    ) -> Dict[str, object]:
        metadata = resource.metadata or {}
        resource_group = metadata.get("resource_group")
        account_name = metadata.get("account_name")
        container_name = resource.name

        if not (resource_group and account_name and container_name):
            return {}

        container_props = await call_sync_with_retries(
            lambda: self._storage_client.blob_containers.get(
                resource_group, account_name, container_name
            ),
            exceptions=(AzureError, HttpResponseError),
            logger=logger,
        )

        account_props = await self._get_account_properties(account_name, resource_group)
        network_rules = self._serialize_network_rules(
            getattr(account_props, "network_rule_set", None) if account_props else None
        )
        allow_blob_public_access = (
            getattr(account_props, "allow_blob_public_access", None)
            if account_props
            else None
        )

        account_key = await self._get_account_key(account_name, resource_group)
        if not account_key:
            sample_objects: List[Dict[str, object]] = []
        else:
            blob_service_client = BlobServiceClient(
                account_url=f"https://{account_name}.blob.core.windows.net",
                credential=account_key,
            )
            sample_objects = await self._sample_container_objects(
                blob_service_client, container_name
            )

        return {
            "resource_group": resource_group,
            "account_name": account_name,
            "public_access": getattr(container_props, "public_access", None),
            "has_immutability_policy": getattr(
                container_props, "has_immutability_policy", None
            ),
            "has_legal_hold": getattr(container_props, "has_legal_hold", None),
            "default_encryption_scope": getattr(
                container_props, "default_encryption_scope", None
            ),
            "deny_encryption_scope_override": getattr(
                container_props, "deny_encryption_scope_override", None
            ),
            "last_modified": (
                getattr(container_props, "last_modified", None).isoformat()
                if getattr(container_props, "last_modified", None)
                else None
            ),
            "metadata": getattr(container_props, "metadata", {}) or {},
            "signed_identifiers": self._serialize_signed_identifiers(
                getattr(container_props, "signed_identifiers", None)
            ),
            "allow_blob_public_access": allow_blob_public_access,
            "network_rules": network_rules,
            "objectsSample": sample_objects,
            "sampledObjectCount": len(sample_objects),
        }

    async def _get_account_properties(
        self, account_name: str, resource_group: Optional[str]
    ):
        if not resource_group:
            logger.warning(
                "Resource group not found for storage account %s", account_name
            )
            return None

        return await call_sync_with_retries(
            lambda: self._storage_client.storage_accounts.get_properties(
                resource_group, account_name
            ),
            exceptions=(AzureError, HttpResponseError),
            logger=logger,
        )

    async def _get_account_key(
        self, account_name: str, resource_group: Optional[str]
    ) -> Optional[str]:
        if not resource_group:
            return None

        keys = await call_sync_with_retries(
            lambda: self._storage_client.storage_accounts.list_keys(
                resource_group, account_name
            ),
            exceptions=(AzureError, HttpResponseError),
            logger=logger,
        )
        key_items = getattr(keys, "keys", []) or []
        if not key_items:
            return None
        return key_items[0].value

    async def _sample_container_objects(
        self,
        blob_service_client: BlobServiceClient,
        container_name: str,
        max_samples: int = 50,
    ) -> List[Dict[str, object]]:
        try:
            container_client = blob_service_client.get_container_client(container_name)

            def _list_blobs():
                iterator = container_client.list_blobs(
                    results_per_page=max_samples
                ).by_page()
                blobs = []
                for page in iterator:
                    for blob in page:
                        blobs.append(blob)
                        if len(blobs) >= max_samples:
                            return blobs
                return blobs

            blobs = await call_sync_with_retries(
                _list_blobs,
                exceptions=(AzureError,),
                logger=logger,
            )

            samples: List[Dict[str, object]] = []
            for blob in blobs:
                samples.append(
                    {
                        "name": blob.name,
                        "size": getattr(blob, "size", None),
                        "last_modified": (
                            getattr(blob, "last_modified", None).isoformat()
                            if getattr(blob, "last_modified", None)
                            else None
                        ),
                        "content_type": (
                            getattr(blob, "content_settings", None).content_type
                            if getattr(blob, "content_settings", None)
                            else None
                        ),
                    }
                )
            return samples
        except Exception as exc:  # pragma: no cover - network failures
            logger.debug("Failed to sample blobs for %s: %s", container_name, exc)
            return []

    @staticmethod
    def _serialize_network_rules(rule_set) -> Dict[str, object]:
        if not rule_set:
            return {}
        return {
            "default_action": getattr(rule_set, "default_action", None),
            "bypass": getattr(rule_set, "bypass", None),
            "ip_rules": [
                getattr(rule, "ip_address_or_range", None)
                for rule in getattr(rule_set, "ip_rules", [])
            ],
            "virtual_network_rules": [
                getattr(rule, "virtual_network_resource_id", None)
                for rule in getattr(rule_set, "virtual_network_rules", [])
            ],
        }

    @staticmethod
    def _serialize_encryption(encryption) -> Dict[str, object]:
        if not encryption:
            return {}
        services = getattr(encryption, "services", None)
        return {
            "key_source": getattr(encryption, "key_source", None),
            "key_vault_properties": (
                encryption.key_vault_properties.as_dict()
                if getattr(encryption, "key_vault_properties", None)
                and hasattr(encryption.key_vault_properties, "as_dict")
                else None
            ),
            "services": (
                services.as_dict()
                if services and hasattr(services, "as_dict")
                else None
            ),
        }

    @staticmethod
    def _serialize_identity(identity) -> Dict[str, object]:
        if not identity:
            return {}
        return {
            "type": getattr(identity, "type", None),
            "principal_id": getattr(identity, "principal_id", None),
            "tenant_id": getattr(identity, "tenant_id", None),
        }

    @staticmethod
    def _serialize_signed_identifiers(signed_identifiers) -> List[Dict[str, object]]:
        if not signed_identifiers:
            return []
        serialized: List[Dict[str, object]] = []
        for identifier in signed_identifiers:
            access_policy = getattr(identifier, "access_policy", None)
            serialized.append(
                {
                    "id": getattr(identifier, "id", None),
                    "access_policy": (
                        access_policy.as_dict()
                        if access_policy and hasattr(access_policy, "as_dict")
                        else None
                    ),
                }
            )
        return serialized
