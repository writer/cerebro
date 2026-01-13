"""Azure provider for cloud resources.

Collects Azure resources including:
- Storage accounts and containers
- Virtual machines and VM scale sets
- Network security groups (NSGs)
- IAM role assignments and principals
- Key vaults
- SQL databases
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from datetime import datetime
from typing import Any
from uuid import UUID

import structlog
from azure.core.exceptions import AzureError, HttpResponseError
from azure.identity import DefaultAzureCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.storage.models import StorageAccount
from azure.storage.blob import BlobServiceClient

from ..base import (
    BaseProvider,
    ConfigurationSnapshot,
    IamPermission,
    PrincipalInfo,
    ProviderError,
    ResourceInfo,
)
from ..utils.connector import call_sync_with_retries

logger = structlog.get_logger(__name__)


def _extract_resource_group(resource_id: str | None) -> str | None:
    if not resource_id:
        return None
    parts = resource_id.split("/")
    try:
        index = parts.index("resourceGroups")
        return parts[index + 1]
    except (ValueError, IndexError):
        return None


class AzureProvider(BaseProvider):
    """Collect Azure cloud resources, principals, and IAM edges."""

    def __init__(
        self,
        account_id: UUID,
        subscription_id: str,
        **kwargs: Any,
    ) -> None:
        super().__init__(account_id, **kwargs)
        if not subscription_id:
            raise ProviderError("Azure subscription_id is required")

        self.subscription_id = subscription_id
        self._credential = kwargs.get("credential") or DefaultAzureCredential()
        self._storage_client: StorageManagementClient | None = None
        self._compute_client: ComputeManagementClient | None = None
        self._network_client: NetworkManagementClient | None = None
        self._auth_client: AuthorizationManagementClient | None = None

    @property
    def name(self) -> str:
        """Get provider name."""
        return "azure"

    async def authenticate(self) -> bool:
        try:
            # Initialize all management clients
            if self._storage_client is None:
                self._storage_client = StorageManagementClient(
                    credential=self._credential,
                    subscription_id=self.subscription_id,
                )

            if self._compute_client is None:
                self._compute_client = ComputeManagementClient(
                    credential=self._credential,
                    subscription_id=self.subscription_id,
                )

            if self._network_client is None:
                self._network_client = NetworkManagementClient(
                    credential=self._credential,
                    subscription_id=self.subscription_id,
                )

            if self._auth_client is None:
                self._auth_client = AuthorizationManagementClient(
                    credential=self._credential,
                    subscription_id=self.subscription_id,
                )

            # Verify authentication by listing storage accounts
            await call_sync_with_retries(
                lambda: list(self._storage_client.storage_accounts.list()) or True,  # type: ignore[union-attr]
                exceptions=(AzureError, HttpResponseError),
                logger=logger,
            )
            return True
        except Exception as exc:  # pragma: no cover - network failures
            logger.error("Azure authentication failed: %s", exc)
            raise ProviderError("Azure authentication failed") from exc

    async def discover_resources(
        self,
        resource_types: list[str] | None = None,
    ) -> AsyncGenerator[ResourceInfo, None]:
        await self.authenticate()
        assert self._storage_client is not None

        accounts: list[StorageAccount] = await call_sync_with_retries(
            lambda: list(self._storage_client.storage_accounts.list()),  # type: ignore[union-attr]
            exceptions=(AzureError, HttpResponseError),
            logger=logger,
        )

        for account in accounts:
            resource_group = _extract_resource_group(account.id)
            account_name = account.name or ""
            if not account_name or not resource_group:
                continue
            account_props = await self._get_account_properties(
                account_name, resource_group
            )

            if not resource_types or "azure.storage.account" in resource_types:
                metadata = {
                    "account_name": account_name,
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
                        getattr(account, "creation_time", None).isoformat()  # type: ignore[union-attr]
                        if getattr(account, "creation_time", None)
                        else datetime.utcnow().isoformat()
                    ),
                }

                yield ResourceInfo(
                    external_id=account.id or "",
                    name=account_name,
                    resource_type="azure.storage.account",
                    metadata=metadata,
                )

            if resource_types and "azure.storage.container" not in resource_types:
                continue

            account_key = await self._get_account_key(account_name, resource_group)
            if not account_key:
                continue

            blob_service_client = BlobServiceClient(
                account_url=f"https://{account_name}.blob.core.windows.net",
                credential=account_key,
            )

            containers = await call_sync_with_retries(
                lambda client=blob_service_client: list(  # type: ignore[misc]
                    client.list_containers(include_metadata=True)
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
                        getattr(container, "last_modified", None).isoformat()  # type: ignore[union-attr]
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

        # Virtual Machines
        if not resource_types or "azure.compute.vm" in resource_types:
            async for vm in self._discover_virtual_machines():
                yield vm

        # Network Security Groups
        if not resource_types or "azure.network.nsg" in resource_types:
            async for nsg in self._discover_network_security_groups():
                yield nsg

        # Virtual Networks
        if not resource_types or "azure.network.vnet" in resource_types:
            async for vnet in self._discover_virtual_networks():
                yield vnet

    async def _discover_virtual_machines(self) -> AsyncGenerator[ResourceInfo, None]:
        """Discover Azure Virtual Machines."""
        assert self._compute_client is not None

        vms = await call_sync_with_retries(
            lambda: list(self._compute_client.virtual_machines.list_all()),  # type: ignore[union-attr]
            exceptions=(AzureError, HttpResponseError),
            logger=logger,
        )

        for vm in vms:
            resource_group = _extract_resource_group(vm.id)

            # Get instance view for power state
            instance_view = None
            if resource_group and vm.name:
                rg_str = resource_group
                name_str = vm.name
                try:
                    instance_view = await call_sync_with_retries(
                        lambda rg=rg_str, name=name_str: (
                            self._compute_client.virtual_machines.instance_view(rg, name)  # type: ignore[union-attr]
                        ),
                        exceptions=(AzureError, HttpResponseError),
                        logger=logger,
                    )
                except Exception as e:
                    logger.debug(f"Failed to get instance view for {vm.name}: {e}")

            # Extract power state
            power_state = None
            if instance_view and hasattr(instance_view, "statuses"):
                for status in instance_view.statuses or []:
                    if status.code and status.code.startswith("PowerState/"):
                        power_state = status.code.replace("PowerState/", "")
                        break

            # Extract network interfaces
            network_interfaces = []
            if vm.network_profile and vm.network_profile.network_interfaces:
                for nic_ref in vm.network_profile.network_interfaces:
                    network_interfaces.append(nic_ref.id)

            metadata: dict[str, Any] = {
                "resource_group": resource_group,
                "location": vm.location,
                "vm_size": vm.hardware_profile.vm_size if vm.hardware_profile else None,
                "power_state": power_state,
                "os_type": (
                    vm.storage_profile.os_disk.os_type
                    if vm.storage_profile and vm.storage_profile.os_disk
                    else None
                ),
                "os_disk_size_gb": (
                    vm.storage_profile.os_disk.disk_size_gb
                    if vm.storage_profile and vm.storage_profile.os_disk
                    else None
                ),
                "image_reference": self._serialize_image_reference(
                    vm.storage_profile.image_reference
                    if vm.storage_profile
                    else None
                ),
                "network_interfaces": network_interfaces,
                "availability_set": (
                    vm.availability_set.id if vm.availability_set else None
                ),
                "zones": vm.zones or [],
                "tags": vm.tags or {},
                "identity_type": vm.identity.type if vm.identity else None,
                "identity_principal_id": (
                    vm.identity.principal_id if vm.identity else None
                ),
                "provisioning_state": vm.provisioning_state,
                "account_id": str(self.account_id),
            }

            yield ResourceInfo(
                external_id=vm.id,
                name=vm.name,
                resource_type="azure.compute.vm",
                metadata=metadata,
            )

    async def _discover_network_security_groups(
        self,
    ) -> AsyncGenerator[ResourceInfo, None]:
        """Discover Azure Network Security Groups."""
        assert self._network_client is not None

        nsgs = await call_sync_with_retries(
            lambda: list(self._network_client.network_security_groups.list_all()),  # type: ignore[union-attr]
            exceptions=(AzureError, HttpResponseError),
            logger=logger,
        )

        for nsg in nsgs:
            resource_group = _extract_resource_group(nsg.id)

            # Process security rules
            inbound_rules = []
            outbound_rules = []

            for rule in nsg.security_rules or []:
                rule_data = {
                    "name": rule.name,
                    "priority": rule.priority,
                    "direction": rule.direction,
                    "access": rule.access,
                    "protocol": rule.protocol,
                    "source_port_range": rule.source_port_range,
                    "destination_port_range": rule.destination_port_range,
                    "source_address_prefix": rule.source_address_prefix,
                    "destination_address_prefix": rule.destination_address_prefix,
                    "source_address_prefixes": rule.source_address_prefixes,
                    "destination_address_prefixes": rule.destination_address_prefixes,
                }
                if rule.direction == "Inbound":
                    inbound_rules.append(rule_data)
                else:
                    outbound_rules.append(rule_data)

            # Check for risky rules (0.0.0.0/0 or * with Allow)
            has_public_inbound = any(
                r.get("access") == "Allow"
                and (
                    r.get("source_address_prefix") in ("*", "0.0.0.0/0", "Internet")
                    or "0.0.0.0/0" in (r.get("source_address_prefixes") or [])
                )
                for r in inbound_rules
            )

            # Get associated NICs and subnets
            associated_nics = [
                nic.id for nic in (nsg.network_interfaces or [])
            ]
            associated_subnets = [
                subnet.id for subnet in (nsg.subnets or [])
            ]

            metadata: dict[str, Any] = {
                "resource_group": resource_group,
                "location": nsg.location,
                "inbound_rules": inbound_rules,
                "outbound_rules": outbound_rules,
                "inbound_rule_count": len(inbound_rules),
                "outbound_rule_count": len(outbound_rules),
                "has_public_inbound": has_public_inbound,
                "associated_nics": associated_nics,
                "associated_subnets": associated_subnets,
                "tags": nsg.tags or {},
                "provisioning_state": nsg.provisioning_state,
                "account_id": str(self.account_id),
            }

            yield ResourceInfo(
                external_id=nsg.id,
                name=nsg.name,
                resource_type="azure.network.nsg",
                metadata=metadata,
            )

    async def _discover_virtual_networks(
        self,
    ) -> AsyncGenerator[ResourceInfo, None]:
        """Discover Azure Virtual Networks."""
        assert self._network_client is not None

        vnets = await call_sync_with_retries(
            lambda: list(self._network_client.virtual_networks.list_all()),  # type: ignore[union-attr]
            exceptions=(AzureError, HttpResponseError),
            logger=logger,
        )

        for vnet in vnets:
            resource_group = _extract_resource_group(vnet.id)

            # Extract subnets
            subnets = []
            for subnet in vnet.subnets or []:
                subnets.append({
                    "name": subnet.name,
                    "address_prefix": subnet.address_prefix,
                    "nsg_id": subnet.network_security_group.id if subnet.network_security_group else None,
                })

            metadata: dict[str, Any] = {
                "resource_group": resource_group,
                "location": vnet.location,
                "address_space": (
                    vnet.address_space.address_prefixes
                    if vnet.address_space
                    else []
                ),
                "subnets": subnets,
                "subnet_count": len(subnets),
                "dns_servers": (
                    vnet.dhcp_options.dns_servers
                    if vnet.dhcp_options
                    else []
                ),
                "enable_ddos_protection": vnet.enable_ddos_protection,
                "tags": vnet.tags or {},
                "provisioning_state": vnet.provisioning_state,
                "account_id": str(self.account_id),
            }

            yield ResourceInfo(
                external_id=vnet.id,
                name=vnet.name,
                resource_type="azure.network.vnet",
                metadata=metadata,
            )

    @staticmethod
    def _serialize_image_reference(image_ref: Any) -> dict[str, Any] | None:
        """Serialize VM image reference."""
        if not image_ref:
            return None
        return {
            "publisher": getattr(image_ref, "publisher", None),
            "offer": getattr(image_ref, "offer", None),
            "sku": getattr(image_ref, "sku", None),
            "version": getattr(image_ref, "version", None),
            "id": getattr(image_ref, "id", None),
        }

    async def discover_principals(self) -> AsyncGenerator[PrincipalInfo, None]:
        """Discover Azure service principals and managed identities."""
        await self.authenticate()
        assert self._compute_client is not None

        # Discover managed identities from VMs
        vms = await call_sync_with_retries(
            lambda: list(self._compute_client.virtual_machines.list_all()),  # type: ignore[union-attr]
            exceptions=(AzureError, HttpResponseError),
            logger=logger,
        )

        seen_principals: set[str] = set()

        for vm in vms:
            if vm.identity and vm.identity.principal_id:
                if vm.identity.principal_id in seen_principals:
                    continue
                seen_principals.add(vm.identity.principal_id)

                yield PrincipalInfo(
                    external_id=vm.identity.principal_id,
                    principal_type="managed_identity",
                    display_name=f"{vm.name} (Managed Identity)",
                    is_human=False,
                    metadata={
                        "identity_type": vm.identity.type,
                        "vm_id": vm.id,
                        "vm_name": vm.name,
                        "tenant_id": vm.identity.tenant_id,
                    },
                )

    async def discover_iam_edges(self) -> AsyncGenerator[IamPermission, None]:
        """Discover Azure IAM role assignments."""
        await self.authenticate()
        assert self._auth_client is not None

        # Get all role assignments for the subscription
        assignments = await call_sync_with_retries(
            lambda: list(
                self._auth_client.role_assignments.list_for_subscription()  # type: ignore[union-attr]
            ),
            exceptions=(AzureError, HttpResponseError),
            logger=logger,
        )

        # Cache role definitions
        role_definitions: dict[str, str] = {}

        for assignment in assignments:
            # Get role definition name if not cached
            role_def_id = assignment.role_definition_id
            if role_def_id and role_def_id not in role_definitions:
                rid_str = role_def_id
                try:
                    role_def = await call_sync_with_retries(
                        lambda rid=rid_str: self._auth_client.role_definitions.get_by_id(rid),  # type: ignore[union-attr]
                        exceptions=(AzureError, HttpResponseError),
                        logger=logger,
                    )
                    role_definitions[role_def_id] = role_def.role_name or role_def_id
                except Exception:
                    role_definitions[role_def_id] = role_def_id.split("/")[-1]

            role_name = role_definitions.get(role_def_id, "Unknown")

            # Determine if this is an admin role
            is_admin = role_name.lower() in (
                "owner",
                "contributor",
                "user access administrator",
            )

            yield IamPermission(
                principal_external_id=assignment.principal_id or "",
                resource_external_id=assignment.scope,
                permission=role_name,
                via=f"Role Assignment: {assignment.name}",
                is_admin=is_admin,
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
    ) -> dict[str, object]:
        resource_group = (
            resource.metadata.get("resource_group") if resource.metadata else None
        )
        account_name = (
            resource.metadata.get("account_name") if resource.metadata else None
        )
        if not account_name:
            # Derive from ID
            account_name = resource.name

        props = await self._get_account_properties(str(account_name), resource_group)

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
    ) -> dict[str, object]:
        metadata = resource.metadata or {}
        resource_group = metadata.get("resource_group")
        account_name = metadata.get("account_name")
        container_name = resource.name

        if not (resource_group and account_name and container_name):
            return {}

        container_props = await call_sync_with_retries(
            lambda: self._storage_client.blob_containers.get(  # type: ignore[union-attr]
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
            sample_objects: list[dict[str, object]] = []
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
                getattr(container_props, "last_modified", None).isoformat()  # type: ignore[union-attr]
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
        self, account_name: str, resource_group: str | None
    ) -> Any:
        if not resource_group:
            logger.warning(
                "Resource group not found for storage account %s", account_name
            )
            return None

        return await call_sync_with_retries(
            lambda: self._storage_client.storage_accounts.get_properties(  # type: ignore[union-attr]
                resource_group, account_name
            ),
            exceptions=(AzureError, HttpResponseError),
            logger=logger,
        )

    async def _get_account_key(
        self, account_name: str, resource_group: str | None
    ) -> str | None:
        if not resource_group:
            return None

        keys = await call_sync_with_retries(
            lambda: self._storage_client.storage_accounts.list_keys(  # type: ignore[union-attr]
                resource_group, account_name
            ),
            exceptions=(AzureError, HttpResponseError),
            logger=logger,
        )
        key_items = getattr(keys, "keys", []) or []
        if not key_items:
            return None
        key_value: str | None = key_items[0].value
        return key_value

    async def _sample_container_objects(
        self,
        blob_service_client: BlobServiceClient,
        container_name: str,
        max_samples: int = 50,
    ) -> list[dict[str, object]]:
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

            samples: list[dict[str, object]] = []
            for blob in blobs:
                samples.append(
                    {
                        "name": blob.name,
                        "size": getattr(blob, "size", None),
                        "last_modified": (
                            getattr(blob, "last_modified", None).isoformat()  # type: ignore[union-attr]
                            if getattr(blob, "last_modified", None)
                            else None
                        ),
                        "content_type": (
                            getattr(blob, "content_settings", None).content_type  # type: ignore[union-attr]
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
    def _serialize_network_rules(rule_set: Any) -> dict[str, object]:
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
    def _serialize_encryption(encryption: Any) -> dict[str, object]:
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
    def _serialize_identity(identity: Any) -> dict[str, object]:
        if not identity:
            return {}
        return {
            "type": getattr(identity, "type", None),
            "principal_id": getattr(identity, "principal_id", None),
            "tenant_id": getattr(identity, "tenant_id", None),
        }

    @staticmethod
    def _serialize_signed_identifiers(signed_identifiers: Any) -> list[dict[str, object]]:
        if not signed_identifiers:
            return []
        serialized: list[dict[str, object]] = []
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
