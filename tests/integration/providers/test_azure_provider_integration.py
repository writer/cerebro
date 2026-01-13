"""
Integration tests for Azure provider.

Tests Azure provider functionality including:
- Authentication
- VM discovery
- NSG discovery
- VNet discovery
- Storage account discovery
- Principal discovery
- IAM edge discovery
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

from cerebro.providers.azure.provider import AzureProvider
from cerebro.providers.base import ProviderError


class TestAzureProviderAuthentication:
    """Test Azure provider authentication."""

    @pytest.fixture
    def provider(self):
        """Create an Azure provider."""
        return AzureProvider(
            account_id=uuid4(),
            subscription_id="test-subscription-123",
        )

    @pytest.mark.asyncio
    async def test_authenticate_success(self, provider):
        """Test successful authentication."""
        mock_storage_client = MagicMock()
        mock_storage_client.storage_accounts.list.return_value = []

        mock_compute_client = MagicMock()
        mock_network_client = MagicMock()
        mock_auth_client = MagicMock()

        with patch(
            "cerebro.providers.azure.provider.StorageManagementClient",
            return_value=mock_storage_client,
        ):
            with patch(
                "cerebro.providers.azure.provider.ComputeManagementClient",
                return_value=mock_compute_client,
            ):
                with patch(
                    "cerebro.providers.azure.provider.NetworkManagementClient",
                    return_value=mock_network_client,
                ):
                    with patch(
                        "cerebro.providers.azure.provider.AuthorizationManagementClient",
                        return_value=mock_auth_client,
                    ):
                        result = await provider.authenticate()

        assert result is True
        assert provider._storage_client is not None
        assert provider._compute_client is not None
        assert provider._network_client is not None
        assert provider._auth_client is not None

    @pytest.mark.asyncio
    async def test_authenticate_failure(self, provider):
        """Test authentication failure."""
        from azure.core.exceptions import AzureError

        mock_storage_client = MagicMock()
        mock_storage_client.storage_accounts.list.side_effect = AzureError("Auth failed")

        with patch(
            "cerebro.providers.azure.provider.StorageManagementClient",
            return_value=mock_storage_client,
        ):
            with pytest.raises(ProviderError, match="Azure authentication failed"):
                await provider.authenticate()


class TestAzureProviderVMDiscovery:
    """Test Azure VM discovery."""

    @pytest.fixture
    def authenticated_provider(self):
        """Create an authenticated Azure provider with mocked clients."""
        provider = AzureProvider(
            account_id=uuid4(),
            subscription_id="test-subscription-123",
        )

        # Create mock clients
        provider._storage_client = MagicMock()
        provider._storage_client.storage_accounts.list.return_value = []

        provider._compute_client = MagicMock()
        provider._network_client = MagicMock()
        provider._auth_client = MagicMock()

        return provider

    @pytest.mark.asyncio
    async def test_discover_virtual_machines(self, authenticated_provider):
        """Test VM discovery."""
        # Create mock VM
        mock_vm = MagicMock()
        mock_vm.id = "/subscriptions/test/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1"
        mock_vm.name = "vm1"
        mock_vm.location = "eastus"
        mock_vm.hardware_profile = MagicMock(vm_size="Standard_DS2_v2")
        mock_vm.storage_profile = MagicMock()
        mock_vm.storage_profile.os_disk = MagicMock(os_type="Linux", disk_size_gb=128)
        mock_vm.storage_profile.image_reference = MagicMock(
            publisher="Canonical",
            offer="UbuntuServer",
            sku="18.04-LTS",
            version="latest",
        )
        mock_vm.network_profile = MagicMock()
        mock_vm.network_profile.network_interfaces = [MagicMock(id="/subscriptions/test/networkInterfaces/nic1")]
        mock_vm.availability_set = None
        mock_vm.zones = ["1"]
        mock_vm.tags = {"env": "prod"}
        mock_vm.identity = MagicMock(type="SystemAssigned", principal_id="principal-123")
        mock_vm.provisioning_state = "Succeeded"

        authenticated_provider._compute_client.virtual_machines.list_all.return_value = [mock_vm]
        authenticated_provider._compute_client.virtual_machines.instance_view.return_value = MagicMock(
            statuses=[MagicMock(code="PowerState/running")]
        )

        resources = []
        async for resource in authenticated_provider._discover_virtual_machines():
            resources.append(resource)

        assert len(resources) == 1
        assert resources[0].name == "vm1"
        assert resources[0].resource_type == "azure.compute.vm"
        assert resources[0].metadata["vm_size"] == "Standard_DS2_v2"
        assert resources[0].metadata["power_state"] == "running"
        assert resources[0].metadata["os_type"] == "Linux"


class TestAzureProviderNSGDiscovery:
    """Test Azure NSG discovery."""

    @pytest.fixture
    def authenticated_provider(self):
        """Create an authenticated Azure provider with mocked clients."""
        provider = AzureProvider(
            account_id=uuid4(),
            subscription_id="test-subscription-123",
        )

        provider._storage_client = MagicMock()
        provider._storage_client.storage_accounts.list.return_value = []
        provider._compute_client = MagicMock()
        provider._network_client = MagicMock()
        provider._auth_client = MagicMock()

        return provider

    @pytest.mark.asyncio
    async def test_discover_nsgs(self, authenticated_provider):
        """Test NSG discovery."""
        # Create mock NSG with rules
        mock_rule = MagicMock()
        mock_rule.name = "AllowHTTP"
        mock_rule.priority = 100
        mock_rule.direction = "Inbound"
        mock_rule.access = "Allow"
        mock_rule.protocol = "TCP"
        mock_rule.source_port_range = "*"
        mock_rule.destination_port_range = "80"
        mock_rule.source_address_prefix = "*"
        mock_rule.destination_address_prefix = "*"
        mock_rule.source_address_prefixes = None
        mock_rule.destination_address_prefixes = None

        mock_nsg = MagicMock()
        mock_nsg.id = "/subscriptions/test/resourceGroups/rg1/providers/Microsoft.Network/networkSecurityGroups/nsg1"
        mock_nsg.name = "nsg1"
        mock_nsg.location = "eastus"
        mock_nsg.security_rules = [mock_rule]
        mock_nsg.network_interfaces = []
        mock_nsg.subnets = []
        mock_nsg.tags = {}
        mock_nsg.provisioning_state = "Succeeded"

        authenticated_provider._network_client.network_security_groups.list_all.return_value = [mock_nsg]

        resources = []
        async for resource in authenticated_provider._discover_network_security_groups():
            resources.append(resource)

        assert len(resources) == 1
        assert resources[0].name == "nsg1"
        assert resources[0].resource_type == "azure.network.nsg"
        assert resources[0].metadata["has_public_inbound"] is True
        assert len(resources[0].metadata["inbound_rules"]) == 1

    @pytest.mark.asyncio
    async def test_discover_nsgs_no_public_access(self, authenticated_provider):
        """Test NSG discovery with no public access."""
        mock_rule = MagicMock()
        mock_rule.name = "AllowVNet"
        mock_rule.priority = 100
        mock_rule.direction = "Inbound"
        mock_rule.access = "Allow"
        mock_rule.protocol = "TCP"
        mock_rule.source_port_range = "*"
        mock_rule.destination_port_range = "80"
        mock_rule.source_address_prefix = "10.0.0.0/8"
        mock_rule.destination_address_prefix = "*"
        mock_rule.source_address_prefixes = None
        mock_rule.destination_address_prefixes = None

        mock_nsg = MagicMock()
        mock_nsg.id = "/subscriptions/test/resourceGroups/rg1/providers/Microsoft.Network/networkSecurityGroups/nsg2"
        mock_nsg.name = "nsg2"
        mock_nsg.location = "eastus"
        mock_nsg.security_rules = [mock_rule]
        mock_nsg.network_interfaces = []
        mock_nsg.subnets = []
        mock_nsg.tags = {}
        mock_nsg.provisioning_state = "Succeeded"

        authenticated_provider._network_client.network_security_groups.list_all.return_value = [mock_nsg]

        resources = []
        async for resource in authenticated_provider._discover_network_security_groups():
            resources.append(resource)

        assert len(resources) == 1
        assert resources[0].metadata["has_public_inbound"] is False


class TestAzureProviderVNetDiscovery:
    """Test Azure VNet discovery."""

    @pytest.fixture
    def authenticated_provider(self):
        """Create an authenticated Azure provider with mocked clients."""
        provider = AzureProvider(
            account_id=uuid4(),
            subscription_id="test-subscription-123",
        )

        provider._storage_client = MagicMock()
        provider._storage_client.storage_accounts.list.return_value = []
        provider._compute_client = MagicMock()
        provider._network_client = MagicMock()
        provider._auth_client = MagicMock()

        return provider

    @pytest.mark.asyncio
    async def test_discover_vnets(self, authenticated_provider):
        """Test VNet discovery."""
        mock_subnet = MagicMock()
        mock_subnet.name = "default"
        mock_subnet.address_prefix = "10.0.0.0/24"
        mock_subnet.network_security_group = MagicMock(id="/subscriptions/test/nsgs/nsg1")

        mock_vnet = MagicMock()
        mock_vnet.id = "/subscriptions/test/resourceGroups/rg1/providers/Microsoft.Network/virtualNetworks/vnet1"
        mock_vnet.name = "vnet1"
        mock_vnet.location = "eastus"
        mock_vnet.address_space = MagicMock(address_prefixes=["10.0.0.0/16"])
        mock_vnet.subnets = [mock_subnet]
        mock_vnet.dhcp_options = MagicMock(dns_servers=["168.63.129.16"])
        mock_vnet.enable_ddos_protection = False
        mock_vnet.tags = {}
        mock_vnet.provisioning_state = "Succeeded"

        authenticated_provider._network_client.virtual_networks.list_all.return_value = [mock_vnet]

        resources = []
        async for resource in authenticated_provider._discover_virtual_networks():
            resources.append(resource)

        assert len(resources) == 1
        assert resources[0].name == "vnet1"
        assert resources[0].resource_type == "azure.network.vnet"
        assert resources[0].metadata["subnet_count"] == 1
        assert resources[0].metadata["address_space"] == ["10.0.0.0/16"]


class TestAzureProviderPrincipalDiscovery:
    """Test Azure principal discovery."""

    @pytest.fixture
    def authenticated_provider(self):
        """Create an authenticated Azure provider with mocked clients."""
        provider = AzureProvider(
            account_id=uuid4(),
            subscription_id="test-subscription-123",
        )

        provider._storage_client = MagicMock()
        provider._storage_client.storage_accounts.list.return_value = []
        provider._compute_client = MagicMock()
        provider._network_client = MagicMock()
        provider._auth_client = MagicMock()

        return provider

    @pytest.mark.asyncio
    async def test_discover_principals(self, authenticated_provider):
        """Test principal discovery from VM managed identities."""
        mock_vm = MagicMock()
        mock_vm.name = "vm1"
        mock_vm.id = "/subscriptions/test/vms/vm1"
        mock_vm.identity = MagicMock(
            principal_id="principal-123",
            type="SystemAssigned",
            tenant_id="tenant-456",
        )

        authenticated_provider._compute_client.virtual_machines.list_all.return_value = [mock_vm]

        principals = []
        async for principal in authenticated_provider.discover_principals():
            principals.append(principal)

        assert len(principals) == 1
        assert principals[0].external_id == "principal-123"
        assert principals[0].principal_type == "managed_identity"
        assert principals[0].is_human is False


class TestAzureProviderIAMEdges:
    """Test Azure IAM edge discovery."""

    @pytest.fixture
    def authenticated_provider(self):
        """Create an authenticated Azure provider with mocked clients."""
        provider = AzureProvider(
            account_id=uuid4(),
            subscription_id="test-subscription-123",
        )

        provider._storage_client = MagicMock()
        provider._storage_client.storage_accounts.list.return_value = []
        provider._compute_client = MagicMock()
        provider._network_client = MagicMock()
        provider._auth_client = MagicMock()

        return provider

    @pytest.mark.asyncio
    async def test_discover_iam_edges(self, authenticated_provider):
        """Test IAM edge discovery from role assignments."""
        mock_assignment = MagicMock()
        mock_assignment.principal_id = "principal-123"
        mock_assignment.scope = "/subscriptions/test-subscription"
        mock_assignment.role_definition_id = "/subscriptions/test/providers/Microsoft.Authorization/roleDefinitions/owner-id"
        mock_assignment.name = "assignment-1"

        mock_role_def = MagicMock()
        mock_role_def.role_name = "Owner"

        authenticated_provider._auth_client.role_assignments.list_for_subscription.return_value = [mock_assignment]
        authenticated_provider._auth_client.role_definitions.get_by_id.return_value = mock_role_def

        edges = []
        async for edge in authenticated_provider.discover_iam_edges():
            edges.append(edge)

        assert len(edges) == 1
        assert edges[0].principal_external_id == "principal-123"
        assert edges[0].permission == "Owner"
        assert edges[0].is_admin is True

    @pytest.mark.asyncio
    async def test_discover_iam_edges_non_admin(self, authenticated_provider):
        """Test IAM edge discovery with non-admin role."""
        mock_assignment = MagicMock()
        mock_assignment.principal_id = "principal-456"
        mock_assignment.scope = "/subscriptions/test-subscription/resourceGroups/rg1"
        mock_assignment.role_definition_id = "/subscriptions/test/providers/Microsoft.Authorization/roleDefinitions/reader-id"
        mock_assignment.name = "assignment-2"

        mock_role_def = MagicMock()
        mock_role_def.role_name = "Reader"

        authenticated_provider._auth_client.role_assignments.list_for_subscription.return_value = [mock_assignment]
        authenticated_provider._auth_client.role_definitions.get_by_id.return_value = mock_role_def

        edges = []
        async for edge in authenticated_provider.discover_iam_edges():
            edges.append(edge)

        assert len(edges) == 1
        assert edges[0].permission == "Reader"
        assert edges[0].is_admin is False


class TestAzureProviderStorageDiscovery:
    """Test Azure storage account discovery (existing functionality)."""

    @pytest.fixture
    def authenticated_provider(self):
        """Create an authenticated Azure provider with mocked clients."""
        provider = AzureProvider(
            account_id=uuid4(),
            subscription_id="test-subscription-123",
        )

        provider._storage_client = MagicMock()
        provider._compute_client = MagicMock()
        provider._compute_client.virtual_machines.list_all.return_value = []
        provider._network_client = MagicMock()
        provider._network_client.network_security_groups.list_all.return_value = []
        provider._network_client.virtual_networks.list_all.return_value = []
        provider._auth_client = MagicMock()

        return provider

    @pytest.mark.asyncio
    async def test_discover_storage_accounts(self, authenticated_provider):
        """Test storage account discovery."""
        mock_account = MagicMock()
        mock_account.id = "/subscriptions/test/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/storage1"
        mock_account.name = "storage1"
        mock_account.kind = "StorageV2"
        mock_account.sku = MagicMock(name="Standard_LRS")
        mock_account.primary_location = "eastus"
        mock_account.location = "eastus"
        mock_account.tags = {}
        mock_account.creation_time = None

        authenticated_provider._storage_client.storage_accounts.list.return_value = [mock_account]
        authenticated_provider._storage_client.storage_accounts.get_properties.return_value = MagicMock(
            allow_blob_public_access=False,
            minimum_tls_version="TLS1_2",
            enable_https_traffic_only=True,
            network_rule_set=None,
        )

        resources = []
        async for resource in authenticated_provider.discover_resources(
            resource_types=["azure.storage.account"]
        ):
            resources.append(resource)

        assert len(resources) == 1
        assert resources[0].name == "storage1"
        assert resources[0].resource_type == "azure.storage.account"
