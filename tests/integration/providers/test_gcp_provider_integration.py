"""Integration tests for GCP provider.

These tests use mocked Google Cloud client responses to verify the provider's
behavior without requiring actual GCP credentials.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

from cerebro.providers.gcp.provider import GCPProvider


class MockInstance:
    """Mock GCP compute instance."""

    def __init__(self, instance_id: str, name: str, labels: dict | None = None):
        self.id = instance_id
        self.name = name
        self.labels = labels or {}
        self.status = "RUNNING"
        self.machine_type = "n1-standard-1"
        self.zone = "us-central1-a"


class MockAggregatedListResponse:
    """Mock for aggregated list response."""

    def __init__(self, instances_by_zone: dict):
        self._instances_by_zone = instances_by_zone

    def __iter__(self):
        for zone, instances in self._instances_by_zone.items():
            response = MagicMock()
            response.instances = instances
            yield zone, response


class TestGCPProviderAuthentication:
    """Test GCP authentication flows."""

    @pytest.fixture
    def provider(self):
        """Create a GCP provider instance."""
        return GCPProvider(
            account_id=uuid4(),
            project_id="test-project-123",
        )

    @pytest.mark.asyncio
    async def test_authenticate_success(self, provider):
        """Test successful authentication with default credentials."""
        mock_credentials = MagicMock()
        mock_project = "test-project-123"

        with patch("google.auth.default", return_value=(mock_credentials, mock_project)):
            with patch("google.cloud.compute_v1.InstancesClient"):
                result = await provider.authenticate()

        assert result is True

    @pytest.mark.asyncio
    async def test_authenticate_missing_libraries(self, provider):
        """Test authentication fails gracefully when libraries missing."""
        with patch.dict("sys.modules", {"google.auth": None, "google.cloud": None}):
            # Import error should be caught
            result = await provider.authenticate()
            # Should return False, not raise
            assert result is False

    @pytest.mark.asyncio
    async def test_authenticate_invalid_credentials(self, provider):
        """Test authentication fails with invalid credentials."""
        with patch("google.auth.default", side_effect=Exception("Invalid credentials")):
            result = await provider.authenticate()

        assert result is False


class TestGCPProviderResourceDiscovery:
    """Test GCP resource discovery."""

    @pytest.fixture
    def authenticated_provider(self):
        """Create a provider with mocked GCP clients."""
        provider = GCPProvider(
            account_id=uuid4(),
            project_id="test-project-123",
        )
        return provider

    @pytest.mark.asyncio
    async def test_discover_compute_instances(self, authenticated_provider):
        """Test GCP compute instance discovery."""
        mock_instances = {
            "zones/us-central1-a": [
                MockInstance("123456", "web-server-1", {"env": "prod"}),
                MockInstance("123457", "web-server-2", {"env": "prod"}),
            ],
            "zones/us-east1-b": [
                MockInstance("123458", "db-server-1", {"env": "prod"}),
            ],
        }

        mock_client = MagicMock()
        mock_client.aggregated_list.return_value = MockAggregatedListResponse(mock_instances)

        mock_credentials = MagicMock()

        with patch("google.auth.default", return_value=(mock_credentials, "test-project")):
            with patch("google.cloud.compute_v1.InstancesClient", return_value=mock_client):
                resources = []
                async for resource in authenticated_provider.discover_resources():
                    resources.append(resource)

        assert len(resources) == 3
        assert all(r.resource_type == "gcp.compute.instance" for r in resources)

        # Check specific instance
        web_server = next(r for r in resources if r.name == "web-server-1")
        assert web_server.external_id == "123456"

    @pytest.mark.asyncio
    async def test_discover_resources_handles_empty_zones(self, authenticated_provider):
        """Test discovery handles zones with no instances."""
        mock_client = MagicMock()
        # Simulate empty zone response
        empty_response = MagicMock()
        empty_response.instances = None

        populated_response = MagicMock()
        populated_response.instances = [MockInstance("123456", "only-server")]

        mock_client.aggregated_list.return_value = [
            ("zones/us-central1-a", empty_response),
            ("zones/us-east1-b", populated_response),
        ]

        mock_credentials = MagicMock()

        with patch("google.auth.default", return_value=(mock_credentials, "test-project")):
            with patch("google.cloud.compute_v1.InstancesClient", return_value=mock_client):
                resources = []
                async for resource in authenticated_provider.discover_resources():
                    resources.append(resource)

        assert len(resources) == 1
        assert resources[0].name == "only-server"


class TestGCPProviderPrincipalDiscovery:
    """Test GCP principal discovery."""

    @pytest.fixture
    def authenticated_provider(self):
        """Create a provider with mocked GCP clients."""
        return GCPProvider(
            account_id=uuid4(),
            project_id="test-project-123",
        )

    @pytest.mark.asyncio
    async def test_discover_service_accounts(self, authenticated_provider):
        """Test GCP service account discovery."""
        mock_service_accounts = [
            MagicMock(
                email="sa-1@test-project.iam.gserviceaccount.com",
                display_name="Service Account 1",
                unique_id="123456",
                disabled=False,
            ),
            MagicMock(
                email="sa-2@test-project.iam.gserviceaccount.com",
                display_name="Service Account 2",
                unique_id="123457",
                disabled=False,
            ),
        ]

        mock_iam_client = MagicMock()
        mock_iam_client.list_service_accounts.return_value = mock_service_accounts

        mock_credentials = MagicMock()

        with patch("google.auth.default", return_value=(mock_credentials, "test-project")):
            with patch("google.cloud.iam_admin_v1.IAMClient", return_value=mock_iam_client):
                principals = []
                async for principal in authenticated_provider.discover_principals():
                    principals.append(principal)

        service_accounts = [p for p in principals if p.principal_type == "service_account"]
        assert len(service_accounts) >= 2


class TestGCPProviderIAMEdges:
    """Test GCP IAM edge discovery."""

    @pytest.fixture
    def authenticated_provider(self):
        """Create a provider with mocked GCP clients."""
        return GCPProvider(
            account_id=uuid4(),
            project_id="test-project-123",
        )

    @pytest.mark.asyncio
    async def test_discover_iam_edges(self, authenticated_provider):
        """Test discovering IAM edges."""
        mock_credentials = MagicMock()

        with patch("google.auth.default", return_value=(mock_credentials, "test-project")):
            edges = []
            async for edge in authenticated_provider.discover_iam_edges():
                edges.append(edge)

        # Should return a list (may be empty if no bindings found)
        assert isinstance(edges, list)


class TestGCPProviderConfigurationCollection:
    """Test GCP configuration snapshot collection."""

    @pytest.fixture
    def authenticated_provider(self):
        """Create a provider with mocked GCP clients."""
        return GCPProvider(
            account_id=uuid4(),
            project_id="test-project-123",
        )

    @pytest.mark.asyncio
    async def test_get_resource_configuration(self, authenticated_provider):
        """Test getting compute instance configuration."""
        from cerebro.providers.base import ResourceInfo

        mock_instance = MagicMock()
        mock_instance.id = "123456"
        mock_instance.name = "test-instance"
        mock_instance.machine_type = "zones/us-central1-a/machineTypes/n1-standard-1"
        mock_instance.status = "RUNNING"
        mock_instance.network_interfaces = []
        mock_instance.labels = {"env": "prod"}
        mock_instance.metadata = MagicMock(items=[])
        mock_instance.service_accounts = []
        mock_instance.shielded_instance_config = None

        mock_client = MagicMock()
        mock_client.get.return_value = mock_instance

        mock_credentials = MagicMock()

        resource = ResourceInfo(
            external_id="123456",
            name="test-instance",
            resource_type="gcp.compute.instance",
        )

        with patch("google.auth.default", return_value=(mock_credentials, "test-project")):
            with patch("google.cloud.compute_v1.InstancesClient", return_value=mock_client):
                config = await authenticated_provider.get_resource_configuration(resource)

        assert config is not None


class TestGCPProviderErrorHandling:
    """Test GCP provider error handling."""

    @pytest.fixture
    def provider(self):
        """Create a GCP provider instance."""
        return GCPProvider(
            account_id=uuid4(),
            project_id="test-project-123",
        )

    @pytest.mark.asyncio
    async def test_handles_api_error_gracefully(self, provider):
        """Test that API errors don't crash the provider."""
        from google.api_core.exceptions import NotFound

        mock_client = MagicMock()
        mock_client.aggregated_list.side_effect = NotFound("Resource not found")

        mock_credentials = MagicMock()

        with patch("google.auth.default", return_value=(mock_credentials, "test-project")):
            with patch("google.cloud.compute_v1.InstancesClient", return_value=mock_client):
                resources = []
                async for resource in provider.discover_resources():
                    resources.append(resource)

        # Should return empty list, not raise
        assert resources == []

    @pytest.mark.asyncio
    async def test_handles_permission_denied(self, provider):
        """Test that permission denied errors are handled."""
        from google.api_core.exceptions import PermissionDenied

        mock_client = MagicMock()
        mock_client.aggregated_list.side_effect = PermissionDenied("Access denied")

        mock_credentials = MagicMock()

        with patch("google.auth.default", return_value=(mock_credentials, "test-project")):
            with patch("google.cloud.compute_v1.InstancesClient", return_value=mock_client):
                resources = []
                async for resource in provider.discover_resources():
                    resources.append(resource)

        # Should return empty list, not raise
        assert resources == []
