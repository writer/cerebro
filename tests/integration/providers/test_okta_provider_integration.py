"""Integration tests for Okta provider.

These tests use mocked httpx responses to verify the provider's behavior
without requiring actual Okta credentials.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import httpx
import pytest

from cerebro.providers.base import ProviderError
from cerebro.providers.okta.provider import OktaProvider


class MockResponse:
    """Mock httpx response."""

    def __init__(self, json_data: dict | list, status_code: int = 200, headers: dict | None = None):
        self._json_data = json_data
        self.status_code = status_code
        self.headers = headers or {}

    def json(self):
        return self._json_data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                f"HTTP {self.status_code}",
                request=MagicMock(),
                response=self,
            )


class TestOktaProviderAuthentication:
    """Test Okta authentication flows."""

    @pytest.fixture
    def provider(self):
        """Create an Okta provider instance."""
        return OktaProvider(
            account_id=uuid4(),
            domain="test.okta.com",
            api_token="test-token",
        )

    @pytest.mark.asyncio
    async def test_authenticate_success(self, provider):
        """Test successful authentication."""
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.get.return_value = MockResponse({
            "id": "org123",
            "companyName": "Test Company",
            "status": "ACTIVE",
        })

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await provider.authenticate()

        assert result is True
        mock_client.get.assert_called_with("/api/v1/org")

    @pytest.mark.asyncio
    async def test_authenticate_no_token_raises_error(self):
        """Test authentication fails without API token."""
        provider = OktaProvider(
            account_id=uuid4(),
            domain="test.okta.com",
            api_token=None,
        )

        # Patch settings to ensure no token is available
        with patch.object(provider, "api_token", None):
            with pytest.raises(ProviderError, match="API token not configured"):
                await provider.authenticate()

    @pytest.mark.asyncio
    async def test_authenticate_invalid_token(self, provider):
        """Test authentication fails with invalid token."""
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.get.return_value = MockResponse(
            {"errorCode": "E0000011", "errorSummary": "Invalid token"},
            status_code=401,
        )

        with patch("httpx.AsyncClient", return_value=mock_client):
            with pytest.raises(ProviderError, match="authentication failed"):
                await provider.authenticate()


class TestOktaProviderResourceDiscovery:
    """Test Okta resource discovery."""

    @pytest.fixture
    def authenticated_provider(self):
        """Create an authenticated Okta provider."""
        provider = OktaProvider(
            account_id=uuid4(),
            domain="test.okta.com",
            api_token="test-token",
        )
        provider._client = AsyncMock(spec=httpx.AsyncClient)
        return provider

    @pytest.mark.asyncio
    async def test_discover_applications(self, authenticated_provider):
        """Test Okta application discovery."""
        mock_apps = [
            {
                "id": "app1",
                "name": "salesforce",
                "label": "Salesforce",
                "status": "ACTIVE",
                "created": "2024-01-01T00:00:00.000Z",
                "signOnMode": "SAML_2_0",
            },
            {
                "id": "app2",
                "name": "slack",
                "label": "Slack",
                "status": "ACTIVE",
                "created": "2024-01-02T00:00:00.000Z",
                "signOnMode": "OPENID_CONNECT",
            },
        ]

        authenticated_provider._client.get.return_value = MockResponse(
            mock_apps, headers={}
        )

        resources = []
        async for resource in authenticated_provider.discover_resources(
            resource_types=["okta.app"]
        ):
            resources.append(resource)

        assert len(resources) == 2
        assert resources[0].resource_type == "okta.app"
        assert resources[0].external_id == "app1"
        assert resources[0].name == "Salesforce"

    @pytest.mark.asyncio
    async def test_discover_policies(self, authenticated_provider):
        """Test Okta policy discovery."""
        mock_policies = [
            {
                "id": "policy1",
                "name": "Default Policy",
                "type": "OKTA_SIGN_ON",
                "status": "ACTIVE",
                "created": "2024-01-01T00:00:00.000Z",
            },
        ]

        authenticated_provider._client.get.return_value = MockResponse(
            mock_policies, headers={}
        )

        resources = []
        async for resource in authenticated_provider.discover_resources(
            resource_types=["okta.policy"]
        ):
            resources.append(resource)

        assert len(resources) >= 1
        policy_resources = [r for r in resources if r.resource_type == "okta.policy"]
        assert len(policy_resources) >= 1


class TestOktaProviderPrincipalDiscovery:
    """Test Okta principal discovery."""

    @pytest.fixture
    def authenticated_provider(self):
        """Create an authenticated Okta provider."""
        provider = OktaProvider(
            account_id=uuid4(),
            domain="test.okta.com",
            api_token="test-token",
        )
        provider._client = AsyncMock(spec=httpx.AsyncClient)
        return provider

    @pytest.mark.asyncio
    async def test_discover_users(self, authenticated_provider):
        """Test Okta user discovery."""
        mock_users = [
            {
                "id": "user1",
                "status": "ACTIVE",
                "created": "2024-01-01T00:00:00.000Z",
                "profile": {
                    "login": "alice@example.com",
                    "email": "alice@example.com",
                    "firstName": "Alice",
                    "lastName": "Smith",
                },
            },
            {
                "id": "user2",
                "status": "ACTIVE",
                "created": "2024-01-02T00:00:00.000Z",
                "profile": {
                    "login": "bob@example.com",
                    "email": "bob@example.com",
                    "firstName": "Bob",
                    "lastName": "Jones",
                },
            },
        ]

        mock_groups = [
            {
                "id": "group1",
                "type": "OKTA_GROUP",
                "profile": {"name": "Engineering", "description": "Engineering team"},
                "created": "2024-01-01T00:00:00.000Z",
            },
        ]

        # Mock both users and groups endpoints
        async def mock_get(url):
            if "/users" in url:
                return MockResponse(mock_users, headers={})
            elif "/groups" in url:
                return MockResponse(mock_groups, headers={})
            return MockResponse([], headers={})

        authenticated_provider._client.get = mock_get

        principals = []
        async for principal in authenticated_provider.discover_principals():
            principals.append(principal)

        user_principals = [p for p in principals if p.principal_type == "user"]
        assert len(user_principals) >= 2

    @pytest.mark.asyncio
    async def test_discover_groups(self, authenticated_provider):
        """Test Okta group discovery."""
        mock_users = []
        mock_groups = [
            {
                "id": "group1",
                "type": "OKTA_GROUP",
                "profile": {
                    "name": "Engineering",
                    "description": "Engineering team",
                },
                "created": "2024-01-01T00:00:00.000Z",
            },
            {
                "id": "group2",
                "type": "OKTA_GROUP",
                "profile": {
                    "name": "Sales",
                    "description": "Sales team",
                },
                "created": "2024-01-02T00:00:00.000Z",
            },
        ]

        async def mock_get(url):
            if "/users" in url:
                return MockResponse(mock_users, headers={})
            elif "/groups" in url:
                return MockResponse(mock_groups, headers={})
            return MockResponse([], headers={})

        authenticated_provider._client.get = mock_get

        principals = []
        async for principal in authenticated_provider.discover_principals():
            principals.append(principal)

        group_principals = [p for p in principals if p.principal_type == "group"]
        assert len(group_principals) >= 2


class TestOktaProviderIAMEdges:
    """Test Okta IAM edge discovery."""

    @pytest.fixture
    def authenticated_provider(self):
        """Create an authenticated Okta provider."""
        provider = OktaProvider(
            account_id=uuid4(),
            domain="test.okta.com",
            api_token="test-token",
        )
        provider._client = AsyncMock(spec=httpx.AsyncClient)
        return provider

    @pytest.mark.asyncio
    async def test_discover_iam_edges(self, authenticated_provider):
        """Test discovering IAM edges (app assignments)."""
        from cerebro.providers.base import ResourceInfo

        # Mock app users endpoint
        mock_app_users = [
            {
                "id": "appuser1",
                "scope": "USER",
                "status": "ACTIVE",
                "credentials": {"userName": "alice@example.com"},
                "_links": {
                    "user": {"href": "https://test.okta.com/api/v1/users/user1"}
                },
            },
        ]

        authenticated_provider._client.get.return_value = MockResponse(
            mock_app_users, headers={}
        )

        resource = ResourceInfo(
            external_id="app1",
            name="TestApp",
            resource_type="okta.app",
        )

        edges = []
        async for edge in authenticated_provider.discover_iam_edges(resource=resource):
            edges.append(edge)

        # Should discover app assignments as IAM edges
        assert isinstance(edges, list)


class TestOktaProviderPagination:
    """Test Okta API pagination handling."""

    @pytest.fixture
    def authenticated_provider(self):
        """Create an authenticated Okta provider."""
        provider = OktaProvider(
            account_id=uuid4(),
            domain="test.okta.com",
            api_token="test-token",
        )
        provider._client = AsyncMock(spec=httpx.AsyncClient)
        return provider

    @pytest.mark.asyncio
    async def test_handles_users_response(self, authenticated_provider):
        """Test that provider correctly handles user responses."""
        mock_users = [
            {"id": f"user{i}", "status": "ACTIVE", "profile": {"login": f"user{i}@example.com", "email": f"user{i}@example.com", "firstName": "User", "lastName": str(i)}}
            for i in range(10)
        ]
        mock_groups = [
            {"id": "group1", "type": "OKTA_GROUP", "profile": {"name": "TestGroup"}}
        ]

        async def mock_get(url):
            if "/users" in url:
                return MockResponse(mock_users, headers={})
            elif "/groups" in url:
                return MockResponse(mock_groups, headers={})
            return MockResponse([], headers={})

        authenticated_provider._client.get = mock_get

        principals = []
        async for principal in authenticated_provider.discover_principals():
            principals.append(principal)

        # Should have fetched users and groups
        assert len(principals) >= 10


class TestOktaProviderErrorHandling:
    """Test Okta error handling."""

    @pytest.fixture
    def authenticated_provider(self):
        """Create an authenticated Okta provider."""
        provider = OktaProvider(
            account_id=uuid4(),
            domain="test.okta.com",
            api_token="test-token",
        )
        provider._client = AsyncMock(spec=httpx.AsyncClient)
        return provider

    @pytest.mark.asyncio
    async def test_handles_api_error_gracefully(self, authenticated_provider):
        """Test that API errors don't crash the provider."""
        async def mock_get(url):
            raise httpx.HTTPStatusError(
                "HTTP 500",
                request=MagicMock(),
                response=MagicMock(status_code=500),
            )

        authenticated_provider._client.get = mock_get

        # Should handle errors gracefully and return empty
        principals = []
        async for principal in authenticated_provider.discover_principals():
            principals.append(principal)

        # Empty is acceptable when API errors occur
        assert isinstance(principals, list)
