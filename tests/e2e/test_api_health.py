"""
E2E Tests: API Health and Basic Connectivity

These tests verify that the API is running and basic endpoints work.
"""

import pytest
import httpx

pytestmark = pytest.mark.e2e


@pytest.mark.asyncio
async def test_health_endpoint(api_client: httpx.AsyncClient):
    """Test that the health endpoint returns OK."""
    response = await api_client.get("/health")
    assert response.status_code == 200
    
    data = response.json()
    assert data.get("status") in ("ok", "healthy")


@pytest.mark.asyncio
async def test_openapi_spec_available(api_client: httpx.AsyncClient):
    """Test that OpenAPI spec is accessible."""
    response = await api_client.get("/api/v1/openapi.json")
    assert response.status_code == 200
    
    spec = response.json()
    assert "openapi" in spec
    assert "paths" in spec
    assert "info" in spec


@pytest.mark.asyncio
async def test_docs_endpoint(api_client: httpx.AsyncClient):
    """Test that API docs are accessible."""
    response = await api_client.get("/docs")
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_unauthenticated_request_rejected(api_client: httpx.AsyncClient):
    """Test that protected endpoints require authentication."""
    response = await api_client.get("/api/v1/findings")
    assert response.status_code in (401, 403)
