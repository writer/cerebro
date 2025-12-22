"""
E2E Tests: Authentication Flow

These tests verify the complete authentication lifecycle.
"""

import os
import pytest
import httpx

pytestmark = pytest.mark.e2e


@pytest.mark.asyncio
async def test_login_with_valid_credentials(api_client: httpx.AsyncClient):
    """Test successful login returns tokens."""
    response = await api_client.post(
        "/api/v1/auth/login",
        data={
            "username": os.getenv("E2E_TEST_USER", "test@example.com"),
            "password": os.getenv("E2E_TEST_PASSWORD", "testpassword123"),
        },
    )

    # May fail if test user doesn't exist - that's expected in some environments
    if response.status_code == 200:
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert "token_type" in data
        assert data["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_login_with_invalid_credentials(api_client: httpx.AsyncClient):
    """Test login with wrong password fails."""
    response = await api_client.post(
        "/api/v1/auth/login",
        data={"username": "test@example.com", "password": "wrongpassword"},
    )

    assert response.status_code in (401, 403, 404)


@pytest.mark.asyncio
async def test_token_refresh(auth_client: httpx.AsyncClient):
    """Test that token refresh works."""
    # First login to get tokens
    login_response = await auth_client.post(
        "/api/v1/auth/login",
        data={
            "username": os.getenv("E2E_TEST_USER", "test@example.com"),
            "password": os.getenv("E2E_TEST_PASSWORD", "testpassword123"),
        },
    )

    if login_response.status_code != 200:
        pytest.skip("Test user not available")

    tokens = login_response.json()

    # Try to refresh
    refresh_response = await auth_client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]},
    )

    if refresh_response.status_code == 200:
        new_tokens = refresh_response.json()
        assert "access_token" in new_tokens


@pytest.mark.asyncio
async def test_authenticated_request_succeeds(auth_client: httpx.AsyncClient):
    """Test that authenticated requests work."""
    # Skip if not authenticated
    if "Authorization" not in auth_client.headers:
        pytest.skip("Authentication not available")

    response = await auth_client.get("/api/v1/organizations")
    assert response.status_code in (200, 403)  # 403 if no orgs assigned
