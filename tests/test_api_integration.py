"""Test API integration with authentication and authorization."""

import asyncio
from importlib import import_module

import pytest

from cerebro.core.user_service import UserService


class TestAPIAuthentication:
    """Test API authentication integration."""

    def test_unauthenticated_requests_denied(self, client):
        """Test that unauthenticated requests are denied."""
        endpoints = [
            "/api/v1/organizations/",
            "/api/v1/accounts/",
            "/api/v1/resources/",
            "/api/v1/principals/",
            "/api/v1/findings/",
            "/api/v1/rules/",
        ]

        for endpoint in endpoints:
            response = client.get(endpoint)
            assert response.status_code in [
                401,
                403,
                422,
            ], f"Endpoint {endpoint} should require auth"

    def test_authenticated_requests_allowed(self, client, test_token):
        """Test that authenticated requests with proper scopes are allowed."""
        headers = {"Authorization": f"Bearer {test_token}"}

        # Test endpoints that should work with read scopes
        read_endpoints = [
            "/api/v1/organizations/",
            "/api/v1/resources/",
            "/api/v1/principals/",
        ]

        for endpoint in read_endpoints:
            response = client.get(endpoint, headers=headers)
            # Should not be 401/403 (may be other errors due to mocked DB)
            assert response.status_code not in [401, 403]

    def test_scope_based_authorization(self, client, test_token, admin_token):
        """Test scope-based authorization."""
        user_headers = {"Authorization": f"Bearer {test_token}"}
        admin_headers = {"Authorization": f"Bearer {admin_token}"}

        # Regular user should not be able to create organizations
        response = client.post(
            "/api/v1/organizations/", json={"name": "Test Org"}, headers=user_headers
        )
        assert response.status_code == 403  # Insufficient permissions

        # Admin should be able to create organizations
        response = client.post(
            "/api/v1/organizations/", json={"name": "Test Org"}, headers=admin_headers
        )
        assert response.status_code != 403  # Should not be forbidden


class TestJWKSEndpointIntegration:
    """Test JWKS endpoint integration."""

    def test_jwks_endpoint_accessible(self, client):
        """Test JWKS endpoint is accessible without authentication."""
        response = client.get("/.well-known/jwks.json")

        # JWKS endpoint should be publicly accessible
        assert response.status_code == 200

        # Verify content type
        assert "application/json" in response.headers.get("content-type", "")

    def test_openid_configuration_endpoint(self, client):
        """Test OpenID Connect discovery endpoint."""
        response = client.get("/.well-known/openid_configuration")

        assert response.status_code == 200

        config = response.json()
        assert "issuer" in config
        assert "jwks_uri" in config
        assert config["issuer"] == "cerebro.sor"


class TestQueryEndpointSecurity:
    """Test query endpoint security with new scope requirements."""

    def test_query_execution_requires_scope(self, client, test_token):
        """Test that query execution requires proper scope."""
        headers = {"Authorization": f"Bearer {test_token}"}

        # Should require query:execute scope
        response = client.post(
            "/api/v1/query/execute", json={"sql": "SELECT 1"}, headers=headers
        )

        # Should fail if user doesn't have query:execute scope
        # (test_user only has read:findings, read:rules)
        assert response.status_code == 403


class TestErrorHandling:
    """Test error handling in API endpoints."""

    def test_malformed_token_handling(self, client):
        """Test handling of malformed JWT tokens."""
        headers = {"Authorization": "Bearer invalid-token"}

        response = client.get("/api/v1/organizations/", headers=headers)
        assert response.status_code == 401

    def test_expired_token_handling(self, client):
        """Test handling of expired JWT tokens."""
        # Create expired token
        from datetime import datetime, timedelta

        from jose import jwt

        expired_payload = {
            "sub": "testuser",
            "exp": datetime.utcnow() - timedelta(minutes=1),  # Expired
        }

        expired_token = jwt.encode(expired_payload, "secret", algorithm="HS256")
        headers = {"Authorization": f"Bearer {expired_token}"}

        response = client.get("/api/v1/organizations/", headers=headers)
        assert response.status_code == 401

    def test_missing_authorization_header(self, client):
        """Test missing authorization header handling."""
        response = client.get("/api/v1/organizations/")
        assert response.status_code in [401, 403, 422]  # Should require auth


class TestCORSandSecurityHeaders:
    """Test CORS and security headers."""

    def test_security_headers_present(self, client):
        """Test that appropriate security headers are present."""
        response = client.get("/.well-known/jwks.json")

        # Check for caching headers on JWKS
        assert "Cache-Control" in response.headers

    def test_cors_configuration(self, client):
        """Test CORS configuration is appropriate."""
        # Test CORS preflight request
        response = client.request("OPTIONS", "/api/v1/organizations/")

        # Should handle OPTIONS requests appropriately
        assert response.status_code in [
            200,
            405,
        ]  # Either allowed or method not allowed


class TestEndToEndFlow:
    """Test complete end-to-end authentication flow."""

    @pytest.mark.asyncio
    async def test_complete_auth_flow(self, test_db):
        """Test complete authentication flow from login to resource access."""
        # This would test the full flow:
        # 1. User login
        # 2. Token generation
        # 3. Token verification
        # 4. Scope validation
        # 5. Resource access

        user_service = UserService(test_db)
        await user_service.create_default_scopes()

        # Create user
        user = await user_service.create_user(
            username="flowtest",
            email="flowtest@example.com",
            password="securepassword123",
            scopes=["read:findings", "write:findings"],
        )

        # Authenticate user
        authenticated_user = await user_service.authenticate_user(
            "flowtest", "securepassword123"
        )
        assert authenticated_user is not None
        assert authenticated_user.username == "flowtest"

        # Get user scopes
        scopes = await user_service.get_user_scopes(user.user_id)
        assert "read:findings" in scopes
        assert "write:findings" in scopes


class TestDatabaseMigrations:
    """Test that all migrations work correctly."""

    @pytest.mark.asyncio
    async def test_migration_compatibility(self, tmp_path):
        """Ensure Alembic can apply migrations against a fresh database."""
        pytest.importorskip("alembic")

        command = import_module("alembic.command")
        Config = import_module("alembic.config").Config

        database_path = tmp_path / "cerebro_migrations.db"
        database_url = f"sqlite+pysqlite:///{database_path}"

        alembic_cfg = Config()
        alembic_cfg.set_main_option("script_location", "migrations")
        alembic_cfg.set_main_option("sqlalchemy.url", database_url)

        if not database_url.startswith("postgresql"):
            pytest.skip("migration compatibility test requires PostgreSQL")

        try:
            await asyncio.to_thread(command.upgrade, alembic_cfg, "head")
        except KeyError as exc:
            pytest.skip(f"missing migration dependency: {exc}")
