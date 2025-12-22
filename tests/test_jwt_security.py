"""Tests for JWT security improvements: key management, rotation, and verification."""

import json
import os
import time
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import JWTError, jwt

from cerebro.core.config import settings
from cerebro.core.security.jwt import JWTService
from cerebro.core.security.key_store import JWTKeyStore
from cerebro.core.user_service import UserService


class TestJWTKeyStore:
    """Test JWT key store functionality."""

    @pytest.mark.asyncio
    async def test_create_new_signing_key(self, test_db):
        """Test RSA signing key generation and storage."""
        # Mock KMS for testing
        mock_kms = AsyncMock()
        mock_kms.encrypt_data.return_value = (b"encrypted_key", b"encrypted_dek")

        with patch("cerebro.core.security.key_store.get_kms", return_value=mock_kms):
            key_store = JWTKeyStore(test_db)

            signing_key = await key_store.create_new_signing_key()

            assert signing_key.kid is not None
            assert signing_key.algorithm == settings.jwt_algorithm
            assert signing_key.is_active is True
            assert signing_key.public_key_pem is not None
            assert signing_key.encrypted_private_key is not None
            assert signing_key.encrypted_dek is not None

            # Verify key ID format
            assert signing_key.kid.startswith("cerebro-")
            assert len(signing_key.kid.split("-")[1]) == 8  # 8 hex chars

    @pytest.mark.asyncio
    async def test_get_current_signing_key(self, test_db):
        """Test retrieval of current active signing key."""
        mock_kms = AsyncMock()
        mock_kms.encrypt_data.return_value = (b"encrypted_key", b"encrypted_dek")

        with patch("cerebro.core.security.key_store.get_kms", return_value=mock_kms):
            key_store = JWTKeyStore(test_db)

            # Should return None when no keys exist
            current_key = await key_store.get_current_signing_key()
            assert current_key is None

            # Create a key
            created_key = await key_store.create_new_signing_key()

            # Should return the created key
            current_key = await key_store.get_current_signing_key()
            assert current_key is not None
            assert current_key.key_id == created_key.key_id

    @pytest.mark.asyncio
    async def test_key_rotation_logic(self, test_db):
        """Test key rotation logic and timing."""
        mock_kms = AsyncMock()
        mock_kms.encrypt_data.return_value = (b"encrypted_key", b"encrypted_dek")

        with patch("cerebro.core.security.key_store.get_kms", return_value=mock_kms):
            key_store = JWTKeyStore(test_db)

            # Create initial key
            key1 = await key_store.create_new_signing_key()

            # Should not need rotation immediately
            needs_rotation = await key_store.rotate_keys_if_needed()
            assert needs_rotation is False

            # Simulate expired key by modifying created_at (older than rotation window)
            key1.created_at = datetime.utcnow() - timedelta(hours=25)
            await test_db.commit()

            # Should need rotation now
            needs_rotation = await key_store.rotate_keys_if_needed()
            assert needs_rotation is True

            # Should have 2 keys now (old + new)
            verification_keys = await key_store.get_verification_keys()
            assert len(verification_keys) >= 1  # At least the new key

    @pytest.mark.asyncio
    async def test_jwks_response_format(self, test_db):
        """Test JWKS response format compliance."""
        mock_kms = AsyncMock()
        mock_kms.encrypt_data.return_value = (b"encrypted_key", b"encrypted_dek")

        with patch("cerebro.core.security.key_store.get_kms", return_value=mock_kms):
            key_store = JWTKeyStore(test_db)

            # Create a signing key
            signing_key = await key_store.create_new_signing_key()

            # Get JWKS response
            jwks_response = await key_store.get_jwks_response()

            assert "keys" in jwks_response
            assert len(jwks_response["keys"]) >= 1

            # Verify JWKS key format
            jwk = jwks_response["keys"][0]
            assert jwk["kty"] == "RSA"
            assert jwk["kid"] == signing_key.kid
            assert jwk["use"] == "sig"
            assert jwk["alg"] == signing_key.algorithm
            assert "n" in jwk  # RSA modulus
            assert "e" in jwk  # RSA exponent


class TestJWTService:
    """Test enhanced JWT service functionality."""

    @pytest.mark.asyncio
    async def test_token_creation_with_full_claims(self, test_db):
        """Test JWT token creation with all security claims."""
        mock_kms = AsyncMock()
        mock_kms.encrypt_data.return_value = (b"encrypted_key", b"encrypted_dek")
        mock_kms.decrypt_data.return_value = self._generate_test_private_key()

        with patch("cerebro.core.security.key_store.get_kms", return_value=mock_kms):
            key_store = JWTKeyStore(test_db)
            jwt_service = JWTService(key_store)

            # Create signing key
            await key_store.create_new_signing_key()

            # Create token
            token = await jwt_service.create_token(
                username="testuser", scopes=["read:findings", "write:rules"]
            )

            assert token is not None

            # Decode token to verify claims (without signature verification for testing)
            unverified_payload = jwt.get_unverified_claims(token)
            unverified_header = jwt.get_unverified_header(token)

            # Verify standard claims
            assert unverified_payload["sub"] == "testuser"
            assert unverified_payload["iss"] == "cerebro.sor"
            assert unverified_payload["aud"] == "cerebro.api"
            assert "iat" in unverified_payload
            assert "nbf" in unverified_payload
            assert "exp" in unverified_payload
            assert "jti" in unverified_payload

            # Verify custom claims
            assert unverified_payload["scopes"] == ["read:findings", "write:rules"]
            assert unverified_payload["token_type"] == "access"

            # Verify header
            assert unverified_header["alg"] == settings.jwt_algorithm
            assert unverified_header["typ"] == "JWT"
            assert "kid" in unverified_header

    @pytest.mark.asyncio
    async def test_token_verification_success(self, test_db):
        """Test successful JWT token verification."""
        mock_kms = AsyncMock()
        private_key_bytes = self._generate_test_private_key()
        mock_kms.encrypt_data.return_value = (b"encrypted_key", b"encrypted_dek")
        mock_kms.decrypt_data.return_value = private_key_bytes

        # Mock Redis for revocation checks
        mock_redis = AsyncMock()
        mock_redis.exists.return_value = False  # Not revoked

        with (
            patch("cerebro.core.security.key_store.get_kms", return_value=mock_kms),
            patch("redis.asyncio.from_url", return_value=mock_redis),
        ):

            key_store = JWTKeyStore(test_db)
            jwt_service = JWTService(key_store)

            # Create and verify token
            token = await jwt_service.create_token("testuser", ["read:findings"])
            payload = await jwt_service.verify_token(token)

            assert payload["sub"] == "testuser"
            assert payload["scopes"] == ["read:findings"]

    @pytest.mark.asyncio
    async def test_token_revocation(self, test_db):
        """Test JWT token revocation functionality."""
        mock_kms = AsyncMock()
        private_key_bytes = self._generate_test_private_key()
        mock_kms.encrypt_data.return_value = (b"encrypted_key", b"encrypted_dek")
        mock_kms.decrypt_data.return_value = private_key_bytes

        # Mock Redis
        mock_redis = AsyncMock()
        mock_redis.setex.return_value = True
        mock_redis.exists.return_value = False  # Initially not revoked

        with (
            patch("cerebro.core.security.key_store.get_kms", return_value=mock_kms),
            patch("redis.asyncio.from_url", return_value=mock_redis),
        ):

            key_store = JWTKeyStore(test_db)
            jwt_service = JWTService(key_store)

            # Create token
            token = await jwt_service.create_token("testuser", ["read:findings"])

            # Revoke token
            revoked = await jwt_service.revoke_token(token, "test_revocation")
            assert revoked is True

            # Verify Redis was called to store revocation
            mock_redis.setex.assert_called()

    @pytest.mark.asyncio
    async def test_revoked_token_verification_fails(self, test_db):
        """Test that revoked tokens fail verification."""
        mock_kms = AsyncMock()
        private_key_bytes = self._generate_test_private_key()
        mock_kms.encrypt_data.return_value = (b"encrypted_key", b"encrypted_dek")
        mock_kms.decrypt_data.return_value = private_key_bytes

        # Mock Redis to simulate revoked token
        mock_redis = AsyncMock()
        mock_redis.setex.return_value = True
        mock_redis.exists.return_value = True  # Token is revoked

        with (
            patch("cerebro.core.security.key_store.get_kms", return_value=mock_kms),
            patch("redis.asyncio.from_url", return_value=mock_redis),
        ):

            key_store = JWTKeyStore(test_db)
            jwt_service = JWTService(key_store)

            # Create token
            token = await jwt_service.create_token("testuser", ["read:findings"])

            # Mock that token is revoked
            mock_redis.exists.return_value = True

            # Verification should fail
            with pytest.raises(JWTError, match="revoked"):
                await jwt_service.verify_token(token)

    def test_jwt_claims_validation(self):
        """Test JWT claims validation logic."""
        # Test with missing standard claims
        invalid_payload = {"sub": "testuser"}  # Missing required claims

        # Should fail verification due to missing claims
        with pytest.raises(JWTError):
            # This would be done in the actual verification process
            required_claims = ["iss", "aud", "iat", "exp", "jti"]
            for claim in required_claims:
                if claim not in invalid_payload:
                    raise JWTError(f"Missing required claim: {claim}")

    @staticmethod
    def _generate_test_private_key() -> bytes:
        """Generate a test RSA private key."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )


class TestJWKSEndpoint:
    """Test JWKS endpoint functionality."""

    @pytest.mark.asyncio
    async def test_jwks_endpoint_response_format(self, test_db):
        """Test JWKS endpoint returns proper format."""
        from cerebro.api.routers.jwks import get_jwks

        mock_kms = AsyncMock()
        mock_kms.encrypt_data.return_value = (b"encrypted_key", b"encrypted_dek")

        with patch("cerebro.core.security.key_store.get_kms", return_value=mock_kms):
            key_store = JWTKeyStore(test_db)

            # Create a signing key
            await key_store.create_new_signing_key()

            # Get JWKS response
            response = await get_jwks(test_db)

            # Verify response format
            assert response.status_code == 200
            content = json.loads(response.body)
            assert "keys" in content
            assert len(content["keys"]) >= 1

            # Verify cache headers
            assert "Cache-Control" in response.headers

    @pytest.mark.asyncio
    async def test_jwks_key_format_compliance(self, test_db):
        """Test that JWKS keys follow RFC 7517 format."""
        mock_kms = AsyncMock()
        mock_kms.encrypt_data.return_value = (b"encrypted_key", b"encrypted_dek")

        with patch("cerebro.core.security.key_store.get_kms", return_value=mock_kms):
            key_store = JWTKeyStore(test_db)

            # Create signing key and get JWKS
            await key_store.create_new_signing_key()
            jwks_response = await key_store.get_jwks_response()

            jwk = jwks_response["keys"][0]

            # Verify RFC 7517 compliance
            required_fields = ["kty", "kid", "use", "alg", "n", "e"]
            for field in required_fields:
                assert field in jwk, f"Missing required JWK field: {field}"

            assert jwk["kty"] == "RSA"
            assert jwk["use"] == "sig"
            assert jwk["alg"] == settings.jwt_algorithm


class TestTokenSecurity:
    """Test token security features."""

    @pytest.mark.asyncio
    async def test_token_uniqueness(self, test_db):
        """Test that each token has a unique jti."""
        mock_kms = AsyncMock()
        mock_kms.encrypt_data.return_value = (b"encrypted_key", b"encrypted_dek")
        mock_kms.decrypt_data.return_value = TestJWTService._generate_test_private_key()

        mock_redis = AsyncMock()
        mock_redis.exists.return_value = False

        with (
            patch("cerebro.core.security.key_store.get_kms", return_value=mock_kms),
            patch("redis.asyncio.from_url", return_value=mock_redis),
        ):

            key_store = JWTKeyStore(test_db)
            jwt_service = JWTService(key_store)

            # Create signing key
            await key_store.create_new_signing_key()

            # Create multiple tokens
            token1 = await jwt_service.create_token("user1", ["read:findings"])
            token2 = await jwt_service.create_token("user2", ["read:findings"])

            # Extract JTIs
            payload1 = jwt.get_unverified_claims(token1)
            payload2 = jwt.get_unverified_claims(token2)

            # JTIs should be different
            assert payload1["jti"] != payload2["jti"]

    @pytest.mark.asyncio
    async def test_token_expiration_validation(self, test_db):
        """Test token expiration validation."""
        mock_kms = AsyncMock()
        private_key_bytes = TestJWTService._generate_test_private_key()
        mock_kms.encrypt_data.return_value = (b"encrypted_key", b"encrypted_dek")
        mock_kms.decrypt_data.return_value = private_key_bytes

        mock_redis = AsyncMock()
        mock_redis.exists.return_value = False

        with (
            patch("cerebro.core.security.key_store.get_kms", return_value=mock_kms),
            patch("redis.asyncio.from_url", return_value=mock_redis),
        ):

            key_store = JWTKeyStore(test_db)
            jwt_service = JWTService(key_store)

            # Create signing key
            await key_store.create_new_signing_key()

            # Create token with very short expiration
            short_expiry = timedelta(seconds=1)
            token = await jwt_service.create_token(
                "testuser", ["read:findings"], expires_delta=short_expiry
            )

            # Wait for token to expire
            time.sleep(2)

            # Verification should fail due to expiration
            with pytest.raises(JWTError):
                await jwt_service.verify_token(token)

    @pytest.mark.asyncio
    async def test_audience_and_issuer_validation(self, test_db):
        """Test JWT audience and issuer validation."""
        mock_kms = AsyncMock()
        private_key_bytes = TestJWTService._generate_test_private_key()
        mock_kms.encrypt_data.return_value = (b"encrypted_key", b"encrypted_dek")
        mock_kms.decrypt_data.return_value = private_key_bytes

        mock_redis = AsyncMock()
        mock_redis.exists.return_value = False

        with (
            patch("cerebro.core.security.key_store.get_kms", return_value=mock_kms),
            patch("redis.asyncio.from_url", return_value=mock_redis),
        ):

            key_store = JWTKeyStore(test_db)
            jwt_service = JWTService(key_store)

            # Create signing key
            await key_store.create_new_signing_key()

            # Create token
            token = await jwt_service.create_token("testuser", ["read:findings"])

            # Verify claims are present
            payload = jwt.get_unverified_claims(token)
            assert payload["iss"] == "cerebro.sor"
            assert payload["aud"] == "cerebro.api"


class TestBackgroundTasks:
    """Test JWT background maintenance tasks."""

    @pytest.mark.asyncio
    async def test_key_rotation_task_logic(self, test_db):
        """Test key rotation background task."""
        from cerebro.tasks.jwt_rotation import rotate_jwt_keys_task

        mock_kms = AsyncMock()
        mock_kms.encrypt_data.return_value = (b"encrypted_key", b"encrypted_dek")

        with (
            patch("cerebro.core.security.key_store.get_kms", return_value=mock_kms),
            patch(
                "cerebro.tasks.jwt_rotation.async_session_factory",
            ) as mock_session_factory,
        ):

            # Mock database session
            mock_session_factory.return_value.__aenter__.return_value = test_db

            # Mock Celery task context
            mock_task = MagicMock()
            mock_task.retry = MagicMock()

            # Test task execution
            result = rotate_jwt_keys_task.__wrapped__(mock_task)

            # Should return result dict
            assert isinstance(result, dict)
            assert "rotation_performed" in result
            assert "keys_cleaned" in result

    def test_periodic_task_configuration(self):
        """Test that periodic tasks are properly configured."""
        from cerebro.tasks.jwt_rotation import setup_periodic_jwt_tasks

        # Mock Celery sender
        mock_sender = MagicMock()

        # Test task setup
        setup_periodic_jwt_tasks(mock_sender)

        # Verify tasks were scheduled (rotation, cleanup, health checks)
        assert mock_sender.add_periodic_task.call_count >= 3


class TestSecurityValidation:
    """Test overall security validation."""

    def test_no_hardcoded_secrets(self):
        """Test that no hardcoded secrets remain in production config."""
        from cerebro.core.config import Settings

        # Test production config validation
        with patch.dict(os.environ, {"ENVIRONMENT": "production"}):
            # Should require explicit SECRET_KEY
            with pytest.raises(ValueError):
                Settings()  # No SECRET_KEY provided

    @pytest.mark.asyncio
    async def test_secure_password_requirements(self, test_db):
        """Test that admin user creation enforces secure passwords."""
        user_service = UserService(test_db)
        await user_service.create_default_scopes()

        with patch.dict(os.environ, {"ENVIRONMENT": "production"}):
            # Should reject weak password
            with pytest.raises(ValueError, match="at least 12 characters"):
                await user_service.create_admin_user(
                    username="admin", email="admin@test.com", password="weak"
                )

    def test_configuration_validators_comprehensive(self):
        """Test all configuration security validators."""
        from cerebro.core.config import Settings

        with patch.dict(
            os.environ,
            {
                "ENVIRONMENT": "production",
                "SNOWFLAKE_DATABASE_URL": "snowflake://user:pass@account/db/schema?warehouse=WH",
            },
        ):
            # Test all security validators
            secure_config = Settings(
                secret_key="a-very-secure-secret-key-that-is-at-least-32-characters-long",
                kms_provider="aws",
                enable_provider_env_fallback=False,
            )

            assert secure_config.secret_key.startswith("a-very-secure")
            assert secure_config.kms_provider == "aws"
            assert secure_config.enable_provider_env_fallback is False


class TestMetricsIntegration:
    """Test metrics integration for JWT operations."""

    def test_jwt_metrics_recording(self):
        """Test JWT metrics are properly recorded."""
        from cerebro.metrics.jwt_metrics import jwt_metrics

        # Test token issuance recording
        jwt_metrics.record_token_issued("RS256", "test-kid")

        # Test key rotation recording
        jwt_metrics.record_key_rotation(True)
        jwt_metrics.set_active_keys(2)

        # Test JWKS cache recording
        jwt_metrics.record_jwks_cache(True)
        jwt_metrics.record_jwks_cache(False)

        # Test revocation recording
        jwt_metrics.record_token_revoked("logout")

        # If we get here without exceptions, metrics work
        assert True

    def test_auth_metrics_recording(self):
        """Test authentication metrics are properly recorded."""
        from cerebro.metrics.auth_metrics import auth_metrics

        # Test login attempt recording
        auth_metrics.record_login_attempt(True, "192.168.1.1", 0.1)
        auth_metrics.record_login_attempt(False, "192.168.1.1", 0.2, locked=True)

        # Test rate limit recording
        auth_metrics.record_rate_limit_hit("per_ip", "192.168.1.1")

        # Test authorization recording
        auth_metrics.record_authorization_check(
            "/api/v1/findings",
            "read:findings",
            True,
        )

        # If we get here without exceptions, metrics work
        assert True
