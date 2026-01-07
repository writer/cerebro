"""Enhanced JWT service with RS256, proper claims, and revocation support."""

import time
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import redis.asyncio as redis
import structlog
from cryptography.hazmat.primitives import serialization
from jose import JWTError, jwt

from cerebro.core.config import settings

from .key_store import JWTKeyStore

logger = structlog.get_logger(__name__)


class JWTService:
    """Production-ready JWT service with RS256, key rotation, and revocation."""

    def __init__(self, key_store: JWTKeyStore, metrics=None):
        """Initialize JWT service.

        Args:
            key_store: JWT key store instance
            metrics: Optional metrics instance (injected by caller)
        """
        self.key_store = key_store
        self._redis_client: redis.Redis | None = None
        self.metrics = metrics
        self._public_key_cache: dict[str, tuple[str, float]] = {}

    async def _get_redis(self) -> redis.Redis:
        """Get Redis client for token revocation."""
        if not self._redis_client:
            self._redis_client = redis.from_url(
                settings.redis_url, encoding="utf-8", decode_responses=True
            )
        return self._redis_client

    async def create_token(
        self,
        username: str,
        scopes: list[str],
        expires_delta: timedelta | None = None,
        *,
        token_type: str = "access",
        org_id: UUID | None = None,
        extra_claims: dict[str, Any] | None = None,
    ) -> str:
        """Create a JWT token with full security claims."""
        try:
            # Get current signing key
            signing_key = await self.key_store.get_current_signing_key()
            if not signing_key:
                # Create initial key if none exists
                signing_key = await self.key_store.create_new_signing_key()

            # Generate unique token ID for revocation support
            jti = str(uuid4())

            # Calculate expiration
            if expires_delta:
                expire = datetime.now(UTC) + expires_delta
            else:
                expire = datetime.now(UTC) + timedelta(
                    minutes=settings.access_token_expire_minutes
                )

            # Build JWT claims with security best practices
            now = datetime.now(UTC)
            skew = max(settings.jwt_clock_skew_seconds, 5)
            exp_claim = int(
                (
                    expire - timedelta(seconds=settings.jwt_clock_skew_seconds)
                ).timestamp()
            )

            claims: dict[str, Any] = {
                # Standard claims
                "sub": username,  # Subject (user identifier)
                "iss": "cerebro.sor",  # Issuer
                "aud": "cerebro.api",  # Audience
                "iat": int(now.timestamp()),  # Issued at
                "exp": max(exp_claim, int(now.timestamp()) + 1),  # Expires
                "nbf": int((now - timedelta(seconds=skew)).timestamp()),
                "jti": jti,  # JWT ID (for revocation)
                # Custom claims
                "scopes": scopes,  # User permissions
                "token_type": token_type,  # Token type
            }

            if org_id is not None:
                claims["org_id"] = str(org_id)

            if extra_claims:
                claims.update(extra_claims)

            # Get private key for signing
            private_key_bytes = await self.key_store.get_private_key(signing_key)
            # Create JWT with proper headers
            token = jwt.encode(
                claims=claims,
                key=private_key_bytes,
                algorithm=settings.jwt_algorithm,
                headers={
                    "kid": signing_key.kid,  # Key ID for verification
                    "alg": settings.jwt_algorithm,
                    "typ": "JWT",
                },
            )

            # Record metrics
            if self.metrics:
                self.metrics.record_token_issued(
                    settings.jwt_algorithm, signing_key.kid
                )

            logger.debug(
                f"Created JWT token for user {username} with kid {signing_key.kid}"
            )
            return token

        except (OSError, RuntimeError, ValueError) as e:
            logger.error(f"Failed to create JWT token for user {username}: {e}")
            raise

    async def verify_token(
        self, token: str, expected_type: str | None = None
    ) -> dict[str, Any]:
        """Verify JWT token with comprehensive security checks."""
        # Optional metrics timing
        if self.metrics:
            with self.metrics.time_token_verification():
                return await self._verify_token_impl(token, expected_type)
        else:
            return await self._verify_token_impl(token, expected_type)

    async def _verify_token_impl(
        self, token: str, expected_type: str | None = None
    ) -> dict[str, Any]:
        """Internal token verification implementation."""
        try:
            # Decode header to get key ID without verification
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get("kid")
            algorithm = unverified_header.get("alg", "unknown")

            if not kid:
                raise JWTError("Token missing key ID (kid) in header")

            # Get signing key by ID
            signing_key = await self.key_store.get_key_by_kid(kid)
            if not signing_key:
                raise JWTError(f"Unknown signing key: {kid}")

            cache_entry = self._public_key_cache.get(signing_key.kid)
            now_ts = time.time()
            public_key_pem: str | None = None

            if cache_entry:
                cached_key, expires_at = cache_entry
                if expires_at > now_ts:
                    public_key_pem = cached_key
                    if self.metrics:
                        self.metrics.record_public_key_cache("hit")
                else:
                    if self.metrics:
                        self.metrics.record_public_key_cache("expired")
                    self._public_key_cache.pop(signing_key.kid, None)

            if public_key_pem is None:
                private_key_bytes = await self.key_store.get_private_key(signing_key)
                private_key = serialization.load_pem_private_key(
                    private_key_bytes, password=None
                )
                public_key_pem = (
                    private_key.public_key()
                    .public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                    .decode()
                )
                ttl = max(settings.jwt_public_key_cache_ttl_seconds, 0)
                if ttl:
                    self._public_key_cache[signing_key.kid] = (
                        public_key_pem,
                        now_ts + ttl,
                    )
                if self.metrics:
                    self.metrics.record_public_key_cache("miss")

            # Verify and decode token
            payload = jwt.decode(
                token=token,
                key=public_key_pem,
                algorithms=[signing_key.algorithm],
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_aud": True,
                    "verify_iss": True,
                    "leeway": settings.jwt_clock_skew_seconds,
                },
                audience="cerebro.api",
                issuer="cerebro.sor",
            )

            exp_claim = payload.get("exp")
            if exp_claim is not None:
                current_ts = datetime.now(UTC).timestamp()
                if current_ts > exp_claim + settings.jwt_clock_skew_seconds:
                    raise JWTError("Token expired")

            # Additional security checks
            jti = payload.get("jti")
            if not jti:
                raise JWTError("Token missing JWT ID (jti)")

            token_type = payload.get("token_type")
            if expected_type and token_type != expected_type:
                raise JWTError("Token type mismatch")

            # Check if token is revoked
            if await self._is_token_revoked(jti):
                raise JWTError("Token has been revoked")

            username = payload.get("sub")
            if isinstance(username, str) and await self._is_user_blocked(username):
                if self.metrics:
                    self.metrics.record_token_verified("revoked", algorithm, kid)
                raise JWTError("Token revoked due to user block")

            # Update verification metrics
            if self.metrics:
                self.metrics.record_token_verified("success", algorithm, kid)

            return payload

        except JWTError as e:
            logger.debug(f"JWT verification failed: {e}")
            raise
        except (OSError, RuntimeError, ValueError) as e:
            logger.error(f"Unexpected error verifying JWT: {e}")
            raise JWTError(f"Token verification failed: {e}") from e


    async def revoke_token(self, token: str, reason: str = "logout") -> bool:
        """Revoke a JWT token by adding its jti to revocation list."""
        try:
            # Extract jti without full verification (for revocation purposes)
            unverified_payload = jwt.get_unverified_claims(token)
            jti = unverified_payload.get("jti")
            exp = unverified_payload.get("exp")

            if not jti:
                logger.warning("Cannot revoke token without jti")
                return False

            # Calculate TTL based on token expiration
            now = int(time.time())
            ttl = (
                max(exp - now, 0) if exp else settings.access_token_expire_minutes * 60
            )

            # Add to Redis revocation set with TTL
            redis_client = await self._get_redis()
            await redis_client.setex(f"revoked:jwt:{jti}", ttl, reason)

            if self.metrics:
                self.metrics.record_token_revoked(reason)

            logger.info(f"Revoked JWT token {jti} (reason: {reason})")
            return True

        except (OSError, ConnectionError, TimeoutError) as e:
            logger.error(f"Failed to revoke token: {e}")
            return False

    async def revoke_user_tokens(
        self, username: str, reason: str = "admin_action"
    ) -> int:
        """Revoke all tokens for a specific user (emergency use)."""
        # Note: This would require maintaining a user->jti mapping in Redis
        # For now, we'll implement a simpler approach by adding the user to a blocklist
        # with a TTL equal to the longest possible token lifetime

        try:
            redis_client = await self._get_redis()
            ttl = (
                settings.access_token_expire_minutes * 60 * 2
            )  # 2x token lifetime for safety

            await redis_client.setex(f"blocked:user:{username}", ttl, reason)

            if self.metrics:
                self.metrics.record_token_revoked(reason)

            logger.warning(f"Blocked all tokens for user {username} (reason: {reason})")
            return 1  # We don't track exact count for user-level blocks

        except (OSError, ConnectionError, TimeoutError) as e:
            logger.error(f"Failed to block user tokens for {username}: {e}")
            return 0

    async def _is_token_revoked(self, jti: str) -> bool:
        """Check if a token is revoked by looking up its jti."""
        try:
            redis_client = await self._get_redis()

            # Check specific token revocation
            is_revoked = await redis_client.exists(f"revoked:jwt:{jti}")

            return bool(is_revoked)

        except (OSError, ConnectionError, TimeoutError) as e:
            logger.warning(f"Failed to check token revocation status for {jti}: {e}")
            # Fail open for availability, but log the issue
            return False

    async def _is_user_blocked(self, username: str) -> bool:
        """Check if all tokens for a user are blocked."""
        try:
            redis_client = await self._get_redis()

            is_blocked = await redis_client.exists(f"blocked:user:{username}")

            return bool(is_blocked)

        except (OSError, ConnectionError, TimeoutError) as e:
            logger.warning(f"Failed to check user block status for {username}: {e}")
            return False

    async def cleanup_expired_revocations(self) -> int:
        """Clean up expired token revocations from Redis."""
        try:
            redis_client = await self._get_redis()

            # Redis automatically expires keys with TTL, but we can scan and count
            # This is mainly for metrics and monitoring
            cursor = 0
            expired_count = 0

            while True:
                cursor, keys = await redis_client.scan(
                    cursor=cursor, match="revoked:jwt:*", count=1000
                )

                if keys:
                    # Check which keys actually exist (non-expired)
                    pipeline = redis_client.pipeline()
                    for key in keys:
                        pipeline.exists(key)

                    results = await pipeline.execute()
                    expired_count += sum(1 for exists in results if not exists)

                if cursor == 0:
                    break

            if expired_count > 0:
                if self.metrics:
                    self.metrics.record_revocation_cleanup(expired_count)

            return expired_count

        except (OSError, ConnectionError, TimeoutError) as e:
            logger.error(f"Failed to cleanup expired revocations: {e}")
            return 0

    async def get_token_info(self, token: str) -> dict[str, Any] | None:
        """Get token information without full verification (for debugging/admin)."""
        try:
            unverified_payload = jwt.get_unverified_claims(token)
            unverified_header = jwt.get_unverified_header(token)

            return {
                "header": unverified_header,
                "payload": {
                    "sub": unverified_payload.get("sub"),
                    "iss": unverified_payload.get("iss"),
                    "aud": unverified_payload.get("aud"),
                    "iat": unverified_payload.get("iat"),
                    "exp": unverified_payload.get("exp"),
                    "jti": unverified_payload.get("jti"),
                    "scopes": unverified_payload.get("scopes"),
                },
                "is_expired": unverified_payload.get("exp", 0) < time.time(),
            }

        except (ValueError, KeyError) as e:
            logger.debug(f"Failed to get token info: {e}")
            return None
