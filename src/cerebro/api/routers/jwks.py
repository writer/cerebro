"""JSON Web Key Set (JWKS) endpoint for public key distribution."""

import logging
from typing import Dict, Any
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.core.database import get_db
from cerebro.core.security.key_store import JWTKeyStore
from cerebro.core.config import settings
from cerebro.metrics.jwt_metrics import jwt_metrics
from cerebro.api.auth import require_admin

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Authentication"])


@router.get("/.well-known/jwks.json", response_model=Dict[str, Any])
async def get_jwks(db: AsyncSession = Depends(get_db)) -> JSONResponse:
    """
    Get JSON Web Key Set (JWKS) for token verification.
    
    This endpoint provides public keys that can be used to verify JWT tokens
    issued by this service. It follows the JWKS specification (RFC 7517).
    
    The response includes:
    - Current active signing keys
    - Recently rotated keys (within overlap period) 
    - Key metadata for proper verification
    
    Clients should cache this response and refresh periodically.
    """
    with jwt_metrics.time_jwks_request():
        try:
            key_store = JWTKeyStore(db)
            
            # Get JWKS response with public keys
            jwks_response = await key_store.get_jwks_response()
            
            # Add cache headers for performance
            headers = {
                "Cache-Control": f"public, max-age={settings.jwks_cache_ttl_seconds}",
                "Content-Type": "application/json"
            }
            
            logger.debug(f"Served JWKS with {len(jwks_response.get('keys', []))} keys")
            
            return JSONResponse(
                content=jwks_response,
                headers=headers
            )
            
        except Exception as e:
            logger.error(f"Failed to serve JWKS: {e}")
            raise HTTPException(
                status_code=500,
                detail="Failed to retrieve public keys"
            )


@router.get("/.well-known/openid_configuration")
async def get_openid_configuration() -> Dict[str, Any]:
    """
    OpenID Connect Discovery endpoint.
    
    Provides metadata about the JWT issuer for automatic client configuration.
    This is optional but helpful for OAuth/OIDC clients.
    """
    try:
        from cerebro.core.config import settings
        
        base_url = "https://your-cerebro-domain.com"  # TODO: Make configurable
        
        return {
            "issuer": "cerebro.sor",
            "jwks_uri": f"{base_url}/.well-known/jwks.json",
            "authorization_endpoint": f"{base_url}/api/v1/auth/login",
            "token_endpoint": f"{base_url}/api/v1/auth/token",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": [settings.jwt_algorithm],
            "token_endpoint_auth_methods_supported": ["client_secret_post"],
            "scopes_supported": [
                "openid", "read:organizations", "write:organizations", 
                "read:findings", "write:findings", "read:rules", "write:rules",
                "collect:data", "query:execute"
            ]
        }
        
    except Exception as e:
        logger.error(f"Failed to serve OpenID configuration: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve OpenID configuration"
        )


@router.get("/auth/jwks-debug")
async def debug_jwks(
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_admin)
) -> Dict[str, Any]:
    """
    Debug endpoint for JWT key information (admin only in production).
    
    Provides detailed information about current signing keys for troubleshooting.
    Should be protected or removed in production.
    """
    try:
        key_store = JWTKeyStore(db)
        
        # Get current signing key
        current_key = await key_store.get_current_signing_key()
        verification_keys = await key_store.get_verification_keys()
        
        return {
            "current_key": {
                "kid": current_key.kid if current_key else None,
                "algorithm": current_key.algorithm if current_key else None,
                "created_at": current_key.created_at.isoformat() if current_key else None,
                "expires_at": current_key.expires_at.isoformat() if current_key and current_key.expires_at else None,
            } if current_key else None,
            "verification_keys_count": len(verification_keys),
            "verification_keys": [
                {
                    "kid": key.kid,
                    "algorithm": key.algorithm,
                    "created_at": key.created_at.isoformat(),
                    "expires_at": key.expires_at.isoformat() if key.expires_at else None,
                }
                for key in verification_keys
            ],
            "settings": {
                "jwt_algorithm": settings.jwt_algorithm,
                "rotation_period_hours": settings.jwt_rotation_period_hours,
                "key_overlap_hours": settings.jwt_key_overlap_hours,
            }
        }
        
    except Exception as e:
        logger.error(f"Failed to serve JWKS debug info: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve key debug information"
        )
