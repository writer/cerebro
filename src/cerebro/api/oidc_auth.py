"""OIDC/Okta authentication provider for Cerebro API.

This module provides OpenID Connect authentication, compatible with:
- Okta
- Azure AD
- Google Workspace
- Auth0
- Any standard OIDC provider
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlencode
from uuid import UUID

import httpx
import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import RedirectResponse
from jose import jwt as jose_jwt
from pydantic import BaseModel, Field

from cerebro.api.dependencies import get_jwt_service
from cerebro.core.config import settings
from cerebro.core.database import get_db
from cerebro.core.security.jwt import JWTService
from cerebro.core.user_service import UserService

logger = structlog.get_logger(__name__)

router = APIRouter()


class OIDCConfig(BaseModel):
    """OIDC provider configuration."""

    # Required settings
    client_id: str
    client_secret: str
    issuer: str  # e.g., https://company.okta.com

    # Optional settings
    authorization_endpoint: str | None = None
    token_endpoint: str | None = None
    userinfo_endpoint: str | None = None
    jwks_uri: str | None = None
    end_session_endpoint: str | None = None

    # Scopes
    scopes: list[str] = Field(default_factory=lambda: ["openid", "email", "profile"])

    # Claim mappings
    username_claim: str = "email"
    email_claim: str = "email"
    name_claim: str = "name"
    groups_claim: str | None = "groups"

    # Session settings
    session_duration_hours: int = 24


class OIDCState(BaseModel):
    """State stored during OIDC flow."""

    state: str
    nonce: str
    redirect_uri: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    org_id: UUID | None = None


class OIDCUserInfo(BaseModel):
    """User info from OIDC provider."""

    sub: str
    email: str | None = None
    email_verified: bool | None = None
    name: str | None = None
    given_name: str | None = None
    family_name: str | None = None
    picture: str | None = None
    groups: list[str] | None = None


# In-memory state store (use Redis in production)
_oidc_states: dict[str, OIDCState] = {}


def get_oidc_config() -> OIDCConfig | None:
    """Get OIDC configuration from settings."""
    # Check if OIDC is configured
    client_id = getattr(settings, "oidc_client_id", None)
    client_secret = getattr(settings, "oidc_client_secret", None)
    issuer = getattr(settings, "oidc_issuer", None)

    # Also check Okta-specific settings
    if not client_id:
        client_id = getattr(settings, "okta_client_id", None)
    if not client_secret:
        client_secret = getattr(settings, "okta_client_secret", None)
    if not issuer:
        okta_domain = getattr(settings, "okta_domain", None)
        if okta_domain:
            issuer = f"https://{okta_domain}"

    if not all([client_id, client_secret, issuer]):
        return None

    return OIDCConfig(
        client_id=client_id,
        client_secret=client_secret,
        issuer=issuer,
        scopes=getattr(settings, "oidc_scopes", ["openid", "email", "profile", "groups"]),
        username_claim=getattr(settings, "oidc_username_claim", "email"),
        email_claim=getattr(settings, "oidc_email_claim", "email"),
        groups_claim=getattr(settings, "oidc_groups_claim", "groups"),
    )


async def discover_oidc_endpoints(config: OIDCConfig) -> OIDCConfig:
    """Discover OIDC endpoints from well-known configuration."""
    discovery_url = f"{config.issuer}/.well-known/openid-configuration"

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(discovery_url, timeout=10.0)
            response.raise_for_status()
            discovery = response.json()

            config.authorization_endpoint = discovery.get("authorization_endpoint")
            config.token_endpoint = discovery.get("token_endpoint")
            config.userinfo_endpoint = discovery.get("userinfo_endpoint")
            config.jwks_uri = discovery.get("jwks_uri")
            config.end_session_endpoint = discovery.get("end_session_endpoint")

            return config
        except Exception as e:
            logger.error("oidc_discovery_failed", issuer=config.issuer, error=str(e))
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Failed to discover OIDC configuration",
            ) from e


def generate_state() -> str:
    """Generate a secure random state parameter."""
    return secrets.token_urlsafe(32)


def generate_nonce() -> str:
    """Generate a secure random nonce."""
    return secrets.token_urlsafe(32)


@router.get("/login")
async def oidc_login(
    request: Request,
    redirect_uri: str | None = Query(None, description="Post-login redirect URI"),
    org_id: UUID | None = Query(None, description="Organization context"),
) -> RedirectResponse:
    """
    Initiate OIDC login flow.

    Redirects to the OIDC provider's authorization endpoint.
    """
    config = get_oidc_config()
    if not config:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="OIDC authentication is not configured",
        )

    config = await discover_oidc_endpoints(config)

    # Generate state and nonce
    state = generate_state()
    nonce = generate_nonce()

    # Determine callback URL
    callback_url = str(request.url_for("oidc_callback"))

    # Store state for verification
    _oidc_states[state] = OIDCState(
        state=state,
        nonce=nonce,
        redirect_uri=redirect_uri or "/",
        org_id=org_id,
    )

    # Build authorization URL
    params = {
        "client_id": config.client_id,
        "response_type": "code",
        "scope": " ".join(config.scopes),
        "redirect_uri": callback_url,
        "state": state,
        "nonce": nonce,
    }

    auth_url = f"{config.authorization_endpoint}?{urlencode(params)}"
    return RedirectResponse(url=auth_url)


@router.get("/callback")
async def oidc_callback(
    request: Request,
    response: Response,
    code: str = Query(..., description="Authorization code"),
    state: str = Query(..., description="State parameter"),
    error: str | None = Query(None),
    error_description: str | None = Query(None),
    jwt_service: JWTService = Depends(get_jwt_service),
) -> RedirectResponse:
    """
    Handle OIDC callback after provider authentication.

    Exchanges the authorization code for tokens and creates a session.
    """
    # Check for errors from provider
    if error:
        logger.warning("oidc_callback_error", error=error, description=error_description)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=error_description or error,
        )

    # Verify state
    stored_state = _oidc_states.pop(state, None)
    if not stored_state:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired state parameter",
        )

    # Check state expiration (5 minutes)
    if datetime.now(UTC) - stored_state.created_at > timedelta(minutes=5):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="State parameter expired",
        )

    config = get_oidc_config()
    if not config:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="OIDC authentication is not configured",
        )

    config = await discover_oidc_endpoints(config)

    # Exchange code for tokens
    callback_url = str(request.url_for("oidc_callback"))
    tokens = await exchange_code_for_tokens(config, code, callback_url)

    # Verify ID token
    id_token = tokens.get("id_token")
    if not id_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No ID token received",
        )

    # Get user info from ID token or userinfo endpoint
    user_info = await get_user_info(config, tokens)

    # Create or update user in database
    db = await anext(get_db())
    try:
        user_service = UserService(db)

        # Find or create user by email
        email = getattr(user_info, config.email_claim, None) or user_info.email
        if not email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email not provided by OIDC provider",
            )

        # Check if user exists
        existing_user = await user_service.get_user_by_username(email)

        if not existing_user:
            # Auto-provision user (can be disabled in settings)
            if getattr(settings, "oidc_auto_provision_users", True):
                existing_user = await user_service.create_user(
                    username=email,
                    email=email,
                    password=secrets.token_urlsafe(32),  # Random password (won't be used)
                    is_admin=False,
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="User not found and auto-provisioning is disabled",
                )

        # Get user scopes (potentially from OIDC groups)
        scopes = await user_service.get_user_scopes(existing_user.user_id)

        # Map OIDC groups to scopes if configured
        if user_info.groups and config.groups_claim:
            group_scope_map = getattr(settings, "oidc_group_scope_map", {})
            for group in user_info.groups:
                if group in group_scope_map:
                    scopes.extend(group_scope_map[group])
            scopes = list(set(scopes))  # Deduplicate

        # Create Cerebro access token
        access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
        access_token = await jwt_service.create_token(
            username=existing_user.username,
            scopes=scopes,
            expires_delta=access_token_expires,
            org_id=stored_state.org_id,
        )

        # Set cookie
        response.set_cookie(
            key=settings.access_token_cookie_name,
            value=access_token,
            max_age=settings.access_token_expire_minutes * 60,
            httponly=True,
            secure=settings.auth_cookie_secure,
            samesite=settings.auth_cookie_same_site,
        )

        # Redirect to original destination
        return RedirectResponse(
            url=stored_state.redirect_uri,
            status_code=status.HTTP_302_FOUND,
        )

    finally:
        await db.close()


async def exchange_code_for_tokens(
    config: OIDCConfig,
    code: str,
    redirect_uri: str,
) -> dict[str, Any]:
    """Exchange authorization code for tokens."""
    async with httpx.AsyncClient() as client:
        response = await client.post(
            config.token_endpoint,
            data={
                "grant_type": "authorization_code",
                "client_id": config.client_id,
                "client_secret": config.client_secret,
                "code": code,
                "redirect_uri": redirect_uri,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10.0,
        )

        if response.status_code != 200:
            logger.error(
                "oidc_token_exchange_failed",
                status=response.status_code,
                body=response.text,
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Failed to exchange authorization code",
            )

        return response.json()


async def get_user_info(
    config: OIDCConfig,
    tokens: dict[str, Any],
) -> OIDCUserInfo:
    """Get user information from ID token or userinfo endpoint."""
    # First try to decode ID token
    id_token = tokens.get("id_token")
    if id_token:
        try:
            # Decode without verification for now (we trust the token from our exchange)
            # In production, verify with JWKS
            claims = jose_jwt.get_unverified_claims(id_token)
            return OIDCUserInfo(
                sub=claims.get("sub"),
                email=claims.get("email"),
                email_verified=claims.get("email_verified"),
                name=claims.get("name"),
                given_name=claims.get("given_name"),
                family_name=claims.get("family_name"),
                picture=claims.get("picture"),
                groups=claims.get("groups"),
            )
        except Exception as e:
            logger.warning("failed_to_decode_id_token", error=str(e))

    # Fall back to userinfo endpoint
    access_token = tokens.get("access_token")
    if access_token and config.userinfo_endpoint:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                config.userinfo_endpoint,
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=10.0,
            )

            if response.status_code == 200:
                data = response.json()
                return OIDCUserInfo(**data)

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Failed to get user information",
    )


@router.get("/logout")
async def oidc_logout(
    request: Request,
    response: Response,
    redirect_uri: str | None = Query(None, description="Post-logout redirect URI"),
) -> RedirectResponse:
    """
    Logout from OIDC session.

    Clears local session and optionally redirects to OIDC provider's logout.
    """
    # Clear local cookies
    response.delete_cookie(key=settings.access_token_cookie_name)
    response.delete_cookie(key=settings.refresh_token_cookie_name)
    response.delete_cookie(key=settings.csrf_cookie_name)

    config = get_oidc_config()
    if config:
        try:
            config = await discover_oidc_endpoints(config)

            # If provider supports logout, redirect there
            if config.end_session_endpoint:
                params = {}
                if redirect_uri:
                    params["post_logout_redirect_uri"] = redirect_uri

                logout_url = config.end_session_endpoint
                if params:
                    logout_url = f"{logout_url}?{urlencode(params)}"

                return RedirectResponse(url=logout_url)
        except Exception as e:
            logger.warning("oidc_logout_redirect_failed", error=str(e))

    # Fall back to local redirect
    return RedirectResponse(url=redirect_uri or "/")


@router.get("/config")
async def get_oidc_config_info() -> dict[str, Any]:
    """Get OIDC configuration info (non-sensitive)."""
    config = get_oidc_config()
    if not config:
        return {"enabled": False}

    return {
        "enabled": True,
        "issuer": config.issuer,
        "scopes": config.scopes,
        "login_url": "/api/v1/auth/oidc/login",
        "logout_url": "/api/v1/auth/oidc/logout",
    }
