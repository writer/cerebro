"""Authentication and authorization for Cerebro API."""

from __future__ import annotations

import secrets
from typing import Dict, List, Optional
from uuid import UUID

from fastapi import Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.api.dependencies import get_jwt_service
from cerebro.core.config import settings
from cerebro.core.database import get_db
from cerebro.core.models import Organization
from cerebro.core.security.jwt import JWTService
from cerebro.core.user_service import UserService


class Token(BaseModel):
    """JWT token response."""

    access_token: str
    token_type: str
    refresh_token: Optional[str] = None
    access_token_expires_in: Optional[int] = None
    refresh_token_expires_in: Optional[int] = None
    csrf_token: Optional[str] = None


class TokenData(BaseModel):
    """Token payload data extracted from a JWT."""

    username: Optional[str] = None
    scopes: List[str] = Field(default_factory=list)
    org_id: Optional[UUID] = None
    token_type: Optional[str] = None


class User(BaseModel):
    """Authenticated user context passed to API endpoints."""

    user_id: UUID
    username: str
    email: Optional[str] = None
    is_admin: bool = False
    scopes: List[str] = Field(default_factory=list)
    org_id: Optional[UUID] = None


async def _resolve_default_org_id(db: AsyncSession) -> Optional[UUID]:
    """Return a default organization identifier for the current tenant."""

    stmt = select(Organization.org_id).order_by(Organization.created_at.asc()).limit(1)
    return await db.scalar(stmt)


def _build_token_data(payload: Dict[str, object]) -> TokenData:
    username = payload.get("sub")
    scopes = payload.get("scopes", [])
    org_id_raw = payload.get("org_id")
    token_type = payload.get("token_type")

    parsed_org_id: Optional[UUID] = None
    if isinstance(org_id_raw, str):
        try:
            parsed_org_id = UUID(org_id_raw)
        except ValueError:
            parsed_org_id = None

    return TokenData(
        username=str(username) if username is not None else None,
        scopes=list(scopes) if isinstance(scopes, list) else [],
        org_id=parsed_org_id,
        token_type=str(token_type) if token_type is not None else None,
    )


def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def validate_csrf(request: Request) -> None:
    cookie_token = request.cookies.get(settings.csrf_cookie_name)
    header_token = request.headers.get(settings.csrf_header_name)

    if not cookie_token or not header_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token missing",
        )

    if not secrets.compare_digest(cookie_token, header_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token mismatch",
        )


def _extract_token_from_request(request: Request) -> str:
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.lower().startswith("bearer "):
        return auth_header.split(" ", 1)[1].strip()

    cookie_token = request.cookies.get(settings.access_token_cookie_name)
    if cookie_token:
        validate_csrf(request)
        return cookie_token

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
    jwt_service: JWTService = Depends(get_jwt_service),
) -> User:
    """Return the authenticated user context for the current request."""

    credentials_token = _extract_token_from_request(request)

    try:
        payload = await jwt_service.verify_token(
            credentials_token, expected_type="access"
        )
    except Exception as exc:  # JWTService raises JWTError internally
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    token_data = _build_token_data(payload)
    if token_data.username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing subject",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_service = UserService(db)
    db_user = await user_service.get_user_by_username(token_data.username)

    if not db_user or not db_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
            headers={"WWW-Authenticate": "Bearer"},
        )

    scopes = await user_service.get_user_scopes(db_user.user_id)
    org_id = token_data.org_id
    if org_id is None:
        org_id = await _resolve_default_org_id(db)

    return User(
        user_id=db_user.user_id,
        username=db_user.username,
        email=db_user.email,
        is_admin=db_user.is_admin,
        scopes=scopes,
        org_id=org_id,
    )


async def get_current_admin_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """Ensure the caller has administrative privileges."""

    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions",
        )
    return current_user


def require_scopes(*required_scopes: str):
    """Declare that an endpoint requires the given scopes."""

    def scope_checker(current_user: User = Depends(get_current_user)) -> User:
        missing = [
            scope for scope in required_scopes if scope not in current_user.scopes
        ]
        if missing:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required scope: {missing[0]}",
            )
        return current_user

    return scope_checker


# Common scope requirements
require_read_findings = require_scopes("read:findings")
require_write_findings = require_scopes("write:findings")
require_read_rules = require_scopes("read:rules")
require_write_rules = require_scopes("write:rules")
require_collect = require_scopes("collect:data")
require_admin = get_current_admin_user


def verify_webhook_signature(
    secret: str, payload: bytes, signature: str, prefix: str = "sha256="
) -> bool:
    """Validate webhook signatures using HMAC-SHA256."""

    import hashlib
    import hmac

    if not secret or not signature or not payload:
        return False

    if not signature.startswith(prefix):
        return False

    provided = signature[len(prefix) :]
    digest = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(digest, provided)
