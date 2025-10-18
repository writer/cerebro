"""Authentication endpoints."""

from datetime import timedelta
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Form, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials, OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.api.auth import Token, User, get_current_user
from cerebro.api.dependencies import get_jwt_service
from cerebro.core.config import settings
from cerebro.core.database import get_db
from cerebro.core.models import Organization
from cerebro.core.refresh_token_service import RefreshTokenService
from cerebro.core.security.jwt import JWTService
from cerebro.core.user_service import UserService

router = APIRouter()
security = HTTPBasic()


class LoginRequest(BaseModel):
    """Login request model."""

    username: str
    password: str


class RefreshTokenRequest(BaseModel):
    """Refresh token request payload."""

    refresh_token: str


class TokenResponse(BaseModel):
    """Enhanced token response including refresh token."""

    access_token: str
    refresh_token: str
    token_type: str


async def _resolve_org_id(db: AsyncSession) -> Optional[UUID]:
    stmt = select(Organization.org_id).order_by(Organization.created_at.asc()).limit(1)
    return await db.scalar(stmt)


async def authenticate_user(username: str, password: str, db: AsyncSession) -> Optional[dict]:
    """Authenticate credentials and return user context."""

    user_service = UserService(db)
    user = await user_service.authenticate_user(username, password)
    if not user:
        return None

    scopes = await user_service.get_user_scopes(user.user_id)
    org_id = await _resolve_org_id(db)

    return {
        "user_id": user.user_id,
        "username": user.username,
        "email": user.email,
        "is_admin": user.is_admin,
        "scopes": scopes,
        "org_id": org_id,
    }


@router.post("/login", response_model=TokenResponse)
async def login_oauth2(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
    jwt_service: JWTService = Depends(get_jwt_service),
):
    """OAuth2 login endpoint for frontend clients."""

    user = await authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = await jwt_service.create_token(
        username=user["username"],
        scopes=user["scopes"],
        expires_delta=access_token_expires,
        org_id=user["org_id"],
    )

    refresh_token_service = RefreshTokenService(db)
    refresh_token = refresh_token_service.generate_refresh_token()
    await refresh_token_service.store_refresh_token(
        user_id=user["user_id"],
        token=refresh_token,
        expires_in_days=30,
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.post("/token", response_model=Token)
async def login_json(
    login_data: LoginRequest,
    db: AsyncSession = Depends(get_db),
    jwt_service: JWTService = Depends(get_jwt_service),
):
    """Issue an access token using JSON credentials."""

    user = await authenticate_user(login_data.username, login_data.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = await jwt_service.create_token(
        username=user["username"],
        scopes=user["scopes"],
        expires_delta=access_token_expires,
        org_id=user["org_id"],
    )

    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/login", response_model=Token)
async def login_form(
    username: str = Form(...),
    password: str = Form(...),
    db: AsyncSession = Depends(get_db),
    jwt_service: JWTService = Depends(get_jwt_service),
):
    """Issue access and refresh tokens via form-encoded login."""

    user = await authenticate_user(username, password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    refresh_token_expires = timedelta(days=settings.refresh_token_expire_days)

    access_token = await jwt_service.create_token(
        username=user["username"],
        scopes=user["scopes"],
        expires_delta=access_token_expires,
        org_id=user["org_id"],
    )

    refresh_token = await jwt_service.create_token(
        username=user["username"],
        scopes=user["scopes"],
        expires_delta=refresh_token_expires,
        token_type="refresh",
        org_id=user["org_id"],
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "refresh_token": refresh_token,
    }


@router.post("/token/basic", response_model=Token)
async def login_basic(
    credentials: HTTPBasicCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
    jwt_service: JWTService = Depends(get_jwt_service),
):
    """Issue an access token using HTTP Basic authentication."""

    user = await authenticate_user(credentials.username, credentials.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )

    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = await jwt_service.create_token(
        username=user["username"],
        scopes=user["scopes"],
        expires_delta=access_token_expires,
        org_id=user["org_id"],
    )

    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)) -> User:
    """Return the authenticated user's profile."""

    return current_user


@router.post("/refresh", response_model=Token)
async def refresh_token(
    refresh_token_value: str,
    db: AsyncSession = Depends(get_db),
    jwt_service: JWTService = Depends(get_jwt_service),
):
    """Refresh an access token using a JWT refresh token."""

    try:
        payload = await jwt_service.verify_token(refresh_token_value, expected_type="refresh")
    except Exception as exc:  # pragma: no cover - bubbled as HTTP error
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        ) from exc

    username = payload.get("sub")
    if not isinstance(username, str):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    user_service = UserService(db)
    user = await user_service.get_user_by_username(username)
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    scopes = await user_service.get_user_scopes(user.user_id)

    org_id = None
    raw_org = payload.get("org_id")
    if isinstance(raw_org, str):
        try:
            org_id = UUID(raw_org)
        except ValueError:
            org_id = None
    if org_id is None:
        org_id = await _resolve_org_id(db)

    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = await jwt_service.create_token(
        username=username,
        scopes=scopes,
        expires_delta=access_token_expires,
        org_id=org_id,
    )

    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/refresh")
async def refresh_access_token(
    refresh_request: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db),
    jwt_service: JWTService = Depends(get_jwt_service),
):
    """Refresh an access token using a stored opaque refresh token."""

    refresh_token_service = RefreshTokenService(db)
    user_id = await refresh_token_service.verify_refresh_token(refresh_request.refresh_token)
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    user_service = UserService(db)
    user = await user_service.get_user_by_id(user_id)
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    scopes = await user_service.get_user_scopes(user_id)
    org_id = await _resolve_org_id(db)

    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = await jwt_service.create_token(
        username=user.username,
        scopes=scopes,
        expires_delta=access_token_expires,
        org_id=org_id,
    )

    return {"access_token": access_token}


@router.post("/logout")
async def logout(
    refresh_request: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db),
):
    """Logout and revoke an opaque refresh token."""

    refresh_token_service = RefreshTokenService(db)
    revoked = await refresh_token_service.revoke_refresh_token(refresh_request.refresh_token)

    if revoked:
        return {"message": "Successfully logged out"}
    return {"message": "Token already invalid"}


@router.get("/protected")
async def protected_endpoint(current_user: User = Depends(get_current_user)):
    """Example protected endpoint."""

    return {"message": f"Hello {current_user.username}!", "scopes": current_user.scopes}
