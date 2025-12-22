"""Authentication endpoints."""

from datetime import timedelta
from typing import Dict, Literal, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials, OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.api.auth import (
    Token,
    User,
    generate_csrf_token,
    get_current_user,
    validate_csrf,
)
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

    refresh_token: Optional[str] = None


class TokenResponse(BaseModel):
    """Enhanced token response including refresh token."""

    access_token: str
    refresh_token: str
    token_type: str
    access_token_expires_in: int
    refresh_token_expires_in: int
    csrf_token: str


async def _resolve_org_id(db: AsyncSession) -> Optional[UUID]:
    stmt = select(Organization.org_id).order_by(Organization.created_at.asc()).limit(1)
    return await db.scalar(stmt)


def _cookie_kwargs() -> dict:
    params = {
        "path": settings.auth_cookie_path,
        "secure": settings.auth_cookie_secure,
        "httponly": True,
        "samesite": settings.auth_cookie_same_site,
    }
    if settings.auth_cookie_domain:
        params["domain"] = settings.auth_cookie_domain
    return params


def _csrf_cookie_kwargs() -> dict:
    params = {
        "path": settings.auth_cookie_path,
        "secure": settings.csrf_cookie_secure,
        "httponly": False,
        "samesite": settings.csrf_cookie_same_site,
    }
    if settings.auth_cookie_domain:
        params["domain"] = settings.auth_cookie_domain
    return params


def _set_auth_cookies(
    response: Response,
    *,
    access_token: str,
    access_ttl_seconds: int,
    refresh_token: Optional[str] = None,
    refresh_ttl_seconds: Optional[int] = None,
) -> None:
    cookie_kwargs = _cookie_kwargs()
    response.set_cookie(
        key=settings.access_token_cookie_name,
        value=access_token,
        max_age=access_ttl_seconds,
        expires=access_ttl_seconds,
        **cookie_kwargs,
    )

    if refresh_token and refresh_ttl_seconds:
        response.set_cookie(
            key=settings.refresh_token_cookie_name,
            value=refresh_token,
            max_age=refresh_ttl_seconds,
            expires=refresh_ttl_seconds,
            **cookie_kwargs,
        )


def _clear_auth_cookies(response: Response) -> None:
    cookie_kwargs = _cookie_kwargs()
    response.delete_cookie(key=settings.access_token_cookie_name, **cookie_kwargs)
    response.delete_cookie(key=settings.refresh_token_cookie_name, **cookie_kwargs)
    response.delete_cookie(key=settings.csrf_cookie_name, **_csrf_cookie_kwargs())


def _set_csrf_cookie(response: Response, csrf_token: str) -> None:
    response.set_cookie(
        key=settings.csrf_cookie_name,
        value=csrf_token,
        **_csrf_cookie_kwargs(),
    )


RefreshMode = Literal["none", "opaque", "jwt"]


async def _issue_tokens(
    response: Response,
    *,
    user: dict,
    jwt_service: JWTService,
    db: AsyncSession,
    refresh_mode: RefreshMode,
    include_refresh_token_in_body: bool,
    include_refresh_metadata: bool,
) -> Dict[str, object]:
    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = await jwt_service.create_token(
        username=user["username"],
        scopes=user["scopes"],
        expires_delta=access_token_expires,
        org_id=user["org_id"],
    )

    refresh_token: Optional[str] = None
    refresh_ttl_seconds: Optional[int] = None

    if refresh_mode == "opaque":
        refresh_service = RefreshTokenService(db)
        refresh_token = refresh_service.generate_refresh_token()
        await refresh_service.store_refresh_token(
            user_id=user["user_id"],
            token=refresh_token,
            expires_in_days=settings.refresh_token_expire_days,
        )
        refresh_ttl_seconds = settings.refresh_token_expire_days * 24 * 60 * 60
    elif refresh_mode == "jwt":
        refresh_delta = timedelta(days=settings.refresh_token_expire_days)
        refresh_token = await jwt_service.create_token(
            username=user["username"],
            scopes=user["scopes"],
            expires_delta=refresh_delta,
            token_type="refresh",
            org_id=user["org_id"],
        )
        refresh_ttl_seconds = settings.refresh_token_expire_days * 24 * 60 * 60

    _set_auth_cookies(
        response,
        access_token=access_token,
        access_ttl_seconds=settings.access_token_expire_minutes * 60,
        refresh_token=refresh_token,
        refresh_ttl_seconds=refresh_ttl_seconds,
    )

    csrf_token = generate_csrf_token()
    _set_csrf_cookie(response, csrf_token)

    payload: Dict[str, object] = {
        "access_token": access_token,
        "token_type": "bearer",
        "access_token_expires_in": settings.access_token_expire_minutes * 60,
        "csrf_token": csrf_token,
    }

    if include_refresh_metadata and settings.refresh_token_expire_days:
        payload["refresh_token_expires_in"] = (
            settings.refresh_token_expire_days * 24 * 60 * 60
        )

    if include_refresh_token_in_body and refresh_token is not None:
        payload["refresh_token"] = refresh_token

    return payload


async def authenticate_user(
    username: str, password: str, db: AsyncSession
) -> Optional[dict]:
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
    response: Response,
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

    return await _issue_tokens(
        response,
        user=user,
        jwt_service=jwt_service,
        db=db,
        refresh_mode="opaque",
        include_refresh_token_in_body=True,
        include_refresh_metadata=True,
    )


@router.post("/token", response_model=Token)
async def login_json(
    response: Response,
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

    return await _issue_tokens(
        response,
        user=user,
        jwt_service=jwt_service,
        db=db,
        refresh_mode="none",
        include_refresh_token_in_body=False,
        include_refresh_metadata=True,
    )


@router.post("/login", response_model=Token)
async def login_form(
    response: Response,
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

    return await _issue_tokens(
        response,
        user=user,
        jwt_service=jwt_service,
        db=db,
        refresh_mode="jwt",
        include_refresh_token_in_body=True,
        include_refresh_metadata=True,
    )


@router.post("/token/basic", response_model=Token)
async def login_basic(
    response: Response,
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

    return await _issue_tokens(
        response,
        user=user,
        jwt_service=jwt_service,
        db=db,
        refresh_mode="none",
        include_refresh_token_in_body=False,
        include_refresh_metadata=False,
    )


@router.get("/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)) -> User:
    """Return the authenticated user's profile."""

    return current_user


@router.post("/refresh", response_model=Token)
async def refresh_token(
    response: Response,
    request: Request,
    refresh_payload: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db),
    jwt_service: JWTService = Depends(get_jwt_service),
):
    """Refresh an access token using either JWT or opaque refresh tokens."""

    provided_refresh = refresh_payload.refresh_token
    refresh_token_value = provided_refresh or request.cookies.get(
        settings.refresh_token_cookie_name
    )

    if not refresh_token_value:
        _clear_auth_cookies(response)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token missing",
        )

    if provided_refresh is None:
        validate_csrf(request)

    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)

    csrf_token = generate_csrf_token()

    try:
        payload = await jwt_service.verify_token(
            refresh_token_value, expected_type="refresh"
        )
    except Exception:
        refresh_token_service = RefreshTokenService(db)
        user_id = await refresh_token_service.verify_refresh_token(refresh_token_value)
        if not user_id:
            _clear_auth_cookies(response)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired refresh token",
            )

        user_service = UserService(db)
        user = await user_service.get_user_by_id(user_id)
        if not user or not user.is_active:
            _clear_auth_cookies(response)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive",
            )

        scopes = await user_service.get_user_scopes(user_id)
        org_id = await _resolve_org_id(db)

        access_token = await jwt_service.create_token(
            username=user.username,
            scopes=scopes,
            expires_delta=access_token_expires,
            org_id=org_id,
        )

        _set_auth_cookies(
            response,
            access_token=access_token,
            access_ttl_seconds=settings.access_token_expire_minutes * 60,
            refresh_token=refresh_token_value,
            refresh_ttl_seconds=settings.refresh_token_expire_days * 24 * 60 * 60,
        )

        _set_csrf_cookie(response, csrf_token)

        return {
            "access_token": access_token,
            "token_type": "bearer",
            "access_token_expires_in": settings.access_token_expire_minutes * 60,
            "refresh_token_expires_in": settings.refresh_token_expire_days
            * 24
            * 60
            * 60,
            "csrf_token": csrf_token,
        }

    username = payload.get("sub")
    if not isinstance(username, str):
        _clear_auth_cookies(response)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    user_service = UserService(db)
    user = await user_service.get_user_by_username(username)
    if not user or not user.is_active:
        _clear_auth_cookies(response)
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

    access_token = await jwt_service.create_token(
        username=username,
        scopes=scopes,
        expires_delta=access_token_expires,
        org_id=org_id,
    )

    _set_auth_cookies(
        response,
        access_token=access_token,
        access_ttl_seconds=settings.access_token_expire_minutes * 60,
    )

    _set_csrf_cookie(response, csrf_token)

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "access_token_expires_in": settings.access_token_expire_minutes * 60,
        "csrf_token": csrf_token,
    }


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    refresh_request: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db),
):
    """Logout and revoke an opaque refresh token."""

    token_value = refresh_request.refresh_token or request.cookies.get(
        settings.refresh_token_cookie_name
    )

    if refresh_request.refresh_token is None:
        validate_csrf(request)

    refresh_token_service = RefreshTokenService(db)
    revoked = False
    if token_value:
        revoked = await refresh_token_service.revoke_refresh_token(token_value)

    _clear_auth_cookies(response)

    if revoked:
        return {"message": "Successfully logged out"}
    return {"message": "Token already invalid"}


@router.get("/protected")
async def protected_endpoint(current_user: User = Depends(get_current_user)):
    """Example protected endpoint."""

    return {"message": f"Hello {current_user.username}!", "scopes": current_user.scopes}
