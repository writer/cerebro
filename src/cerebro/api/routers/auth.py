"""Authentication endpoints."""

from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, status, Form
from fastapi.security import HTTPBasicCredentials, HTTPBasic
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.core.config import settings
from cerebro.core.database import get_db
from cerebro.api.auth import (
    Token, User, verify_password, create_access_token, get_current_user
)

router = APIRouter()
security = HTTPBasic()


class LoginRequest(BaseModel):
    """Login request model."""
    username: str
    password: str


async def authenticate_user(username: str, password: str, db: AsyncSession) -> dict:
    """Authenticate user credentials."""
    from cerebro.core.user_service import UserService
    
    user_service = UserService(db)
    user = await user_service.authenticate_user(username, password)
    
    if not user:
        return None
    
    # Get user scopes
    scopes = await user_service.get_user_scopes(user.user_id)
    
    return {
        "username": user.username,
        "email": user.email,
        "is_admin": user.is_admin,
        "scopes": scopes
    }


@router.post("/token", response_model=Token)
async def login(login_data: LoginRequest, db: AsyncSession = Depends(get_db)):
    """Get access token via username/password."""
    user = await authenticate_user(login_data.username, login_data.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = create_access_token(
        data={"sub": user["username"], "scopes": user["scopes"]},
        expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/login", response_model=Token)
async def login_form(
    username: str = Form(...),
    password: str = Form(...),
    db: AsyncSession = Depends(get_db)
):
    """Get access token via form data (frontend compatibility)."""
    user = await authenticate_user(username, password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    refresh_token_expires = timedelta(days=settings.refresh_token_expire_days)
    
    access_token = create_access_token(
        data={"sub": user["username"], "scopes": user["scopes"]},
        expires_delta=access_token_expires
    )
    
    refresh_token = create_access_token(
        data={"sub": user["username"], "scopes": user["scopes"], "type": "refresh"},
        expires_delta=refresh_token_expires
    )
    
    return {
        "access_token": access_token, 
        "token_type": "bearer",
        "refresh_token": refresh_token
    }


@router.post("/token/basic", response_model=Token)
async def login_basic(
    credentials: HTTPBasicCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
):
    """Get access token via HTTP Basic auth."""
    user = await authenticate_user(credentials.username, credentials.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    
    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = create_access_token(
        data={"sub": user["username"], "scopes": user["scopes"]},
        expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    """Get current user information."""
    return current_user


@router.post("/refresh", response_model=Token)
async def refresh_token(
    refresh_token: str,
    db: AsyncSession = Depends(get_db)
):
    """Refresh access token using refresh token."""
    try:
        # Decode refresh token
        from cerebro.api.auth import verify_token
        from jose import jwt
        
        payload = jwt.decode(refresh_token, settings.secret_key, algorithms=[settings.algorithm])
        username: str = payload.get("sub")
        token_type: str = payload.get("type")
        
        if not username or token_type != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )
        
        # Get user and generate new tokens
        from cerebro.core.user_service import UserService
        user_service = UserService(db)
        user = await user_service.get_user_by_username(username)
        
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive"
            )
        
        scopes = await user_service.get_user_scopes(user.user_id)
        
        access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
        access_token = create_access_token(
            data={"sub": username, "scopes": scopes},
            expires_delta=access_token_expires
        )
        
        return {"access_token": access_token, "token_type": "bearer"}
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )


@router.get("/protected")
async def protected_endpoint(current_user: User = Depends(get_current_user)):
    """Example protected endpoint."""
    return {"message": f"Hello {current_user.username}!", "scopes": current_user.scopes}
