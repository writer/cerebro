"""Authentication endpoints."""

from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBasicCredentials, HTTPBasic
from pydantic import BaseModel

from cerebro.core.config import settings
from cerebro.api.auth import (
    Token, User, verify_password, create_access_token, get_current_user
)

router = APIRouter()
security = HTTPBasic()


class LoginRequest(BaseModel):
    """Login request model."""
    username: str
    password: str


# Mock user database - replace with real user management
USERS_DB = {
    "admin": {
        "username": "admin",
        "email": "admin@cerebro.local",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",  # secret
        "is_admin": True,
        "scopes": ["admin", "read:findings", "write:findings", "read:rules", "write:rules", "collect:data"]
    },
    "analyst": {
        "username": "analyst", 
        "email": "analyst@cerebro.local",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",  # secret
        "is_admin": False,
        "scopes": ["read:findings", "read:rules"]
    }
}


def authenticate_user(username: str, password: str) -> dict:
    """Authenticate user credentials."""
    user = USERS_DB.get(username)
    if not user:
        return None
    if not verify_password(password, user["hashed_password"]):
        return None
    return user


@router.post("/token", response_model=Token)
async def login(login_data: LoginRequest):
    """Get access token via username/password."""
    user = authenticate_user(login_data.username, login_data.password)
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


@router.post("/token/basic", response_model=Token)
async def login_basic(credentials: HTTPBasicCredentials = Depends(security)):
    """Get access token via HTTP Basic auth."""
    user = authenticate_user(credentials.username, credentials.password)
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


@router.get("/protected")
async def protected_endpoint(current_user: User = Depends(get_current_user)):
    """Example protected endpoint."""
    return {"message": f"Hello {current_user.username}!", "scopes": current_user.scopes}
