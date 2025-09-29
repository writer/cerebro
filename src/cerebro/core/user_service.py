"""User management service for authentication and authorization."""

from typing import List, Optional, Dict, Any
from uuid import UUID
from datetime import datetime
import logging

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_
from passlib.context import CryptContext

from .user_models import User, Scope, UserScope, UserAuditLog

logger = logging.getLogger(__name__)

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class UserService:
    """Service for user management operations."""
    
    def __init__(self, db_session: AsyncSession):
        """Initialize user service."""
        self.db = db_session
    
    async def create_user(
        self,
        username: str,
        email: str,
        password: str,
        is_admin: bool = False,
        scopes: Optional[List[str]] = None
    ) -> User:
        """Create a new user."""
        # Check if user already exists
        stmt = select(User).where(
            or_(User.username == username, User.email == email)
        )
        existing_user = await self.db.scalar(stmt)
        
        if existing_user:
            raise ValueError("User with this username or email already exists")
        
        # Hash password
        hashed_password = pwd_context.hash(password)
        
        # Create user
        user = User(
            username=username,
            email=email,
            hashed_password=hashed_password,
            is_admin=is_admin
        )
        
        self.db.add(user)
        await self.db.flush()  # Flush to get user ID
        
        # Add scopes if provided
        if scopes:
            await self.add_user_scopes(user.user_id, scopes)
        
        await self.db.commit()
        await self.db.refresh(user)
        
        logger.info(f"Created user: {username}")
        return user
    
    async def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """Authenticate user with username/password."""
        # Get user
        stmt = select(User).where(
            and_(
                User.username == username,
                User.is_active == True
            )
        )
        user = await self.db.scalar(stmt)
        
        if not user:
            return None
        
        # Verify password
        if not pwd_context.verify(password, user.hashed_password):
            # Log failed login attempt
            await self.log_user_action(
                user.user_id,
                "login_failed",
                success=False,
                error_message="Invalid password"
            )
            return None
        
        # Update last login
        user.last_login = datetime.utcnow()
        await self.db.commit()
        
        # Log successful login
        await self.log_user_action(user.user_id, "login", success=True)
        
        return user
    
    async def get_user_scopes(self, user_id: UUID) -> List[str]:
        """Get all scopes for a user."""
        stmt = select(Scope.name).join(UserScope).where(
            UserScope.user_id == user_id
        )
        scopes = await self.db.scalars(stmt)
        return list(scopes)
    
    async def add_user_scopes(
        self,
        user_id: UUID,
        scope_names: List[str],
        granted_by: Optional[UUID] = None
    ) -> None:
        """Add scopes to a user."""
        # Get scope IDs
        stmt = select(Scope).where(Scope.name.in_(scope_names))
        scopes = await self.db.scalars(stmt)
        scope_dict = {scope.name: scope.scope_id for scope in scopes}
        
        # Create missing scopes
        missing_scopes = set(scope_names) - set(scope_dict.keys())
        for scope_name in missing_scopes:
            scope = Scope(
                name=scope_name,
                description=f"Auto-created scope: {scope_name}"
            )
            self.db.add(scope)
            await self.db.flush()
            scope_dict[scope_name] = scope.scope_id
        
        # Add user scopes
        for scope_name in scope_names:
            # Check if user already has this scope
            stmt = select(UserScope).where(
                and_(
                    UserScope.user_id == user_id,
                    UserScope.scope_id == scope_dict[scope_name]
                )
            )
            existing = await self.db.scalar(stmt)
            
            if not existing:
                user_scope = UserScope(
                    user_id=user_id,
                    scope_id=scope_dict[scope_name],
                    granted_by=granted_by
                )
                self.db.add(user_scope)
        
        await self.db.commit()
        logger.info(f"Added scopes {scope_names} to user {user_id}")
    
    async def remove_user_scopes(
        self,
        user_id: UUID,
        scope_names: List[str]
    ) -> None:
        """Remove scopes from a user."""
        # Get scope IDs
        stmt = select(Scope.scope_id).where(Scope.name.in_(scope_names))
        scope_ids = await self.db.scalars(stmt)
        scope_id_list = list(scope_ids)
        
        # Delete user scopes
        stmt = select(UserScope).where(
            and_(
                UserScope.user_id == user_id,
                UserScope.scope_id.in_(scope_id_list)
            )
        )
        user_scopes = await self.db.scalars(stmt)
        
        for user_scope in user_scopes:
            await self.db.delete(user_scope)
        
        await self.db.commit()
        logger.info(f"Removed scopes {scope_names} from user {user_id}")
    
    async def log_user_action(
        self,
        user_id: UUID,
        action: str,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        success: bool = True,
        error_message: Optional[str] = None
    ) -> None:
        """Log user action for audit trail."""
        audit_log = UserAuditLog(
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            ip_address=ip_address,
            user_agent=user_agent,
            success=success,
            error_message=error_message
        )
        
        self.db.add(audit_log)
        await self.db.commit()
    
    async def get_user_by_id(self, user_id: UUID) -> Optional[User]:
        """Get user by ID."""
        return await self.db.get(User, user_id)
    
    async def get_user_by_username(self, username: str) -> Optional[User]:
        """Get user by username."""
        stmt = select(User).where(User.username == username)
        return await self.db.scalar(stmt)
    
    async def update_user_password(
        self,
        user_id: UUID,
        new_password: str
    ) -> bool:
        """Update user password."""
        user = await self.db.get(User, user_id)
        if not user:
            return False
        
        user.hashed_password = pwd_context.hash(new_password)
        await self.db.commit()
        
        await self.log_user_action(user_id, "password_changed")
        logger.info(f"Updated password for user {user.username}")
        return True
    
    async def deactivate_user(self, user_id: UUID) -> bool:
        """Deactivate a user."""
        user = await self.db.get(User, user_id)
        if not user:
            return False
        
        user.is_active = False
        await self.db.commit()
        
        await self.log_user_action(user_id, "user_deactivated")
        logger.info(f"Deactivated user {user.username}")
        return True
    
    async def list_users(
        self,
        limit: int = 100,
        offset: int = 0,
        active_only: bool = True
    ) -> List[User]:
        """List users."""
        stmt = select(User)
        
        if active_only:
            stmt = stmt.where(User.is_active == True)
        
        stmt = stmt.offset(offset).limit(limit)
        users = await self.db.scalars(stmt)
        return list(users)
    
    async def create_default_scopes(self) -> None:
        """Create default system scopes."""
        default_scopes = [
            ("admin", "Full administrative access"),
            ("read:organizations", "Read organization data"),
            ("write:organizations", "Manage organizations"),
            ("read:accounts", "Read account data"),
            ("write:accounts", "Manage accounts"),
            ("read:resources", "Read resource data"),
            ("read:principals", "Read principal data"),
            ("read:rules", "Read security rules"),
            ("write:rules", "Manage security rules"),
            ("read:findings", "Read security findings"),
            ("write:findings", "Manage security findings"),
            ("collect:data", "Run data collection"),
            ("read:audit", "Read audit logs"),
            ("query:execute", "Execute SQL queries"),
        ]
        
        for scope_name, description in default_scopes:
            # Check if scope exists
            stmt = select(Scope).where(Scope.name == scope_name)
            existing = await self.db.scalar(stmt)
            
            if not existing:
                scope = Scope(name=scope_name, description=description)
                self.db.add(scope)
        
        await self.db.commit()
        logger.info(f"Created {len(default_scopes)} default scopes")
    
    async def create_admin_user(
        self,
        username: str,
        email: str,
        password: str,
    ) -> User:
        """Create admin user with provided credentials.
        
        This method requires explicit username, email, and password.
        No defaults are provided for security.
        """
        import secrets
        import os
        
        # Validate password strength in production
        environment = os.getenv('ENVIRONMENT', 'production').lower()
        if environment not in ['dev', 'development', 'test', 'testing']:
            if len(password) < 12:
                raise ValueError(
                    "Admin password must be at least 12 characters in production. "
                    f"Generate a secure password with: python -c 'import secrets; print(secrets.token_urlsafe(16))'"
                )
        
        # Create admin user
        admin_user = await self.create_user(
            username=username,
            email=email,
            password=password,
            is_admin=True,
            scopes=[
                "admin",
                "read:organizations", "write:organizations",
                "read:accounts", "write:accounts", 
                "read:resources", "read:principals",
                "read:rules", "write:rules",
                "read:findings", "write:findings",
                "collect:data", "read:audit", "query:execute"
            ]
        )
        
        logger.info(f"Created admin user: {username}")
        return admin_user
