"""Test user management service."""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.core.user_service import UserService
from cerebro.core.user_models import User


class TestUserService:
    """Test user service functionality."""
    
    @pytest.mark.asyncio
    async def test_create_user(self, test_db: AsyncSession):
        """Test user creation."""
        user_service = UserService(test_db)
        await user_service.create_default_scopes()
        
        user = await user_service.create_user(
            username="testuser",
            email="test@example.com",
            password="password123",
            scopes=["read:findings"]
        )
        
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert not user.is_admin
        
        # Test scopes were assigned
        scopes = await user_service.get_user_scopes(user.user_id)
        assert "read:findings" in scopes
    
    @pytest.mark.asyncio
    async def test_authenticate_user(self, test_db: AsyncSession):
        """Test user authentication."""
        user_service = UserService(test_db)
        await user_service.create_default_scopes()
        
        # Create user
        await user_service.create_user(
            username="authtest",
            email="auth@example.com",
            password="password123"
        )
        
        # Test successful authentication
        user = await user_service.authenticate_user("authtest", "password123")
        assert user is not None
        assert user.username == "authtest"
        
        # Test failed authentication
        user = await user_service.authenticate_user("authtest", "wrongpassword")
        assert user is None
    
    @pytest.mark.asyncio
    async def test_user_scopes(self, test_db: AsyncSession):
        """Test user scope management."""
        user_service = UserService(test_db)
        await user_service.create_default_scopes()
        
        user = await user_service.create_user(
            username="scopetest",
            email="scope@example.com",
            password="password123"
        )
        
        # Add scopes
        await user_service.add_user_scopes(
            user.user_id,
            ["read:findings", "write:rules"]
        )
        
        scopes = await user_service.get_user_scopes(user.user_id)
        assert "read:findings" in scopes
        assert "write:rules" in scopes
        
        # Remove scope
        await user_service.remove_user_scopes(
            user.user_id,
            ["write:rules"]
        )
        
        scopes = await user_service.get_user_scopes(user.user_id)
        assert "read:findings" in scopes
        assert "write:rules" not in scopes
    
    @pytest.mark.asyncio
    async def test_admin_user_creation(self, test_db: AsyncSession):
        """Test admin user creation."""
        user_service = UserService(test_db)
        await user_service.create_default_scopes()
        
        admin = await user_service.create_admin_user(
            username="testadmin",
            email="admin@example.com",
            password="admin123"
        )
        
        assert admin.is_admin
        
        scopes = await user_service.get_user_scopes(admin.user_id)
        assert "admin" in scopes
        assert "read:findings" in scopes
        assert "write:rules" in scopes
    
    @pytest.mark.asyncio  
    async def test_duplicate_user_prevention(self, test_db: AsyncSession):
        """Test that duplicate users cannot be created."""
        user_service = UserService(test_db)
        await user_service.create_default_scopes()
        
        # Create first user
        await user_service.create_user(
            username="duplicate",
            email="duplicate@example.com",
            password="password123"
        )
        
        # Try to create duplicate username
        with pytest.raises(ValueError, match="already exists"):
            await user_service.create_user(
                username="duplicate",
                email="different@example.com", 
                password="password123"
            )
        
        # Try to create duplicate email
        with pytest.raises(ValueError, match="already exists"):
            await user_service.create_user(
                username="different",
                email="duplicate@example.com",
                password="password123"
            )
