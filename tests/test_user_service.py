"""Tests for the user management service."""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.core.user_service import UserService


class TestUserService:
    """End-to-end coverage for user creation and scope management."""

    @pytest.mark.asyncio
    async def test_create_user(self, test_db: AsyncSession) -> None:
        user_service = UserService(test_db)
        await user_service.create_default_scopes()

        user = await user_service.create_user(
            username="testuser",
            email="test@example.com",
            password="password123",
            scopes=["read:findings"],
        )

        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert not user.is_admin

        scopes = await user_service.get_user_scopes(user.user_id)
        assert "read:findings" in scopes

    @pytest.mark.asyncio
    async def test_authenticate_user(self, test_db: AsyncSession) -> None:
        user_service = UserService(test_db)
        await user_service.create_default_scopes()

        await user_service.create_user(
            username="authtest",
            email="auth@example.com",
            password="password123",
        )

        user = await user_service.authenticate_user("authtest", "password123")
        assert user is not None and user.username == "authtest"

        invalid = await user_service.authenticate_user("authtest", "wrongpassword")
        assert invalid is None

    @pytest.mark.asyncio
    async def test_user_scopes(self, test_db: AsyncSession) -> None:
        user_service = UserService(test_db)
        await user_service.create_default_scopes()

        user = await user_service.create_user(
            username="scopetest",
            email="scope@example.com",
            password="password123",
        )

        await user_service.add_user_scopes(
            user.user_id,
            ["read:findings", "write:rules"],
        )

        scopes = await user_service.get_user_scopes(user.user_id)
        assert "read:findings" in scopes
        assert "write:rules" in scopes

        await user_service.remove_user_scopes(user.user_id, ["write:rules"])
        scopes = await user_service.get_user_scopes(user.user_id)
        assert "read:findings" in scopes
        assert "write:rules" not in scopes

    @pytest.mark.asyncio
    async def test_admin_user_creation(self, test_db: AsyncSession) -> None:
        user_service = UserService(test_db)
        await user_service.create_default_scopes()

        result = await user_service.create_admin_user(
            username="testadmin",
            email="admin@example.com",
            password="admin123",
        )
        admin = result.user

        assert admin.is_admin is True
        scopes = await user_service.get_user_scopes(admin.user_id)
        assert {"admin", "read:findings", "write:rules"} <= set(scopes)

    @pytest.mark.asyncio
    async def test_duplicate_user_prevention(self, test_db: AsyncSession) -> None:
        user_service = UserService(test_db)
        await user_service.create_default_scopes()

        await user_service.create_user(
            username="duplicate",
            email="duplicate@example.com",
            password="password123",
        )

        with pytest.raises(ValueError, match="already exists"):
            await user_service.create_user(
                username="duplicate",
                email="different@example.com",
                password="password123",
            )

        with pytest.raises(ValueError, match="already exists"):
            await user_service.create_user(
                username="different",
                email="duplicate@example.com",
                password="password123",
            )
