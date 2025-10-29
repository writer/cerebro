import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro_sdk.users import UserManager


@pytest.mark.asyncio
async def test_user_manager_create_and_get(test_db: AsyncSession):
    manager = UserManager(test_db)

    record = await manager.create_user(
        username="sdk-user",
        email="sdk@example.com",
        password="secret123",
        scopes=["read:findings"],
    )

    assert record.username == "sdk-user"
    assert "read:findings" in record.scopes

    fetched = await manager.get_user("sdk-user")
    assert fetched is not None
    assert fetched.user_id == record.user_id


@pytest.mark.asyncio
async def test_user_manager_authenticate(test_db: AsyncSession, test_user):
    manager = UserManager(test_db)
    record = await manager.authenticate("testuser", "testpass123")
    assert record is not None
    assert record.username == "testuser"


@pytest.mark.asyncio
async def test_user_manager_scope_updates(test_db: AsyncSession, test_user):
    manager = UserManager(test_db)
    user = await manager.get_user("testuser")
    assert user is not None

    await manager.add_scopes(user.user_id, ["query:execute"])
    updated = await manager.get_user("testuser")
    assert updated is not None and "query:execute" in updated.scopes

    await manager.remove_scopes(user.user_id, ["query:execute"])
    refreshed = await manager.get_user("testuser")
    assert refreshed is not None and "query:execute" not in refreshed.scopes
