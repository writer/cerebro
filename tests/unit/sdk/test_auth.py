import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro_sdk.auth import AuthSession


@pytest.mark.asyncio
async def test_auth_session_login_success(test_db: AsyncSession, test_user):
    auth = AuthSession(test_db)

    tokens = await auth.login("testuser", "testpass123")

    assert tokens is not None
    payload = await auth.verify(tokens.access_token, expected_type="access")
    assert payload["sub"] == "testuser"


@pytest.mark.asyncio
async def test_auth_session_login_failure(test_db: AsyncSession):
    auth = AuthSession(test_db)
    tokens = await auth.login("missing", "nope")
    assert tokens is None
