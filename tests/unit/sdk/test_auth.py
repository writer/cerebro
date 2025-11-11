from datetime import UTC, datetime

import pytest
from jose import jwt
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.core.config import settings
from cerebro_sdk.auth import AuthSession


@pytest.mark.asyncio
async def test_auth_session_login_success(test_db: AsyncSession, test_user):
    auth = AuthSession(test_db)

    tokens = await auth.login("testuser", "testpass123")

    assert tokens is not None
    payload = await auth.verify(tokens.access_token, expected_type="access")
    assert payload["sub"] == "testuser"

    assert tokens.refresh_token is not None
    refresh_payload = jwt.get_unverified_claims(tokens.refresh_token)
    exp = refresh_payload["exp"]
    now_ts = datetime.now(UTC).timestamp()
    min_ttl = settings.refresh_token_expire_days * 24 * 60 * 60 - 300
    assert exp - now_ts >= min_ttl


@pytest.mark.asyncio
async def test_auth_session_login_failure(test_db: AsyncSession):
    auth = AuthSession(test_db)
    tokens = await auth.login("missing", "nope")
    assert tokens is None
