"""Async tests for JWT key rotation."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.core.security.key_store import JWTKeyStore


@pytest.mark.asyncio
async def test_key_rotation_creates_initial_key(test_db: AsyncSession):
    store = JWTKeyStore(test_db)
    assert await store.rotate_keys_if_needed() is True
    key = await store.get_current_signing_key()
    assert key is not None


@pytest.mark.asyncio
async def test_cleanup_expired_keys_handles_empty_store(test_db: AsyncSession):
    store = JWTKeyStore(test_db)
    assert await store.cleanup_expired_keys() == 0
