"""Organization-level authorization helpers.

Many API routes are scoped under /organizations/{org_id}/... .
These helpers ensure the authenticated user is allowed to access the requested org.
"""

from __future__ import annotations

from typing import Callable, TypeVar
from uuid import UUID

from fastapi import Depends, HTTPException, status

from cerebro.api.auth import User, get_current_user


UserDep = TypeVar("UserDep", bound=Callable[..., User])


def enforce_org_access(org_id: UUID, current_user: User) -> None:
    """Raise 403 if the user is not allowed to access the given organization."""

    # Admin users may access any org (useful for internal operations).
    if current_user.is_admin:
        return

    # Non-admin users must be scoped to a single org.
    if current_user.org_id is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Organization context required",
        )

    if current_user.org_id != org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Organization access denied",
        )


def require_org_access(user_dependency=get_current_user):  # type: ignore[assignment]
    """Dependency factory that also verifies the requested org_id is accessible."""

    async def _dependency(
        org_id: UUID, current_user: User = Depends(user_dependency)
    ) -> User:
        enforce_org_access(org_id, current_user)
        return current_user

    return _dependency
