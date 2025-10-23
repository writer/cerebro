"""Security posture checks for operator workflows."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import List

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.agents.tools import get_tool_registry, ToolPermissionLevel
from cerebro.core.models import Rule
from cerebro.core.user_models import User


@dataclass(slots=True)
class StaleAdminUser:
    user_id: str
    username: str
    email: str
    last_login: datetime | None
    created_at: datetime


async def find_stale_admins(
    db: AsyncSession,
    *,
    max_age_days: int = 90,
) -> List[StaleAdminUser]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)

    query = (
        select(User)
        .where(User.is_admin == True)
        .where(
            or_(
                User.last_login.is_(None),
                User.last_login < cutoff,
            )
        )
    )

    rows = (await db.execute(query)).scalars().all()
    return [
        StaleAdminUser(
            user_id=str(row.user_id),
            username=row.username,
            email=row.email,
            last_login=row.last_login,
            created_at=row.created_at,
        )
        for row in rows
    ]


async def has_cel_canary(db: AsyncSession, rule_name: str = "cel.canary.policy") -> bool:
    query = select(Rule).where(Rule.name == rule_name, Rule.is_active == True)
    result = await db.execute(query)
    return result.scalar_one_or_none() is not None


def tools_missing_attestation() -> List[str]:
    registry = get_tool_registry()
    issues: List[str] = []
    for tool in registry.list_tools():
        if tool.permission_level in (
            ToolPermissionLevel.WRITE_SAFE,
            ToolPermissionLevel.WRITE_DESTRUCTIVE,
            ToolPermissionLevel.ADMIN,
        ) and not tool.cel_policy_key:
            issues.append(tool.name)
    return issues
