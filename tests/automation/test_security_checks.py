from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from cerebro.automation.security_checks import (
    find_stale_admins,
    has_cel_canary,
    tools_missing_attestation,
)
from cerebro.core.models import Rule
from cerebro.core.user_models import User


@pytest.mark.asyncio
async def test_find_stale_admins_detects_old_accounts(test_db):
    old_login = datetime.now(UTC) - timedelta(days=200)
    user = User(
        username="admin",
        email="admin@example.com",
        hashed_password="hashed::secret",
        is_admin=True,
        last_login=old_login,
    )
    test_db.add(user)
    await test_db.commit()

    results = await find_stale_admins(test_db, max_age_days=90)
    assert results and results[0].username == "admin"


@pytest.mark.asyncio
async def test_has_cel_canary_detects_presence(test_db, test_policy):
    rule = Rule(
        policy_id=test_policy.policy_id,
        name="cel.canary.policy",
        description="",
        provider=["github"],
        resource_types=["repo"],
        expression_lang="cel",
        expression="true",
        severity="low",
    )
    test_db.add(rule)
    await test_db.commit()

    assert await has_cel_canary(test_db, rule_name="cel.canary.policy") is True


def test_tools_missing_attestation_returns_list() -> None:
    issues = tools_missing_attestation()
    assert isinstance(issues, list)
