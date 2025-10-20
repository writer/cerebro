from __future__ import annotations

import pytest
from uuid import uuid4

from sqlalchemy import text

from cerebro.collectors.collector import CollectionResult
from cerebro.collectors.manager import CollectorManager


@pytest.mark.asyncio
async def test_collect_organization_raises_for_unknown_org(test_db):
    manager = CollectorManager(test_db)

    with pytest.raises(ValueError):
        await manager.collect_organization(uuid4())


@pytest.mark.asyncio
async def test_collect_organization_aggregates_success(
    test_db,
    test_org,
    test_github_account,
    monkeypatch,
):
    manager = CollectorManager(test_db)

    async def fake_collect_account(account, resource_types=None):
        return CollectionResult(
            account_id=account.account_id,
            provider=account.provider,
            resources_discovered=3,
            principals_discovered=1,
            config_snapshots=2,
            iam_edges=4,
        )

    monkeypatch.setattr(manager, "collect_account", fake_collect_account)

    summary = await manager.collect_organization(test_org.org_id)

    assert summary["organization"] == test_org.name
    assert summary["accounts_processed"] == 1
    assert summary["errors"] == []
    assert summary["summary"] == {
        "total_resources": 3,
        "total_principals": 1,
        "total_configs": 2,
        "total_iam_edges": 4,
    }


@pytest.mark.asyncio
async def test_collect_organization_records_account_errors(
    test_db,
    test_org,
    test_github_account,
    monkeypatch,
):
    manager = CollectorManager(test_db)

    async def failing_collect_account(account, resource_types=None):
        raise RuntimeError("collection failed")

    monkeypatch.setattr(manager, "collect_account", failing_collect_account)

    summary = await manager.collect_organization(test_org.org_id)

    assert summary["accounts_processed"] == 0
    assert summary["results"] == []
    assert any("collection failed" in error for error in summary["errors"])


@pytest.mark.asyncio
async def test_collect_organization_handles_empty_accounts(
    test_db,
    test_org,
    monkeypatch,
):
    manager = CollectorManager(test_db)

    # Ensure select(Account) returns no rows by deleting accounts
    await test_db.execute(text("DELETE FROM accounts"))
    await test_db.commit()

    summary = await manager.collect_organization(test_org.org_id)

    assert summary["accounts_processed"] == 0
    assert summary["errors"] == ["No accounts found for collection"]
