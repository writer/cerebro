from __future__ import annotations

from datetime import datetime
from typing import Dict, Optional
from unittest.mock import AsyncMock

import pytest

from cerebro.collectors.collector import ConfigCollector
from cerebro.providers.base import (
    BaseProvider,
    ResourceInfo,
    PrincipalInfo,
    ConfigurationSnapshot,
    IamPermission,
)


class StubProvider(BaseProvider):
    """Minimal provider implementation for collector tests."""

    def __init__(self, account_id, *, config_map: Optional[Dict[str, Dict]] = None, raise_on_config: bool = False):
        super().__init__(account_id)
        self._config_map = config_map or {}
        self._raise_on_config = raise_on_config

    @property
    def name(self) -> str:
        return "github"

    async def authenticate(self) -> bool:
        return True

    async def discover_resources(self, resource_types=None):
        for external_id in self._config_map.keys():
            yield ResourceInfo(
                external_id=external_id,
                name=external_id,
                resource_type="github.repo",
            )

    async def discover_principals(self):
        for principal in []:
            yield principal

    async def get_resource_configuration(self, resource: ResourceInfo) -> ConfigurationSnapshot:
        if self._raise_on_config:
            raise RuntimeError("config fetch failed")

        config = self._config_map.get(resource.external_id)
        if not config:
            return None

        return ConfigurationSnapshot(
            resource_external_id=resource.external_id,
            captured_at=config["captured_at"],
            normalized_config=config["normalized_config"],
        )

    async def discover_iam_edges(self):
        for edge in []:
            yield edge


@pytest.mark.asyncio
async def test_config_collector_persists_configuration(
    test_db,
    test_github_account,
    test_resource,
):
    collector = ConfigCollector(test_db)

    collector.bulk_ops.bulk_upsert_resources = AsyncMock(return_value={"processed": 0})
    collector.bulk_ops.bulk_upsert_principals = AsyncMock(return_value={"processed": 0})
    collector.bulk_ops.bulk_insert_config_snapshots = AsyncMock(return_value=1)
    collector.bulk_ops.preload_principal_map = AsyncMock(return_value={})
    collector.bulk_ops.preload_resource_map = AsyncMock(return_value={})
    collector.bulk_ops.bulk_insert_iam_edges = AsyncMock(return_value=0)

    captured_at = datetime.utcnow()
    provider = StubProvider(
        test_github_account.account_id,
        config_map={
            test_resource.external_id: {
                "captured_at": captured_at,
                "normalized_config": {"visibility": "private"},
            }
        },
    )

    result = await collector.collect_account(provider, test_github_account)

    assert result.config_snapshots == 1
    assert result.errors == []

    insert_args = collector.bulk_ops.bulk_insert_config_snapshots.await_args
    snapshots = insert_args.args[1]
    assert snapshots[0]["resource_id"] == test_resource.resource_id
    assert snapshots[0]["normalized_config"] == {"visibility": "private"}


@pytest.mark.asyncio
async def test_config_collector_records_errors_on_insert_failure(
    test_db,
    test_github_account,
    test_resource,
):
    collector = ConfigCollector(test_db)

    collector.bulk_ops.bulk_upsert_resources = AsyncMock(return_value={"processed": 0})
    collector.bulk_ops.bulk_upsert_principals = AsyncMock(return_value={"processed": 0})
    collector.bulk_ops.bulk_insert_config_snapshots = AsyncMock(side_effect=RuntimeError("db down"))
    collector.bulk_ops.preload_principal_map = AsyncMock(return_value={})
    collector.bulk_ops.preload_resource_map = AsyncMock(return_value={})
    collector.bulk_ops.bulk_insert_iam_edges = AsyncMock(return_value=0)

    provider = StubProvider(
        test_github_account.account_id,
        config_map={
            test_resource.external_id: {
                "captured_at": datetime.utcnow(),
                "normalized_config": {"visibility": "private"},
            }
        },
    )

    result = await collector.collect_account(provider, test_github_account)

    assert result.config_snapshots == 0
    assert any("Failed to collect configurations" in err for err in result.errors)
