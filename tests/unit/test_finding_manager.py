"""Unit tests for FindingManager lifecycle."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.findings.manager import FindingManager, FindingResult


class StubEvaluator:
    async def evaluate_organization(self, org, provider=None, resource_types=None):
        return {}


@pytest.mark.asyncio
async def test_generate_findings_handles_empty_results(test_db: AsyncSession):
    manager = FindingManager(test_db, StubEvaluator())  # type: ignore[arg-type]
    result = await manager.generate_findings(org=None)  # type: ignore[arg-type]
    assert isinstance(result, FindingResult)
