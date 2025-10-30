import pytest

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

from cerebro_sdk.findings import FindingService
from cerebro_sdk.pagination import PageRequest


class StubSession:
    def __init__(self, rows):
        self._rows = rows

    async def scalars(self, _stmt):
        return self._rows


def build_finding(last_seen: datetime):
    finding_id = uuid4()
    return SimpleNamespace(
        finding_id=finding_id,
        org_id=uuid4(),
        account_id=uuid4(),
        provider="aws",
        rule_id=uuid4(),
        rule_version=1,
        resource_id=None,
        principal_id=None,
        first_seen=last_seen - timedelta(hours=1),
        last_seen=last_seen,
        status="open",
        severity="high",
        fingerprint="fp",
        title="Finding",
        summary=None,
        evidence=None,
    )


@pytest.mark.asyncio
async def test_list_findings_page_returns_items_and_cursor():
    now = datetime.now(timezone.utc)
    findings = [build_finding(now - timedelta(minutes=index)) for index in range(3)]
    service = FindingService(StubSession(findings))

    page = await service.list_findings_page(org_id=uuid4(), page=PageRequest(limit=2))

    assert len(page.items) == 2
    assert page.next_cursor is not None


@pytest.mark.asyncio
async def test_list_findings_page_last_page():
    now = datetime.now(timezone.utc)
    findings = [build_finding(now)]
    service = FindingService(StubSession(findings))

    page = await service.list_findings_page(org_id=uuid4(), page=PageRequest(limit=5))

    assert len(page.items) == 1
    assert page.next_cursor is None
