from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.core.models import Finding
from cerebro_sdk.findings import FindingService


@pytest.mark.asyncio
async def test_finding_service_list_and_close(
    test_db: AsyncSession,
    test_org,
    test_github_account,
    test_resource,
    test_rule,
):
    service = FindingService(test_db)

    finding = Finding(
        finding_id=uuid4(),
        org_id=test_org.org_id,
        account_id=test_github_account.account_id,
        provider="github",
        rule_id=test_rule.rule_id,
        rule_version=test_rule.version,
        resource_id=test_resource.resource_id,
        first_seen=datetime.now(UTC),
        last_seen=datetime.now(UTC),
        status="open",
        severity="medium",
        fingerprint="sdk-test",
        title="SDK Test Finding",
        summary="Created for SDK test",
    )
    test_db.add(finding)
    await test_db.commit()

    records = await service.list_findings(test_org.org_id)
    assert records and records[0].title == "SDK Test Finding"

    closed = await service.close_finding(finding.finding_id)
    assert closed is True
    updated = await service.get_finding(finding.finding_id)
    assert updated is not None and updated.status == "fixed"


@pytest.mark.asyncio
async def test_finding_service_generate_for_org(test_db: AsyncSession, test_org):
    service = FindingService(test_db)
    result = await service.generate_for_org(test_org.org_id)
    assert result.findings_created == 0
