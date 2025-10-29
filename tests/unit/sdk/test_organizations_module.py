import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro_sdk.organizations import OrganizationManager
from cerebro.core.models import Organization, Account, Resource


@pytest.mark.asyncio
async def test_organization_manager_workflow(test_db: AsyncSession):
    org = Organization(name="SDK Org")
    test_db.add(org)
    await test_db.commit()
    await test_db.refresh(org)

    account = Account(
        org_id=org.org_id,
        provider="github",
        external_id="sdk",
        display_name="SDK Account",
    )
    test_db.add(account)
    await test_db.commit()
    await test_db.refresh(account)

    resource = Resource(
        account_id=account.account_id,
        provider="github",
        resource_type="repo",
        external_id="writer/sdk",
        name="writer/sdk",
    )
    test_db.add(resource)
    await test_db.commit()

    manager = OrganizationManager(test_db)

    orgs = await manager.list_organizations()
    assert any(o.org_id == org.org_id for o in orgs)

    fetched = await manager.get_organization(org.org_id)
    assert fetched is not None and fetched.name == "SDK Org"

    accounts = await manager.list_accounts(org.org_id)
    assert accounts and accounts[0].external_id == "sdk"

    resources = await manager.list_resources(account.account_id)
    assert resources and resources[0].external_id == "writer/sdk"
