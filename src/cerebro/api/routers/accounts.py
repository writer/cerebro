"""Account management endpoints."""

from typing import List
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from cerebro.core.database import get_db
from cerebro.core.models import Account, Organization
from cerebro.api.schemas import AccountCreate, AccountResponse
from cerebro.api.auth import get_current_user, require_scopes, User

router = APIRouter(dependencies=[Depends(get_current_user)])


@router.post("/", response_model=AccountResponse)
async def create_account(
    account: AccountCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scopes("admin")),
):
    """Create a new account."""
    # Verify organization exists
    org = await db.get(Organization, account.org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    # Check for duplicate
    stmt = select(Account).where(
        Account.org_id == account.org_id,
        Account.provider == account.provider,
        Account.external_id == account.external_id,
    )
    existing = await db.scalar(stmt)
    if existing:
        raise HTTPException(status_code=400, detail="Account already exists")

    db_account = Account(
        org_id=account.org_id,
        provider=account.provider,
        external_id=account.external_id,
        display_name=account.display_name,
    )
    db.add(db_account)
    await db.commit()
    await db.refresh(db_account)
    return db_account


@router.get("/", response_model=List[AccountResponse])
async def list_accounts(
    org_id: UUID = None,
    provider: str = None,
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
):
    """List accounts."""
    stmt = select(Account)

    if org_id:
        stmt = stmt.where(Account.org_id == org_id)
    if provider:
        stmt = stmt.where(Account.provider == provider)

    stmt = stmt.offset(skip).limit(limit)
    accounts = await db.scalars(stmt)
    return list(accounts)


@router.get("/{account_id}", response_model=AccountResponse)
async def get_account(account_id: UUID, db: AsyncSession = Depends(get_db)):
    """Get account by ID."""
    account = await db.get(Account, account_id)
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    return account


@router.delete("/{account_id}")
async def delete_account(
    account_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scopes("admin")),
):
    """Delete an account."""
    account = await db.get(Account, account_id)
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")

    await db.delete(account)
    await db.commit()
    return {"message": "Account deleted successfully"}
