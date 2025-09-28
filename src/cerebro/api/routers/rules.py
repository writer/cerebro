"""Rule management endpoints."""

from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from cerebro.core.database import get_db
from cerebro.core.models import Rule, Policy
from cerebro.api.schemas import RuleCreate, RuleResponse
from cerebro.rules.engine import rule_engine

router = APIRouter()


@router.post("/", response_model=RuleResponse)
async def create_rule(
    rule: RuleCreate,
    db: AsyncSession = Depends(get_db)
):
    """Create a new rule."""
    # Verify policy exists if provided
    if rule.policy_id:
        policy = await db.get(Policy, rule.policy_id)
        if not policy:
            raise HTTPException(status_code=404, detail="Policy not found")
    
    # Test compile the rule if it's CEL
    if rule.expression_lang == "cel":
        try:
            rule_engine.compile_rule(rule.expression)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Rule compilation failed: {e}")
    
    db_rule = Rule(
        policy_id=rule.policy_id,
        name=rule.name,
        description=rule.description,
        provider=rule.provider,
        resource_types=rule.resource_types,
        expression_lang=rule.expression_lang,
        expression=rule.expression,
        severity=rule.severity,
        cwe=rule.cwe,
        cis=rule.cis,
        nist_800_53=rule.nist_800_53,
        mitre_attack=rule.mitre_attack
    )
    
    db.add(db_rule)
    await db.commit()
    await db.refresh(db_rule)
    return db_rule


@router.get("/", response_model=List[RuleResponse])
async def list_rules(
    provider: Optional[str] = None,
    severity: Optional[str] = None,
    is_active: Optional[bool] = True,
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db)
):
    """List rules."""
    stmt = select(Rule)
    
    if provider:
        stmt = stmt.where(Rule.provider.contains([provider]))
    if severity:
        stmt = stmt.where(Rule.severity == severity)
    if is_active is not None:
        stmt = stmt.where(Rule.is_active == is_active)
    
    stmt = stmt.offset(skip).limit(limit)
    rules = await db.scalars(stmt)
    return list(rules)


@router.get("/{rule_id}", response_model=RuleResponse)
async def get_rule(
    rule_id: UUID,
    db: AsyncSession = Depends(get_db)
):
    """Get rule by ID."""
    rule = await db.get(Rule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule


@router.put("/{rule_id}", response_model=RuleResponse)
async def update_rule(
    rule_id: UUID,
    rule_update: RuleCreate,
    db: AsyncSession = Depends(get_db)
):
    """Update a rule."""
    db_rule = await db.get(Rule, rule_id)
    if not db_rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    # Test compile the rule if it's CEL
    if rule_update.expression_lang == "cel":
        try:
            rule_engine.compile_rule(rule_update.expression)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Rule compilation failed: {e}")
    
    # Update fields
    db_rule.name = rule_update.name
    db_rule.description = rule_update.description
    db_rule.provider = rule_update.provider
    db_rule.resource_types = rule_update.resource_types
    db_rule.expression_lang = rule_update.expression_lang
    db_rule.expression = rule_update.expression
    db_rule.severity = rule_update.severity
    db_rule.cwe = rule_update.cwe
    db_rule.cis = rule_update.cis
    db_rule.nist_800_53 = rule_update.nist_800_53
    db_rule.mitre_attack = rule_update.mitre_attack
    db_rule.version += 1  # Increment version
    
    await db.commit()
    await db.refresh(db_rule)
    return db_rule


@router.delete("/{rule_id}")
async def deactivate_rule(
    rule_id: UUID,
    db: AsyncSession = Depends(get_db)
):
    """Deactivate a rule (soft delete)."""
    rule = await db.get(Rule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    rule.is_active = False
    await db.commit()
    return {"message": "Rule deactivated successfully"}


@router.post("/{rule_id}/test")
async def test_rule(
    rule_id: UUID,
    db: AsyncSession = Depends(get_db)
):
    """Test a rule compilation."""
    rule = await db.get(Rule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    if rule.expression_lang != "cel":
        raise HTTPException(status_code=400, detail="Only CEL rules can be tested")
    
    try:
        compiled = rule_engine.compile_rule(rule.expression)
        return {
            "rule_id": rule_id,
            "status": "success",
            "message": "Rule compiled successfully"
        }
    except Exception as e:
        return {
            "rule_id": rule_id,
            "status": "error",
            "message": str(e)
        }
