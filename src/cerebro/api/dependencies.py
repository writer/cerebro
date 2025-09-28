"""FastAPI dependencies."""

from typing import AsyncGenerator
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.core.database import get_db
from cerebro.rules.engine import rule_engine
from cerebro.findings.evaluator import RuleEvaluator
from cerebro.findings.manager import FindingManager
from cerebro.collectors.manager import CollectorManager


async def get_rule_evaluator(db: AsyncSession = Depends(get_db)) -> RuleEvaluator:
    """Get rule evaluator instance."""
    return RuleEvaluator(db, rule_engine)


async def get_finding_manager(db: AsyncSession = Depends(get_db)) -> FindingManager:
    """Get finding manager instance."""
    evaluator = RuleEvaluator(db, rule_engine)
    return FindingManager(db, evaluator)


async def get_collector_manager(db: AsyncSession = Depends(get_db)) -> CollectorManager:
    """Get collector manager instance."""
    return CollectorManager(db)
