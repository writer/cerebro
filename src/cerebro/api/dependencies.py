"""FastAPI dependencies."""

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.core.database import get_db
from cerebro.core.security.key_store import JWTKeyStore
from cerebro.core.security.jwt import JWTService
from cerebro.collectors.manager import CollectorManager
from cerebro.findings.evaluator import RuleEvaluator
from cerebro.findings.manager import FindingManager
from cerebro.metrics.jwt_metrics import jwt_metrics
from cerebro.rules.engine import rule_engine


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


async def get_jwt_service(db: AsyncSession = Depends(get_db)) -> JWTService:
    """Provide JWT service backed by the configured key store."""
    key_store = JWTKeyStore(db, metrics=jwt_metrics)
    await key_store.rotate_keys_if_needed()
    return JWTService(key_store, metrics=jwt_metrics)
