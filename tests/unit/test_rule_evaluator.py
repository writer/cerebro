"""Unit tests for RuleEvaluator using a stub rule engine."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.core.models import Rule, Resource, Account, Organization, ConfigSnapshot
from cerebro.findings.evaluator import RuleEvaluator
from cerebro.rules import EvaluationContext, RuleResult


@dataclass
class StubRuleEngine:
    results: List[RuleResult]

    def evaluate_rules(self, rules: List[Dict[str, Any]], context: EvaluationContext) -> List[RuleResult]:
        return self.results


@pytest.mark.asyncio
async def test_rule_evaluator_returns_stubbed_results(test_db: AsyncSession):
    org = Organization(name="Org")
    account = Account(org=org, provider="github", external_id="org")
    resource = Resource(account=account, provider="github", resource_type="repo", external_id="repo")
    rule = Rule(
        name="Test Rule",
        provider=["github"],
        resource_types=["repo"],
        expression_lang="cel",
        expression="resource.provider == 'github'",
        severity="high",
    )
    snapshot = ConfigSnapshot(
        resource=resource,
        captured_at=org.created_at,
        config_sha=b"abc",
        normalized_config={"visibility": "public"},
        collector_version="1.0",
    )
    test_db.add_all([org, account, resource, rule, snapshot])
    await test_db.commit()

    result = RuleResult(rule_id=rule.rule_id, matched=True)
    evaluator = RuleEvaluator(test_db, StubRuleEngine([result]))
    outputs = await evaluator.evaluate_resource(resource)
    assert outputs == [result]
