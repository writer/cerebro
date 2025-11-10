"""Unit tests for RuleEvaluator using a stub rule engine."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.core.models import Account, ConfigSnapshot, Organization, Resource, Rule
from cerebro.findings.evaluator import RuleEvaluator
from cerebro.rules import EvaluationContext, RuleResult


@dataclass
class StubRuleEngine:
    results: list[RuleResult]

    def evaluate_rules(
        self,
        rules: list[dict[str, Any]],
        context: EvaluationContext,
    ) -> list[RuleResult]:
        return self.results


@pytest.mark.asyncio
async def test_rule_evaluator_returns_stubbed_results(test_db: AsyncSession):
    org = Organization(name="Org")
    account = Account(org_id=org.org_id, provider="github", external_id="org")
    resource = Resource(provider="github", resource_type="repo", external_id="repo")
    rule = Rule(
        name="Test Rule",
        provider=["github"],
        resource_types=["repo"],
        expression_lang="cel",
        expression="resource.provider == 'github'",
        severity="high",
    )
    snapshot = ConfigSnapshot(
        resource_id=resource.resource_id,
        captured_at=datetime.utcnow(),
        config_sha=b"abc",
        normalized_config={"visibility": "public"},
        collector_version="1.0",
    )
    test_db.add(org)
    await test_db.flush()

    account.org_id = org.org_id
    test_db.add(account)
    await test_db.flush()

    resource.account_id = account.account_id
    test_db.add(resource)
    await test_db.flush()

    snapshot.resource_id = resource.resource_id
    test_db.add_all([rule, snapshot])
    await test_db.commit()

    result = RuleResult(rule_id=rule.rule_id, matched=True)
    evaluator = RuleEvaluator(test_db, StubRuleEngine([result]))
    outputs = await evaluator.evaluate_resource(resource)
    assert outputs == [result]
