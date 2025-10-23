from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from cerebro.automation.daily_summary import build_slack_payload, generate_daily_summary
from cerebro.agents.models import AgentSession
from cerebro.core.models import Account, Finding, Policy, Rule


@pytest.mark.asyncio
async def test_generate_daily_summary_creates_session(test_db, test_org):
    policy = Policy(org_id=test_org.org_id, name="Test Policy")
    test_db.add(policy)
    await test_db.commit()
    await test_db.refresh(policy)

    rule = Rule(
        policy_id=policy.policy_id,
        name="Canary Rule",
        description="",
        provider=["github"],
        resource_types=["repo"],
        expression_lang="cel",
        expression="true",
        severity="high",
    )
    test_db.add(rule)

    account = Account(
        org_id=test_org.org_id,
        provider="github",
        external_id="example",
        display_name="Example Org",
    )
    test_db.add(account)
    await test_db.commit()
    await test_db.refresh(rule)
    await test_db.refresh(account)

    now = datetime.now(timezone.utc)
    finding = Finding(
        finding_id=uuid4(),
        org_id=test_org.org_id,
        account_id=account.account_id,
        provider="github",
        rule_id=rule.rule_id,
        rule_version=1,
        resource_id=None,
        principal_id=None,
        first_seen=now - timedelta(hours=2),
        last_seen=now - timedelta(hours=1),
        status="open",
        severity="high",
        fingerprint="fp-test",
        title="Public repository without branch protection",
        summary="Repository lacks required controls",
    )
    test_db.add(finding)
    await test_db.commit()

    summary = await generate_daily_summary(
        test_db,
        org_id=test_org.org_id,
        created_by="automation",
        limit=5,
        window_hours=24,
    )

    assert summary.org_id == test_org.org_id
    assert summary.total_findings() == 1
    assert summary.severity_totals()["high"] == 1

    stored_session = await test_db.get(AgentSession, summary.session_id)
    assert stored_session is not None
    assert stored_session.context["automation"] == "daily_agent_summary"
    assert str(finding.finding_id) in stored_session.context["finding_ids"]


@pytest.mark.asyncio
async def test_slack_payload_includes_expected_fields(test_db, test_org):
    # Reuse generate_daily_summary test to create data
    policy = Policy(org_id=test_org.org_id, name="Policy")
    test_db.add(policy)
    await test_db.commit()
    await test_db.refresh(policy)

    rule = Rule(
        policy_id=policy.policy_id,
        name="Rule",
        description="",
        provider=["github"],
        resource_types=["repo"],
        expression_lang="cel",
        expression="true",
        severity="critical",
    )
    test_db.add(rule)

    account = Account(
        org_id=test_org.org_id,
        provider="github",
        external_id="stage",
        display_name="Stage Org",
    )
    test_db.add(account)
    await test_db.commit()
    await test_db.refresh(rule)
    await test_db.refresh(account)

    now = datetime.now(timezone.utc)
    finding = Finding(
        finding_id=uuid4(),
        org_id=test_org.org_id,
        account_id=account.account_id,
        provider="github",
        rule_id=rule.rule_id,
        rule_version=1,
        resource_id=None,
        principal_id=None,
        first_seen=now - timedelta(hours=3),
        last_seen=now - timedelta(minutes=15),
        status="open",
        severity="critical",
        fingerprint="fp-critical",
        title="Production token leak",
        summary="",
    )
    test_db.add(finding)
    await test_db.commit()

    summary = await generate_daily_summary(
        test_db,
        org_id=test_org.org_id,
        created_by="automation",
        limit=1,
        window_hours=24,
    )

    payload = build_slack_payload(summary, session_url="https://example.com/sessions")
    assert "blocks" in payload
    assert payload["blocks"][0]["type"] == "header"
    assert "Daily Security Kickoff" in payload["blocks"][0]["text"]["text"]
    assert payload["blocks"][1]["fields"][1]["text"].startswith("*Findings:*")
    assert payload["blocks"][-1]["type"] in {"context", "actions"}
