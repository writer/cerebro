from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from cerebro.agents.models import (
    AgentReviewTask,
    AgentSession,
    AgentType,
    ReviewTaskStatus,
)


def _run_async(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def test_review_queue_summary_endpoint(client, test_db, test_org, test_token):
    async def _seed_tasks():
        session = AgentSession(
            org_id=test_org.org_id,
            agent_type=AgentType.SECURITY_ANALYST,
            created_by="reviewer",
            context={},
        )
        test_db.add(session)
        await test_db.flush()

        now = datetime.now(timezone.utc)

        tasks = [
            AgentReviewTask(
                org_id=test_org.org_id,
                session_id=session.id,
                title="Investigate finding",
                summary="Review flagged finding",
                payload={"finding_id": "f-1"},
                status=ReviewTaskStatus.PENDING,
                priority="high",
                due_at=now - timedelta(hours=2),
                created_by="system",
            ),
            AgentReviewTask(
                org_id=test_org.org_id,
                session_id=session.id,
                title="Approve remediation",
                summary="Confirm remediation plan",
                payload={"finding_id": "f-2"},
                status=ReviewTaskStatus.PENDING,
                priority="medium",
                due_at=now + timedelta(hours=4),
                assigned_to="analyst@example.com",
                created_by="system",
            ),
            AgentReviewTask(
                org_id=test_org.org_id,
                session_id=session.id,
                title="Closed task",
                summary="Already handled",
                payload={},
                status=ReviewTaskStatus.APPROVED,
                created_by="system",
                resolved_by="analyst",
                resolved_at=now,
            ),
        ]

        test_db.add_all(tasks)
        await test_db.commit()

    _run_async(_seed_tasks())

    headers = {"Authorization": f"Bearer {test_token}"}
    response = client.get(
        "/api/v1/agents/review-tasks/summary",
        headers=headers,
    )

    assert response.status_code == 200, response.text

    summary = response.json()
    pending = summary["pending"]
    assert pending["total"] == 2
    assert pending["unassigned"] == 1
    assert pending["overdue"] == 1
    assert pending["next_due"] is not None

    status_counts = {entry["status"]: entry for entry in summary["status_counts"]}
    assert status_counts["pending"]["count"] == 2
    assert status_counts["approved"]["count"] == 1

    priority_breakdown = {
        entry["priority"]: entry["count"] for entry in summary["priority_breakdown"]
    }
    assert priority_breakdown.get("high") == 1
