from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.agents.models import (
    AgentMemoryEntry,
    AgentReviewTask,
    AgentRuntimeEvent,
    MessageRole,
    ReviewTaskStatus,
)
from cerebro_sdk.agents import AgentAnalyticsClient, AgentManager, AgentReviewManager


@pytest.mark.asyncio
async def test_agent_manager_create_and_list_sessions(test_db: AsyncSession, test_org):
    manager = AgentManager(test_db)

    record = await manager.create_session(
        org_id=test_org.org_id,
        agent_type="security_analyst",
        created_by="analyst@example.com",
        context={"finding_ids": [str(uuid4())]},
        title="Investigate incident",
    )

    assert record.agent_type == "security_analyst"
    assert record.is_active is True

    sessions, total = await manager.list_sessions(org_id=test_org.org_id)
    assert total == 1
    assert sessions[0].title == "Investigate incident"


@pytest.mark.asyncio
async def test_agent_manager_messages_flow(test_db: AsyncSession, test_org):
    manager = AgentManager(test_db)
    session = await manager.create_session(
        org_id=test_org.org_id,
        agent_type="security_analyst",
        created_by="analyst@example.com",
        context={},
    )

    message = await manager.add_message(
        session_id=session.session_id,
        role="user",
        content={"text": "Summarize findings"},
    )
    assert message.role == "user"

    messages = await manager.list_messages(session_id=session.session_id)
    assert len(messages) == 1
    assert messages[0].content["text"] == "Summarize findings"

    deleted = await manager.delete_message(message.message_id)
    assert deleted is True

    messages_after = await manager.list_messages(session_id=session.session_id)
    assert messages_after == []


@pytest.mark.asyncio
async def test_agent_manager_memory_entries_and_stats(test_db: AsyncSession, test_org):
    manager = AgentManager(test_db)
    session = await manager.create_session(
        org_id=test_org.org_id,
        agent_type="security_analyst",
        created_by="memory@example.com",
        context={},
    )

    entry = AgentMemoryEntry(
        org_id=test_org.org_id,
        session_id=session.session_id,
        role=MessageRole.ASSISTANT,
        scopes=[{"type": "finding", "value": "abc"}],
        content="Detailed summary of the finding.",
        summary="finding summary",
        extra_metadata={"presented_count": 1},
        decay_score=1.25,
        token_count=64,
        last_accessed_at=datetime.now(timezone.utc),
    )
    test_db.add(entry)
    await test_db.commit()

    records = await manager.list_memory_entries(session_id=session.session_id, include_content=True)
    assert len(records) == 1
    assert records[0].content == "Detailed summary of the finding."

    stats = await manager.get_memory_stats(session_id=session.session_id)
    assert stats is not None
    assert stats.total_entries == 1
    assert stats.presented_entries == 1


@pytest.mark.asyncio
async def test_agent_review_manager_workflow(test_db: AsyncSession, test_org):
    manager = AgentManager(test_db)
    session = await manager.create_session(
        org_id=test_org.org_id,
        agent_type="security_analyst",
        created_by="reviewer@example.com",
        context={},
    )

    task = AgentReviewTask(
        org_id=test_org.org_id,
        session_id=session.session_id,
        title="Review remediation",
        summary="Approve remediation plan",
        payload={"severity": "high"},
        created_by="system",
        status=ReviewTaskStatus.PENDING,
    )
    test_db.add(task)
    await test_db.commit()
    await test_db.refresh(task)

    review_manager = AgentReviewManager(test_db)

    tasks = await review_manager.list_tasks(org_id=test_org.org_id)
    assert len(tasks) == 1

    updated = await review_manager.update_task_status(
        task_id=task.id,
        status="approved",
        resolved_by="lead@example.com",
        notes="Looks good",
    )
    assert updated is not None and updated.status == "approved"

    comment = await review_manager.add_comment(
        task_id=task.id,
        author="lead@example.com",
        content="Ship it",
    )
    assert comment.content == "Ship it"

    comments = await review_manager.list_comments(task_id=task.id)
    assert len(comments) == 1

    assigned = await review_manager.assign_task(
        task_id=task.id,
        assigned_to="secops@example.com",
        assigned_by="lead@example.com",
    )
    assert assigned is not None and assigned.assigned_to == "secops@example.com"

    bulk = await review_manager.bulk_update(
        org_id=test_org.org_id,
        task_ids=[task.id],
        priority="high",
        notification_channel="slack",
    )
    assert bulk and bulk[0].priority == "high"

    history = await review_manager.list_history(task_id=task.id)
    assert history and history[0].change_type in {"status_change", "assignment", "comment"}


@pytest.mark.asyncio
async def test_agent_analytics_client_summary(test_db: AsyncSession, test_org):
    manager = AgentManager(test_db)
    session = await manager.create_session(
        org_id=test_org.org_id,
        agent_type="security_analyst",
        created_by="analytics@example.com",
        context={"_skill_tags": ["runtime", "memory"]},
    )

    await manager.add_message(
        session_id=session.session_id,
        role="user",
        content={"text": "How many alerts?"},
    )

    event = AgentRuntimeEvent(
        org_id=test_org.org_id,
        session_id=session.session_id,
        event_type="runtime_selected",
        payload={"runtime": "claude"},
    )
    test_db.add(event)
    await test_db.commit()

    analytics = AgentAnalyticsClient(test_db)

    events = await analytics.list_events(session_id=session.session_id)
    assert events and events[0].event_type == "runtime_selected"

    summaries = await analytics.summarize_events(session_id=session.session_id)
    assert summaries and summaries[0].event_type == "runtime_selected"

    org_summary = await analytics.summarize_org(org_id=test_org.org_id)
    assert org_summary.total_sessions >= 1
    assert org_summary.message_count >= 1


@pytest.mark.asyncio
async def test_agent_manager_workflows_linking(test_db: AsyncSession, test_org):
    manager = AgentManager(test_db)
    session = await manager.create_session(
        org_id=test_org.org_id,
        agent_type="security_analyst",
        created_by="workflow@example.com",
        context={},
    )

    finding_id = uuid4()
    updated_session = await manager.link_findings(session_id=session.session_id, finding_ids=[finding_id])
    assert updated_session is not None and str(finding_id) in updated_session.context["finding_ids"]

    sessions = await manager.sessions_for_finding(org_id=test_org.org_id, finding_id=finding_id)
    assert len(sessions) == 1

    incident_id = uuid4()
    await manager.link_incident(session_id=session.session_id, incident_id=incident_id)

    incident_sessions = await manager.sessions_for_incident(org_id=test_org.org_id, incident_id=incident_id)
    assert len(incident_sessions) == 1

    derived = await manager.create_session_for_findings(
        org_id=test_org.org_id,
        created_by="workflow@example.com",
        finding_ids=[finding_id],
        title="Finding follow-up",
    )
    assert str(finding_id) in derived.context["finding_ids"]

    incident_session = await manager.create_incident_session(
        org_id=test_org.org_id,
        created_by="workflow@example.com",
        incident_id=incident_id,
    )
    assert incident_session.context["incident_id"] == str(incident_id)
