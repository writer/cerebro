from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.agents.models import (
    AgentMemoryEntry,
    AgentPolicySuggestion,
    AgentReviewTask,
    AgentRuntimeEvent,
    ToolApproval,
    ToolInvocation,
    MessageRole,
    ReviewTaskStatus,
    ToolInvocationStatus,
    ApprovalStatus,
)
from cerebro_sdk.agents import (
    AgentAnalyticsClient,
    AgentManager,
    AgentNotificationManager,
    AgentPlaybook,
    AgentReviewManager,
    AgentToolingManager,
)


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
async def test_agent_tooling_manager_operations(test_db: AsyncSession, test_org):
    agent_manager = AgentManager(test_db)
    session = await agent_manager.create_session(
        org_id=test_org.org_id,
        agent_type="security_analyst",
        created_by="tooling@example.com",
        context={},
    )

    invocation = ToolInvocation(
        session_id=session.session_id,
        tool_name="timeline.generate",
        tool_version="1.0",
        input_data={"scope": "incident"},
        status=ToolInvocationStatus.PENDING,
    )
    test_db.add(invocation)
    await test_db.commit()
    await test_db.refresh(invocation)

    approval = ToolApproval(
        org_id=test_org.org_id,
        tool_invocation_id=invocation.id,
        requested_by="tooling@example.com",
        reason="Requires approval",
        risk_assessment={"impact": "high"},
        status=ApprovalStatus.PENDING,
    )
    suggestion = AgentPolicySuggestion(
        org_id=test_org.org_id,
        tool_name="timeline.generate",
        cel_expression="input.scope == 'incident'",
        support_count=1,
        reject_count=0,
        details={"source": "sdk-test"},
    )
    test_db.add_all([approval, suggestion])
    await test_db.commit()

    tooling = AgentToolingManager(test_db)

    invocations = await tooling.list_invocations(org_id=test_org.org_id)
    assert len(invocations) == 1 and invocations[0].tool_name == "timeline.generate"

    approvals = await tooling.list_approvals(org_id=test_org.org_id)
    assert approvals and approvals[0].status == "pending"

    updated = await tooling.update_approval_status(
        approval_id=approval.id,
        status="approved",
        decided_by="lead@example.com",
        decision_reason="Verified",
    )
    assert updated is not None and updated.status == "approved"

    await test_db.refresh(invocation)
    assert invocation.status == ToolInvocationStatus.SUCCESS

    suggestions = await tooling.list_policy_suggestions(org_id=test_org.org_id)
    assert suggestions and suggestions[0].tool_name == "timeline.generate"


@pytest.mark.asyncio
async def test_agent_notification_manager(test_db: AsyncSession, test_org):
    manager = AgentManager(test_db)
    session = await manager.create_session(
        org_id=test_org.org_id,
        agent_type="security_analyst",
        created_by="notify@example.com",
        context={},
    )

    task = AgentReviewTask(
        org_id=test_org.org_id,
        session_id=session.session_id,
        title="Verify containment",
        summary="Confirm containment steps",
        payload={},
        created_by="system",
        status=ReviewTaskStatus.PENDING,
    )
    test_db.add(task)
    await test_db.commit()
    await test_db.refresh(task)

    notification_manager = AgentNotificationManager(test_db)
    notification = await notification_manager.enqueue_notification(
        org_id=test_org.org_id,
        task_id=task.id,
        channel="slack",
        payload={"priority": "high"},
    )
    assert notification.status == "pending"

    notifications = await notification_manager.list_notifications(org_id=test_org.org_id)
    assert len(notifications) == 1

    delivered = await notification_manager.mark_delivered(notification.notification_id)
    assert delivered is not None and delivered.status == "delivered"

    ticket = await notification_manager.create_ticket(
        org_id=test_org.org_id,
        task_id=task.id,
        system="jira",
        summary="Investigate containment",
        metadata={"project": "SEC"},
    )
    assert ticket.status == "open"

    tickets = await notification_manager.list_tickets(task_id=task.id)
    assert len(tickets) == 1

    closed = await notification_manager.close_ticket(ticket_id=ticket.ticket_id, external_id="JIRA-123")
    assert closed is not None and closed.status == "closed"


@pytest.mark.asyncio
async def test_agent_playbook_helpers(test_db: AsyncSession, test_org):
    playbook = AgentPlaybook(test_db)
    finding_id = uuid4()

    findings_session = await playbook.kickoff_findings_playbook(
        org_id=test_org.org_id,
        created_by="playbook@example.com",
        finding_ids=[finding_id],
        title="Finding triage",
    )
    assert str(finding_id) in findings_session.context["finding_ids"]

    incident_id = uuid4()
    incident_session = await playbook.start_incident_playbook(
        org_id=test_org.org_id,
        created_by="playbook@example.com",
        incident_id=incident_id,
        finding_ids=[finding_id],
        title="Incident response",
    )
    assert incident_session.context["incident_id"] == str(incident_id)

    entry = AgentMemoryEntry(
        org_id=test_org.org_id,
        session_id=findings_session.session_id,
        role=MessageRole.ASSISTANT,
        scopes=[{"type": "finding", "value": str(finding_id)}],
        content="Initial assessment",
        summary="assessment",
        decay_score=1.0,
        token_count=16,
        last_accessed_at=datetime.now(timezone.utc),
    )
    test_db.add(entry)
    await test_db.commit()

    snapshot = await playbook.memory_snapshot(session_id=findings_session.session_id)
    assert snapshot is not None and snapshot.total_entries == 1

    task = AgentReviewTask(
        org_id=test_org.org_id,
        session_id=incident_session.session_id,
        title="Review containment",
        summary="Need approval",
        payload={},
        created_by="system",
        status=ReviewTaskStatus.PENDING,
    )
    test_db.add(task)
    await test_db.commit()
    await test_db.refresh(task)

    notifications = await playbook.schedule_notifications(task_id=task.id, channels=["slack", "pagerduty"])
    assert len(notifications) == 2

    ticket = await playbook.escalate_to_ticket(
        task_id=task.id,
        system="pagerduty",
        summary="Escalate containment",
    )
    assert ticket is not None and ticket.status == "open"

    suggestion = await playbook.record_policy_suggestion(
        org_id=test_org.org_id,
        tool_name="timeline.generate",
        cel_expression="input.scope == 'incident'",
        details={"reason": "pattern"},
    )
    assert suggestion.support_count == 1

    updated = await playbook.record_policy_suggestion(
        org_id=test_org.org_id,
        tool_name="timeline.generate",
        cel_expression="input.scope == 'incident'",
        support_delta=2,
    )
    assert updated.support_count == 3
