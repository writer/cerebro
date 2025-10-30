from datetime import datetime, timezone, timedelta
from uuid import uuid4

import pytest
from prometheus_client import CollectorRegistry
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
    NotificationStatus,
    TicketStatus,
)
from cerebro_sdk.agents import (
    AgentAnalyticsClient,
    AgentInvalidStatusError,
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
async def test_agent_manager_memory_scope_counts(test_db: AsyncSession, test_org):
    manager = AgentManager(test_db)
    session = await manager.create_session(
        org_id=test_org.org_id,
        agent_type="security_analyst",
        created_by="memory-scope@example.com",
        context={},
    )

    scope_sets = [
        [{"type": "finding", "value": "A"}],
        [{"type": "incident", "value": "B"}],
        [{"type": "finding", "value": "C"}, {"type": "provider", "value": "aws"}],
    ]
    for idx, scopes in enumerate(scope_sets):
        entry = AgentMemoryEntry(
            org_id=test_org.org_id,
            session_id=session.session_id,
            role=MessageRole.ASSISTANT,
            scopes=scopes,
            content=f"Entry {idx}",
            summary=f"Entry {idx}",
            decay_score=1.0,
            token_count=10,
            last_accessed_at=datetime.now(timezone.utc),
        )
        test_db.add(entry)
    await test_db.commit()

    stats = await manager.get_memory_stats(session_id=session.session_id)
    assert stats is not None
    assert stats.scope_distribution.get("finding") == 2
    assert stats.scope_distribution.get("incident") == 1
    assert stats.scope_distribution.get("provider") == 1


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
async def test_agent_tooling_manager_filters(test_db: AsyncSession, test_org):
    agent_manager = AgentManager(test_db)
    session = await agent_manager.create_session(
        org_id=test_org.org_id,
        agent_type="security_analyst",
        created_by="filters@example.com",
        context={},
    )

    now = datetime.now(timezone.utc)
    statuses = [
        ToolInvocationStatus.PENDING,
        ToolInvocationStatus.SUCCESS,
        ToolInvocationStatus.ERROR,
    ]
    invocations = []
    for idx, status in enumerate(statuses):
        started_at = now - timedelta(hours=idx + 1)
        invocation = ToolInvocation(
            session_id=session.session_id,
            tool_name=f"tool-{idx}",
            tool_version="1.0",
            input_data={"idx": idx},
            status=status,
            started_at=started_at,
        )
        invocation.completed_at = started_at + timedelta(minutes=5)
        test_db.add(invocation)
        invocations.append(invocation)
    await test_db.commit()
    for invocation in invocations:
        await test_db.refresh(invocation)

    approvals = []
    for idx, status in enumerate([ApprovalStatus.PENDING, ApprovalStatus.APPROVED, ApprovalStatus.REJECTED]):
        approval = ToolApproval(
            org_id=test_org.org_id,
            tool_invocation_id=invocations[idx].id,
            requested_by=f"reviewer{idx}@example.com",
            reason="Routine check",
            risk_assessment={"impact": "medium"},
            status=status,
            requested_at=invocations[idx].started_at + timedelta(minutes=10),
        )
        test_db.add(approval)
        approvals.append(approval)
    await test_db.commit()

    tooling = AgentToolingManager(test_db)

    success = await tooling.list_invocations(org_id=test_org.org_id, status=ToolInvocationStatus.SUCCESS)
    assert len(success) == 1 and success[0].status == ToolInvocationStatus.SUCCESS.value

    recent = await tooling.list_invocations(org_id=test_org.org_id, since=now - timedelta(hours=2))
    assert len(recent) == 2

    cursor_time = invocations[1].started_at
    older = await tooling.list_invocations(org_id=test_org.org_id, cursor=cursor_time, page_size=5)
    assert all(record.started_at < cursor_time for record in older)

    pending = await tooling.list_approvals(org_id=test_org.org_id, status=ApprovalStatus.PENDING)
    assert len(pending) == 1 and pending[0].status == ApprovalStatus.PENDING.value

    approval_cursor = approvals[1].requested_at
    older_approvals = await tooling.list_approvals(
        org_id=test_org.org_id,
        cursor=approval_cursor,
        page_size=10,
    )
    assert all(record.requested_at < approval_cursor for record in older_approvals)


@pytest.mark.asyncio
async def test_agent_tooling_manager_rejection_updates_invocation(test_db: AsyncSession, test_org):
    agent_manager = AgentManager(test_db)
    session = await agent_manager.create_session(
        org_id=test_org.org_id,
        agent_type="security_analyst",
        created_by="rejection@example.com",
        context={},
    )

    started_at = datetime.now(timezone.utc)
    invocation = ToolInvocation(
        session_id=session.session_id,
        tool_name="dangerous.action",
        tool_version="2.0",
        input_data={"action": "delete"},
        status=ToolInvocationStatus.APPROVAL_REQUIRED,
        started_at=started_at,
    )
    test_db.add(invocation)
    await test_db.commit()
    await test_db.refresh(invocation)

    approval = ToolApproval(
        org_id=test_org.org_id,
        tool_invocation_id=invocation.id,
        requested_by="automaton@example.com",
        reason="High-risk operation",
        risk_assessment={"impact": "high"},
        status=ApprovalStatus.PENDING,
        requested_at=started_at,
    )
    test_db.add(approval)
    await test_db.commit()
    await test_db.refresh(approval)

    tooling = AgentToolingManager(test_db)
    record = await tooling.update_approval_status(
        approval_id=approval.id,
        status=ApprovalStatus.REJECTED.value,
        decided_by="secops@example.com",
        decision_reason="Not safe",
    )
    assert record is not None and record.status == ApprovalStatus.REJECTED.value

    await test_db.refresh(invocation)
    assert invocation.status == ToolInvocationStatus.ERROR
    assert invocation.error_message == "Not safe"


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
    assert notification.status == NotificationStatus.PENDING.value

    pending_notifications = await notification_manager.list_notifications(
        org_id=test_org.org_id,
        status=NotificationStatus.PENDING,
    )
    assert len(pending_notifications) == 1

    delivered = await notification_manager.mark_delivered(notification.notification_id)
    assert delivered is not None and delivered.status == NotificationStatus.DELIVERED.value

    with pytest.raises(AgentInvalidStatusError):
        await notification_manager.mark_delivered(notification.notification_id)

    ticket = await notification_manager.create_ticket(
        org_id=test_org.org_id,
        task_id=task.id,
        system="jira",
        summary="Investigate containment",
        metadata={"project": "SEC"},
    )
    assert ticket.status == TicketStatus.OPEN.value

    tickets = await notification_manager.list_tickets(task_id=task.id)
    assert len(tickets) == 1

    closed = await notification_manager.close_ticket(ticket_id=ticket.ticket_id, external_id="JIRA-123")
    assert closed is not None and closed.status == TicketStatus.CLOSED.value

    with pytest.raises(AgentInvalidStatusError):
        await notification_manager.close_ticket(ticket_id=ticket.ticket_id)


@pytest.mark.asyncio
async def test_agent_tooling_and_notification_metrics(test_db: AsyncSession, test_org):
    registry = CollectorRegistry()

    tooling = AgentToolingManager(test_db, registry=registry)
    await tooling.list_invocations(org_id=test_org.org_id)
    await tooling.list_approvals(org_id=test_org.org_id)

    tooling_list = registry.get_sample_value(
        "cerebro_sdk_tool_invocation_queries_total",
        labels={"operation": "list"},
    )
    approvals_list = registry.get_sample_value(
        "cerebro_sdk_tool_approval_queries_total",
        labels={"operation": "list"},
    )

    assert tooling_list == 1
    assert approvals_list == 1

    notifications = AgentNotificationManager(test_db, registry=registry)
    records = await notifications.list_notifications(org_id=test_org.org_id)
    assert records == []

    notif_list = registry.get_sample_value(
        "cerebro_sdk_notifications_total",
        labels={"operation": "list"},
    )
    assert notif_list == 1


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
    assert all(record.status == NotificationStatus.PENDING.value for record in notifications)

    ticket = await playbook.escalate_to_ticket(
        task_id=task.id,
        system="pagerduty",
        summary="Escalate containment",
    )
    assert ticket is not None and ticket.status == TicketStatus.OPEN.value

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
