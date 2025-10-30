import { beforeEach, describe, expect, it, vi } from "vitest";

import HttpClient from "../src/httpClient";
import { AgentsClient } from "../src/clients/agents";

const fetchMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
  // @ts-expect-error assign test double
  globalThis.fetch = fetchMock;
});

describe("AgentsClient", () => {
  it("returns review queue summary with camelCase fields", async () => {
    const now = new Date().toISOString();
    fetchMock.mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ({
        generated_at: now,
        status_counts: [
          {
            status: "pending",
            count: 5,
            unassigned: 2,
            overdue: 1,
            oldest_created: now,
            newest_created: now,
          },
        ],
        pending: {
          total: 5,
          unassigned: 2,
          overdue: 1,
          next_due: now,
          oldest_created: now,
        },
        priority_breakdown: [
          {
            priority: "high",
            count: 3,
          },
        ],
      }),
    });

    const client = new AgentsClient(new HttpClient({ baseUrl: "https://api.example.com" }));
    const summary = await client.getReviewQueueSummary();

    expect(summary.generatedAt).toBeInstanceOf(Date);
    expect(summary.statusCounts[0].status).toBe("pending");
    expect(summary.priorityBreakdown[0].priority).toBe("high");
  });

  it("lists review tasks", async () => {
    const now = new Date().toISOString();
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ([
        {
          id: "task-1",
          session_id: "session-1",
          org_id: "org-1",
          status: "pending",
          title: "Review",
          summary: null,
          payload: null,
          promotion_target: null,
          priority: "high",
          due_at: now,
          escalated_to: null,
          notification_channel: null,
          ticket_reference: null,
          created_by: "user",
          created_at: now,
          resolved_by: null,
          resolved_at: null,
          resolution_notes: null,
        },
      ]),
    });

    const client = new AgentsClient(new HttpClient({ baseUrl: "https://api.example.com" }));
    const tasks = await client.listReviewTasks({ status: "pending", limit: 5 });

    expect(tasks).toHaveLength(1);
    expect(tasks[0].taskId).toBe("task-1");
    expect(tasks[0].dueAt).toBeInstanceOf(Date);
    expect(tasks[0].payload).toEqual({});
    const [url] = fetchMock.mock.calls[0];
    expect(url).toContain("status=pending");
    expect(url).toContain("limit=5");
  });

  it("lists review tasks using cursor pagination", async () => {
    const now = new Date().toISOString();
    fetchMock.mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ({
        items: [
          {
            id: "task-1",
            session_id: "session-1",
            org_id: "org-1",
            status: "pending",
            title: "Review",
            summary: "Summary",
            payload: { foo: "bar" },
            promotion_target: null,
            priority: "high",
            due_at: now,
            escalated_to: null,
            notification_channel: null,
            ticket_reference: null,
            created_by: "user",
            created_at: now,
            resolved_by: null,
            resolved_at: null,
            resolution_notes: null,
          },
        ],
        next_cursor: "cursor-next",
      }),
    });

    const client = new AgentsClient(new HttpClient({ baseUrl: "https://api.example.com" }));
    const page = await client.listReviewTasksPage({ status: "pending", cursor: "cursor-token", limit: 10 });

    expect(page.items).toHaveLength(1);
    expect(page.items[0].taskId).toBe("task-1");
    expect(page.items[0].dueAt).toBeInstanceOf(Date);
    expect(page.nextCursor).toBe("cursor-next");
    const [url] = fetchMock.mock.calls[0];
    expect(url).toContain("status=pending");
    expect(url).toContain("cursor=cursor-token");
    expect(url).toContain("limit=10");
  });

  it("bulk updates review tasks with optional fields", async () => {
    const now = new Date();
    const iso = now.toISOString();
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ([
        {
          id: "task-1",
          session_id: "session-1",
          org_id: "org-1",
          status: "resolved",
          title: "Review",
          summary: null,
          payload: {},
          promotion_target: null,
          priority: null,
          due_at: iso,
          escalated_to: null,
          notification_channel: null,
          ticket_reference: null,
          created_by: "user",
          created_at: iso,
          resolved_by: "resolver",
          resolved_at: iso,
          resolution_notes: "done",
        },
      ]),
    });

    const client = new AgentsClient(new HttpClient({ baseUrl: "https://api.example.com" }));
    const result = await client.bulkUpdateReviewTasks({
      taskIds: ["task-1"],
      status: "resolved",
      notes: "done",
      dueAt: now,
      notificationChannel: "slack:#alerts",
      ticketMetadata: { external: true },
    });

    expect(result).toHaveLength(1);
    const [, init] = fetchMock.mock.calls[0];
    expect(JSON.parse((init as RequestInit).body as string)).toEqual({
      task_ids: ["task-1"],
      status: "resolved",
      notes: "done",
      due_at: iso,
      notification_channel: "slack:#alerts",
      ticket_metadata: { external: true },
    });
  });

  it("resolves review tasks with notes", async () => {
    const now = new Date().toISOString();
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ({
        id: "task-1",
        session_id: "session-1",
        org_id: "org-1",
        status: "resolved",
        title: "Review",
        summary: null,
        payload: {},
        promotion_target: null,
        priority: null,
        due_at: now,
        escalated_to: null,
        notification_channel: null,
        ticket_reference: null,
        created_by: "user",
        created_at: now,
        resolved_by: "resolver",
        resolved_at: now,
        resolution_notes: "done",
      }),
    });

    const client = new AgentsClient(new HttpClient({ baseUrl: "https://api.example.com" }));
    const record = await client.resolveReviewTask("task-1", { status: "resolved", notes: "done" });

    expect(record.status).toBe("resolved");
    expect(record.resolutionNotes).toBe("done");
    const [, init] = fetchMock.mock.calls[0];
    expect(JSON.parse((init as RequestInit).body as string)).toEqual({ status: "resolved", notes: "done" });
  });

  it("assigns review tasks", async () => {
    const now = new Date().toISOString();
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ({
        id: "task-1",
        session_id: "session-1",
        org_id: "org-1",
        status: "pending",
        title: "Review",
        summary: null,
        payload: {},
        promotion_target: null,
        priority: null,
        due_at: now,
        escalated_to: null,
        notification_channel: null,
        ticket_reference: null,
        created_by: "user",
        created_at: now,
        resolved_by: null,
        resolved_at: null,
        resolution_notes: null,
      }),
    });

    const client = new AgentsClient(new HttpClient({ baseUrl: "https://api.example.com" }));
    await client.assignReviewTask("task-1", "analyst");

    const [, init] = fetchMock.mock.calls[0];
    expect(JSON.parse((init as RequestInit).body as string)).toEqual({ assigned_to: "analyst" });
  });

  it("adds and lists comments", async () => {
    const now = new Date().toISOString();
    fetchMock
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers({ "content-type": "application/json" }),
        json: async () => ({
          id: "comment-1",
          task_id: "task-1",
          author: "user",
          content: "note",
          created_at: now,
          updated_at: null,
          metadata: { tag: "test" },
        }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers({ "content-type": "application/json" }),
        json: async () => ([
          {
            id: "comment-1",
            task_id: "task-1",
            author: "user",
            content: "note",
            created_at: now,
            updated_at: null,
            metadata: { tag: "test" },
          },
        ]),
      });

    const client = new AgentsClient(new HttpClient({ baseUrl: "https://api.example.com" }));
    const created = await client.addReviewTaskComment("task-1", "note", { tag: "test" });
    expect(created.metadata).toEqual({ tag: "test" });

    const comments = await client.listReviewTaskComments("task-1", { limit: 25 });
    expect(comments).toHaveLength(1);
    expect(comments[0].commentId).toBe("comment-1");
    const secondCall = fetchMock.mock.calls[1];
    expect((secondCall[0] as string)).toContain("limit=25");
  });

  it("lists history entries", async () => {
    const now = new Date().toISOString();
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ([
        {
          id: "hist-1",
          task_id: "task-1",
          changed_by: "user",
          change_type: "status_change",
          field_name: "status",
          old_value: { status: "pending" },
          new_value: { status: "resolved" },
          created_at: now,
          metadata: { notes: "text" },
        },
      ]),
    });

    const client = new AgentsClient(new HttpClient({ baseUrl: "https://api.example.com" }));
    const history = await client.listReviewTaskHistory("task-1");

    expect(history).toHaveLength(1);
    expect(history[0].historyId).toBe("hist-1");
    expect(history[0].oldValue?.status).toBe("pending");
  });

  it("fetches SLA summary", async () => {
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ({
        total_pending: 10,
        breached: 2,
        at_risk: 3,
        on_track: 5,
        compliance_rate: 50.0,
      }),
    });

    const client = new AgentsClient(new HttpClient({ baseUrl: "https://api.example.com" }));
    const summary = await client.getReviewTaskSlaSummary();

    expect(summary.totalPending).toBe(10);
    expect(summary.atRisk).toBe(3);
    expect(summary.complianceRate).toBe(50);
  });

  it("lists SLA breached tasks", async () => {
    const now = new Date().toISOString();
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ([
        {
          task_id: "task-1",
          sla_hours: 8,
          elapsed_hours: 9.5,
          remaining_hours: -1.5,
          percentage_elapsed: 1.2,
          is_breached: true,
          is_at_risk: false,
          created_at: now,
          due_at: now,
        },
      ]),
    });

    const client = new AgentsClient(new HttpClient({ baseUrl: "https://api.example.com" }));
    const breached = await client.listReviewTasksSlaBreached();

    expect(breached).toHaveLength(1);
    expect(breached[0].isBreached).toBe(true);
    expect(breached[0].percentageElapsed).toBe(1.2);
  });

  it("lists SLA at-risk tasks", async () => {
    const now = new Date().toISOString();
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ([
        {
          task_id: "task-2",
          sla_hours: 8,
          elapsed_hours: 6,
          remaining_hours: 2,
          percentage_elapsed: 0.75,
          is_breached: false,
          is_at_risk: true,
          created_at: now,
          due_at: now,
        },
      ]),
    });

    const client = new AgentsClient(new HttpClient({ baseUrl: "https://api.example.com" }));
    const atRisk = await client.listReviewTasksSlaAtRisk();

    expect(atRisk).toHaveLength(1);
    expect(atRisk[0].isAtRisk).toBe(true);
    expect(atRisk[0].taskId).toBe("task-2");
  });

  it("lists review notifications", async () => {
    const now = new Date().toISOString();
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ([
        {
          id: "notif-1",
          task_id: "task-1",
          org_id: "org-1",
          channel: "slack",
          status: "delivered",
          payload: { channel: "#alerts" },
          created_at: now,
          delivered_at: now,
        },
      ]),
    });

    const client = new AgentsClient(new HttpClient({ baseUrl: "https://api.example.com" }));
    const notifications = await client.listReviewNotifications({ status: "delivered", limit: 10 });

    expect(notifications).toHaveLength(1);
    expect(notifications[0].channel).toBe("slack");
    const [url] = fetchMock.mock.calls[0];
    expect(url).toContain("status=delivered");
    expect(url).toContain("limit=10");
  });

  it("lists agent sessions with pagination", async () => {
    const now = new Date().toISOString();
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ({
        limit: 25,
        offset: 0,
        total: 1,
        sessions: [
          {
            session_id: "session-1",
            org_id: "org-1",
            agent_type: "security_analyst",
            status: "active",
            title: "Investigation",
            created_by: "user",
            created_at: now,
            context: { finding_ids: ["finding-1"] },
          },
        ],
      }),
    });

    const client = new AgentsClient(new HttpClient({ baseUrl: "https://api.example.com" }));
    const sessions = await client.listSessions({ agentType: "security_analyst", limit: 25, offset: 0 });

    expect(sessions.sessions).toHaveLength(1);
    expect(sessions.sessions[0].agentType).toBe("security_analyst");
    expect(sessions.sessions[0].createdAt).toBeInstanceOf(Date);
    const [url] = fetchMock.mock.calls[0];
    expect(url).toContain("agent_type=security_analyst");
    expect(url).toContain("limit=25");
  });

  it("creates an agent session", async () => {
    const now = new Date().toISOString();
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 201,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ({
        session_id: "session-2",
        org_id: "org-1",
        agent_type: "incident_responder",
        status: "active",
        title: "Incident",
        created_by: "user",
        created_at: now,
        context: { incident_id: "inc-1" },
      }),
    });

    const client = new AgentsClient(new HttpClient({ baseUrl: "https://api.example.com" }));
    const session = await client.createSession({
      agentType: "incident_responder",
      context: { incident_id: "inc-1" },
      title: "Incident",
    });

    expect(session.sessionId).toBe("session-2");
    const [, init] = fetchMock.mock.calls[0];
    expect(JSON.parse((init as RequestInit).body as string)).toEqual({
      agent_type: "incident_responder",
      context: { incident_id: "inc-1" },
      title: "Incident",
    });
  });

  it("gets an agent session with messages", async () => {
    const now = new Date().toISOString();
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ({
        session: {
          session_id: "session-1",
          org_id: "org-1",
          agent_type: "security_analyst",
          status: "active",
          title: "Investigation",
          created_by: "user",
          created_at: now,
          context: {},
        },
        message_count: 1,
        messages: [
          {
            message_id: "msg-1",
            role: "user",
            content: "hello",
            timestamp: now,
            metadata: null,
          },
        ],
        metrics: { tokens: 42 },
        tool_invocations: [
          {
            id: "tool-1",
            tool_name: "ticket",
            status: "success",
            started_at: now,
            completed_at: now,
            error_message: null,
          },
        ],
      }),
    });

    const client = new AgentsClient(new HttpClient({ baseUrl: "https://api.example.com" }));
    const detail = await client.getSession("session-1", { messageLimit: 10 });

    expect(detail.messageCount).toBe(1);
    expect(detail.messages[0].createdAt).toBeInstanceOf(Date);
    expect(detail.toolInvocations[0].toolName).toBe("ticket");
    const [url] = fetchMock.mock.calls[0];
    expect(url).toContain("message_limit=10");
  });

  it("lists session messages", async () => {
    const now = new Date().toISOString();
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ([
        {
          message_id: "msg-1",
          role: "assistant",
          content: "response",
          timestamp: now,
          metadata: { source: "agent" },
        },
      ]),
    });

    const client = new AgentsClient(new HttpClient({ baseUrl: "https://api.example.com" }));
    const messages = await client.listSessionMessages("session-1", { limit: 20, offset: 0 });

    expect(messages).toHaveLength(1);
    expect(messages[0].metadata).toEqual({ source: "agent" });
    const [url] = fetchMock.mock.calls[0];
    expect(url).toContain("limit=20");
    expect(url).toContain("offset=0");
  });

  it("sends a session message without streaming override", async () => {
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ({}),
    });

    const client = new AgentsClient(new HttpClient({ baseUrl: "https://api.example.com" }));
    await client.sendSessionMessage("session-1", { message: "hello" });

    const [, init] = fetchMock.mock.calls[0];
    expect(JSON.parse((init as RequestInit).body as string)).toEqual({ message: "hello" });
  });

  it("lists session memory entries", async () => {
    const now = new Date().toISOString();
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ([
        {
          id: "mem-1",
          summary: "summary",
          role: "system",
          decay_score: 0.9,
          token_count: 120,
          created_at: now,
          last_accessed_at: now,
          scopes: [{ type: "org", value: "org-1" }],
          scope_labels: ["org:org-1"],
          metadata: { highlighted: true },
          content: "full content",
          ann_selected: true,
          lexical_similarity: 0.8,
          embedding_similarity: 0.85,
          combined_similarity: 0.82,
        },
      ]),
    });

    const client = new AgentsClient(new HttpClient({ baseUrl: "https://api.example.com" }));
    const memories = await client.listSessionMemoryEntries("session-1", { includeContent: true, limit: 5 });

    expect(memories).toHaveLength(1);
    expect(memories[0].content).toBe("full content");
    expect(memories[0].annSelected).toBe(true);
    const [url] = fetchMock.mock.calls[0];
    expect(url).toContain("include_content=true");
    expect(url).toContain("limit=5");
  });

  it("fetches session memory stats", async () => {
    const now = new Date().toISOString();
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ({
        total_entries: 10,
        recent_entries: 3,
        presented_entries: 2,
        average_decay: 0.75,
        token_total: 4096,
        role_distribution: { system: 5 },
        scope_distribution: { incident: 2 },
        top_memories: [
          {
            id: "mem-1",
            summary: "summary",
            role: "system",
            decay_score: 0.9,
            last_accessed_at: now,
            scope_labels: ["incident:inc-1"],
          },
        ],
      }),
    });

    const client = new AgentsClient(new HttpClient({ baseUrl: "https://api.example.com" }));
    const stats = await client.getSessionMemoryStats("session-1");

    expect(stats.totalEntries).toBe(10);
    expect(stats.topMemories[0].lastAccessedAt).toBeInstanceOf(Date);
  });

  it("lists session analytics events", async () => {
    const now = new Date().toISOString();
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ([
        {
          id: "event-1",
          event_type: "tool_invocation",
          payload: { tool: "ticket" },
          created_at: now,
        },
      ]),
    });

    const client = new AgentsClient(new HttpClient({ baseUrl: "https://api.example.com" }));
    const events = await client.listSessionAnalytics("session-1", {
      eventType: "tool_invocation",
      cursor: now,
      cursorId: "event-0",
      limit: 25,
    });

    expect(events).toHaveLength(1);
    expect(events[0].eventType).toBe("tool_invocation");
    const [url] = fetchMock.mock.calls[0];
    expect(url).toContain("event_type=tool_invocation");
    expect(url).toContain(`cursor=${encodeURIComponent(now)}`);
    expect(url).toContain("cursor_id=event-0");
    expect(url).toContain("limit=25");
  });

  it("summarises session analytics", async () => {
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ([
        {
          event_type: "tool_invocation",
          event_count: 5,
          first_seen: "2024-01-01T00:00:00Z",
          last_seen: "2024-01-01T01:00:00Z",
        },
      ]),
    });

    const client = new AgentsClient(new HttpClient({ baseUrl: "https://api.example.com" }));
    const summary = await client.getSessionAnalyticsSummary("session-1", { eventType: "tool_invocation" });

    expect(summary).toHaveLength(1);
    expect(summary[0].eventCount).toBe(5);
    const [url] = fetchMock.mock.calls[0];
    expect(url).toContain("event_type=tool_invocation");
  });

  it("lists workflow templates", async () => {
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ([
        {
          id: "template-1",
          name: "Template",
          description: "Desc",
          trigger: "on_create",
          conditions: {},
          steps: [
            {
              name: "Step",
              description: "Do",
              action: "assign",
              conditions: {},
              parameters: { assigned_to: "user" },
              order: 1,
            },
          ],
          metadata: { category: "automation" },
        },
      ]),
    });

    const client = new AgentsClient(new HttpClient({ baseUrl: "https://api.example.com" }));
    const templates = await client.listWorkflowTemplates({ trigger: "on_create" });

    expect(templates).toHaveLength(1);
    expect(templates[0].steps[0].action).toBe("assign");
    const [url] = fetchMock.mock.calls[0];
    expect(url).toContain("trigger=on_create");
  });

  it("fetches a workflow template", async () => {
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ({
        id: "template-1",
        name: "Template",
        description: "Desc",
        trigger: "on_create",
        conditions: {},
        steps: [],
        metadata: {},
      }),
    });

    const client = new AgentsClient(new HttpClient({ baseUrl: "https://api.example.com" }));
    const template = await client.getWorkflowTemplate("template-1");

    expect(template.templateId).toBe("template-1");
  });

  it("evaluates workflows", async () => {
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ([
        {
          id: "template-1",
          name: "Template",
          description: "Desc",
          trigger: "on_create",
          conditions: {},
          steps: [],
          metadata: {},
        },
      ]),
    });

    const client = new AgentsClient(new HttpClient({ baseUrl: "https://api.example.com" }));
    const templates = await client.evaluateWorkflows({ trigger: "on_create", context: { priority: "high" } });

    expect(templates).toHaveLength(1);
    const [, init] = fetchMock.mock.calls[0];
    expect(JSON.parse((init as RequestInit).body as string)).toEqual({ trigger: "on_create", context: { priority: "high" } });
  });

  it("lists policy suggestions", async () => {
    const now = new Date().toISOString();
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ([
        {
          id: "suggestion-1",
          tool_name: "ticket",
          cel_expression: "input.priority == 'high'",
          support_count: 5,
          reject_count: 1,
          confidence: 0.8,
          metadata: { scope: "security" },
          last_seen: now,
        },
      ]),
    });

    const client = new AgentsClient(new HttpClient({ baseUrl: "https://api.example.com" }));
    const suggestions = await client.listPolicySuggestions({ limit: 5 });

    expect(suggestions).toHaveLength(1);
    expect(suggestions[0].celExpression).toContain("priority");
    const [url] = fetchMock.mock.calls[0];
    expect(url).toContain("limit=5");
  });

  it("simulates policy expressions", async () => {
    const now = new Date().toISOString();
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ({
        evaluated_count: 3,
        matched_count: 2,
        mismatched_count: 1,
        error_count: 0,
        examples: [
          {
            invocation_id: "inv-1",
            session_id: "session-1",
            tool_name: "ticket",
            matched: true,
            status: "completed",
            started_at: now,
            completed_at: now,
            input_data: { priority: "high" },
            output_data: null,
            cel_context: { priority: "high" },
            error: null,
            latency_ms: 120,
          },
        ],
      }),
    });

    const client = new AgentsClient(new HttpClient({ baseUrl: "https://api.example.com" }));
    const result = await client.simulatePolicyExpression({ expression: "true", toolName: "ticket", limit: 3 });

    expect(result.evaluatedCount).toBe(3);
    expect(result.examples[0].matched).toBe(true);
    const [, init] = fetchMock.mock.calls[0];
    expect(JSON.parse((init as RequestInit).body as string)).toEqual({ expression: "true", tool_name: "ticket", limit: 3 });
  });
});
