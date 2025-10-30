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
});
