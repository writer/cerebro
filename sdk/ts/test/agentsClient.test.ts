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
});
