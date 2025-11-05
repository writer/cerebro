import { beforeEach, describe, expect, it, vi } from "vitest";

import { AgentsClient } from "../../src/clients/agents";
import HttpClient from "../../src/httpClient";
import type { components } from "../../src/generated/openapi";

const fetchMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
});

describe("AgentsClient contract", () => {
  it("maps review tasks returned from the OpenAPI schema", async () => {
    const task: components["schemas"]["ReviewTaskResponse"] = {
      id: "task-1",
      session_id: "session-1",
      org_id: "org-1",
      status: "pending",
      title: "Review",
      summary: "Check this",
      payload: { foo: "bar" },
      promotion_target: null,
      priority: "high",
      due_at: new Date().toISOString(),
      escalated_to: null,
      notification_channel: "slack",
      ticket_reference: null,
      created_by: "user",
      created_at: new Date().toISOString(),
      resolved_by: null,
      resolved_at: null,
      resolution_notes: null,
    };

    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => [task],
    });

    const client = new AgentsClient(new HttpClient({ baseUrl: "https://api.example.com", fetch: fetchMock }));
    const tasks = await client.listReviewTasks();

    expect(tasks).toHaveLength(1);
    expect(tasks[0].taskId).toBe("task-1");
    expect(tasks[0].payload).toEqual({ foo: "bar" });
    expect(tasks[0].createdAt).toBeInstanceOf(Date);
  });
});
