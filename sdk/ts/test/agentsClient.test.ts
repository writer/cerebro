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
});
