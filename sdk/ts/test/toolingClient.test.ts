import { beforeEach, describe, expect, it, vi } from "vitest";

import HttpClient from "../src/httpClient";
import { AgentsClient } from "../src/clients/agents";
import {
  AgentToolingClient,
  InMemoryToolingAdapter,
} from "../src/clients/tooling";

const fetchMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
  // @ts-expect-error test double
  globalThis.fetch = fetchMock;
});

describe("AgentToolingClient", () => {
  it("delegates policy suggestion lookups to AgentsClient", async () => {
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
          reject_count: 0,
          confidence: 0.9,
          metadata: {},
          last_seen: "2024-01-01T00:00:00Z",
        },
      ]),
    });

    const http = new HttpClient({ baseUrl: "https://api.example.com" });
    const agents = new AgentsClient(http);
    const tooling = new AgentToolingClient(agents, new InMemoryToolingAdapter());

    const suggestions = await tooling.listPolicySuggestions({ limit: 1 });
    expect(suggestions).toHaveLength(1);
    expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining("policy-suggestions"), expect.anything());
  });

  it("manages tool invocations via adapter", async () => {
    const http = new HttpClient({ baseUrl: "https://api.example.com" });
    const agents = new AgentsClient(http);
    const adapter = new InMemoryToolingAdapter();
    const tooling = new AgentToolingClient(agents, adapter);

    const created = await tooling.createInvocation({
      sessionId: "session-1",
      toolName: "pager",
      inputData: { message: "hello" },
    });

    expect(created.status).toBe("PENDING");

    const updated = await tooling.updateInvocationResult({
      invocationId: created.invocationId,
      status: "SUCCESS",
      outputData: { ok: true },
    });

    expect(updated.status).toBe("SUCCESS");

    const summary = await tooling.summarizeInvocations();
    expect(summary[0].count).toBeGreaterThan(0);
  });
});
