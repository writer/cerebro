import { describe, expect, it, vi } from "vitest";

import {
  askEmptyState,
  defaultAskModel,
  normalizeAskModel,
  parseAskEventBlock,
  reduceAskEvent,
  streamAgentAsk,
  streamAsk,
} from "./ask";

const streamFromText = (text: string) =>
  new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new TextEncoder().encode(text));
      controller.close();
    },
  });

describe("Ask stream contract", () => {
  it("parses CRLF-framed SSE blocks", () => {
    const event = parseAskEventBlock('event: done\r\ndata: {"trace_id":"trace-1","total_ms":42,"cypher_refused":false,"timings":{"mcp_connect_ms":4,"first_tool_ms":12},"tool_calls":2,"tool_results":2,"delta_count":7}');

    expect(event).toEqual({
      type: "done",
      data: {
        trace_id: "trace-1",
        total_ms: 42,
        cypher_refused: false,
        timings: { mcp_connect_ms: 4, first_tool_ms: 12 },
        tool_calls: 2,
        tool_results: 2,
        delta_count: 7,
      },
    });
  });

  it("preserves multiline data payloads", () => {
    const event = parseAskEventBlock('event: summary\ndata: {"markdown":"line 1\\nline 2","citations":[]}');

    expect(event?.type).toBe("summary");
    if (event?.type === "summary") {
      expect(event.data.markdown).toBe("line 1\nline 2");
    }
  });

  it("tracks unknown stream events for trace debugging", () => {
    const event = parseAskEventBlock('event: token_usage\ndata: {"input":100,"output":20}');

    expect(event).toEqual({
      type: "unknown",
      data: { event: "token_usage", payload: { input: 100, output: 20 } },
    });
  });

  it("parses agent progress events", () => {
    const status = parseAskEventBlock(
      'event: agent_status\ndata: {"stage":"connect","label":"Connecting to graph tools","mode":"agent"}',
    );
    const tool = parseAskEventBlock(
      'event: agent_tool\ndata: {"name":"cerebro.findings.search","status":"completed","detail":"Result received"}',
    );
    const delta = parseAskEventBlock('event: agent_delta\ndata: {"text":"hello"}');

    expect(status).toEqual({
      type: "agent_status",
      data: { stage: "connect", label: "Connecting to graph tools", mode: "agent" },
    });
    expect(tool).toEqual({
      type: "agent_tool",
      data: { name: "cerebro.findings.search", status: "completed", detail: "Result received" },
    });
    expect(delta).toEqual({ type: "agent_delta", data: { text: "hello" } });
  });

  it("parses query plan diagnostics as a first-class stream event", () => {
    const event = parseAskEventBlock(
      'event: query_plan\ndata: {"plan":{"intent":"aggregate_findings_by_source","limit":10},"source":"deterministic_template","deterministic":true,"corrected":true,"diagnostics":[{"level":"warn","code":"relation_alias_canonicalized","message":"fixed"}]}',
    );

    expect(event).toEqual({
      type: "query_plan",
      data: {
        plan: { intent: "aggregate_findings_by_source", limit: 10 },
        source: "deterministic_template",
        deterministic: true,
        corrected: true,
        diagnostics: [{ level: "warn", code: "relation_alias_canonicalized", message: "fixed" }],
      },
    });
  });

  it("normalizes unsupported model IDs to the default", () => {
    expect(normalizeAskModel("not-a-real-model")).toBe(defaultAskModel);
    expect(normalizeAskModel("claude-opus-4-7")).toBe("claude-opus-4-7");
  });

  it("emits a retryable error when the stream ends without a terminal event", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(streamFromText('event: rationale\ndata: {"text":"checking"}\n\n'), {
        status: 200,
        headers: { "content-type": "text/event-stream" },
      }),
    );

    const events = [];
    for await (const event of streamAsk({ tenant_id: "writer", question: "q" }, "")) {
      events.push(event);
    }

    expect(events.at(-1)).toEqual({
      type: "error",
      data: {
        code: "stream_incomplete",
        message: "The response stream ended before completion.",
        retryable: true,
      },
    });
    fetchMock.mockRestore();
  });

  it("posts panel requests to the agent route", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(streamFromText('event: done\ndata: {"trace_id":"trace-1","total_ms":1,"cypher_refused":false}\n\n'), {
        status: 200,
        headers: { "content-type": "text/event-stream" },
      }),
    );

    const events = [];
    for await (const event of streamAgentAsk({ tenant_id: "writer", question: "q" }, "")) {
      events.push(event);
    }

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/agent/ask",
      expect.objectContaining({ method: "POST" }),
    );
    expect(events.at(-1)?.type).toBe("done");
    fetchMock.mockRestore();
  });

  it("keeps reducer status terminal after done and error events", () => {
    const turn = askEmptyState({ question: "q" });
    const completed = reduceAskEvent(turn, {
      type: "done",
      data: { trace_id: "trace-1", total_ms: 10, cypher_refused: false },
    });
    expect(completed.status).toBe("completed");

    const failed = reduceAskEvent(turn, {
      type: "error",
      data: { code: "http_504", message: "timeout", retryable: true },
    });
    expect(failed.status).toBe("error");
    expect(failed.error?.retryable).toBe(true);
  });

  it("stores query plan diagnostics on the active turn", () => {
    const turn = reduceAskEvent(askEmptyState({ question: "q" }), {
      type: "query_plan",
      data: {
        plan: { intent: "top_risk_findings" },
        source: "deterministic_template",
        deterministic: true,
        corrected: false,
      },
    });

    expect(turn.queryPlan?.plan.intent).toBe("top_risk_findings");
    expect(turn.queryPlan?.deterministic).toBe(true);
  });

  it("stores agent timeline and streaming draft text", () => {
    const withStatus = reduceAskEvent(askEmptyState({ question: "q" }), {
      type: "agent_status",
      data: { stage: "connect", label: "Connecting", mode: "agent" },
    });
    const withText = reduceAskEvent(withStatus, {
      type: "agent_delta",
      data: { text: "First sentence." },
    });

    expect(withText.agentMode).toBe("agent");
    expect(withText.agentEvents?.[0]).toMatchObject({ type: "status", stage: "connect" });
    expect(withText.agentAnswerDraft).toBe("First sentence.");
  });
});
