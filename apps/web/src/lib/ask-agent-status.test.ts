import { describe, expect, it } from "vitest";

import { ASK_AGENT_FALLBACK_STATUS, ASK_AGENT_READY_STATUS, askAgentReadiness } from "./ask-agent-status";

describe("ask agent status copy", () => {
  it("keeps fallback status user-facing and configuration-free", () => {
    const text = JSON.stringify(ASK_AGENT_FALLBACK_STATUS);

    expect(ASK_AGENT_FALLBACK_STATUS).toMatchObject({
      stage: "fallback",
      label: "Using Graph Ask",
      detail: "Graph Ask is handling this request.",
      mode: "legacy",
    });
    expect(text).not.toMatch(/env|token|credential|not configured/i);
  });

  it("reports Ask readiness without exposing deployment configuration", () => {
    expect(askAgentReadiness({ canRunAgent: true })).toEqual(ASK_AGENT_READY_STATUS);
    expect(askAgentReadiness({ canRunAgent: false })).toMatchObject({
      label: "Using Graph Ask",
      mode: "legacy",
    });

    const text = JSON.stringify([
      askAgentReadiness({ canRunAgent: true }),
      askAgentReadiness({ canRunAgent: false }),
    ]);
    expect(text).not.toMatch(/env|token|credential|secret|openai|mcp|not configured/i);
  });
});
