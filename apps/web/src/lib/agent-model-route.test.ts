import { describe, expect, it } from "vitest";

import { AGENT_TOOL_PACKS, selectAgentModelRoute } from "./agent-model-route";

describe("agent model routing", () => {
  it("uses Luna for a direct lookup with a short turn budget", () => {
    const route = selectAgentModelRoute({ question: "Who owns this asset?" });
    expect(route).toMatchObject({
      profile: "fast",
      model: "gpt-5.6-luna",
      maxTurns: 3,
      imageDetail: "low",
    });
    expect(route.modelSettings.reasoning?.effort).toBe("minimal");
  });

  it("uses Sol when the operator requests a deep investigation", () => {
    const route = selectAgentModelRoute({
      question: "Trace the impact",
      mode: "deep",
      context: { route: "/findings/f-1", findingId: "f-1" },
    });
    expect(route).toMatchObject({
      profile: "deep",
      model: "gpt-5.6-sol",
      maxTurns: 8,
      toolPack: "finding",
    });
    expect(route.modelSettings.reasoning?.effort).toBe("high");
    expect(AGENT_TOOL_PACKS[route.toolPack]).toContain("cerebro.investigation.context");
  });

  it("uses Terra and the source tools for a standard source question", () => {
    const route = selectAgentModelRoute({
      question: "Explain why this source is stale",
      context: { route: "/sources/github" },
    });
    expect(route).toMatchObject({
      profile: "balanced",
      model: "gpt-5.6-terra",
      toolPack: "source",
    });
  });

  it("preserves a configured model override while retaining the route budgets", () => {
    const route = selectAgentModelRoute(
      { question: "Who owns this asset?" },
      "gpt-5.6-sol",
    );
    expect(route.model).toBe("gpt-5.6-sol");
    expect(route.profile).toBe("fast");
    expect(route.selectionReason).toContain("configured_model");
  });
});
