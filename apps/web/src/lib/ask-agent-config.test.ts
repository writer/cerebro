import { describe, expect, it } from "vitest";

import { askAgentRuntimeConfig } from "./ask-agent-config";

describe("ask agent runtime config", () => {
  it("reports readiness when model access and graph tools are present", () => {
    expect(askAgentRuntimeConfig({
      OPENAI_API_KEY: "present",
      CEREBRO_MCP_URL: "https://api.example.com/mcp",
    })).toMatchObject({
      canRunAgent: true,
      mcpUrl: "https://api.example.com/mcp",
      openAIConfigured: true,
    });
  });

  it("derives the graph tool URL from the API base", () => {
    expect(askAgentRuntimeConfig({
      OPENAI_API_KEY: "present",
      CEREBRO_API_BASE: "https://api.example.com",
    })).toMatchObject({
      canRunAgent: true,
      mcpUrl: "https://api.example.com/api/v1/mcp",
    });
  });

  it("keeps unavailable config as booleans and sanitized URLs", () => {
    expect(askAgentRuntimeConfig({
      CEREBRO_API_BASE: "not a url",
    })).toEqual({
      canRunAgent: false,
      mcpUrl: "",
      mcpToken: "",
      modelOverride: "",
      openAIConfigured: false,
    });
  });

  it("normalizes the model override and MCP credential without exposing env access elsewhere", () => {
    expect(askAgentRuntimeConfig({
      OPENAI_API_KEY: "present",
      CEREBRO_MCP_URL: "https://api.example.com/mcp",
      CEREBRO_AGENT_MODEL: " gpt-5.6-sol ",
      CEREBRO_MCP_TOKEN: " token ",
    })).toMatchObject({
      modelOverride: "gpt-5.6-sol",
      mcpToken: "token",
    });
  });
});
