import assert from "node:assert/strict";
import test from "node:test";
import {
  createPantherMcpTools,
  pantherMcpAgentToolName,
  type PantherMcpRuntimeClient,
  type PantherMcpServerTool,
} from "../src/agent/tools/panther-mcp-tools.js";
import { testConfig } from "./fixtures.js";

test("Panther MCP tools expose configured read tools and skip mutating names by default", () => {
  const config = testConfig({
    pantherMcp: {
      enabled: true,
      url: "https://panther-mcp.example.com/mcp",
      allowedTools: new Set(["list_alerts", "delete_alert"]),
      allowMutatingTools: false,
    },
  });
  const tools = createPantherMcpTools({ config, cerebro: undefined as never, memory: undefined as never }, fakePantherClient());

  assert.deepEqual(tools.map((tool) => tool.name), [
    "panther_mcp_status",
    pantherMcpAgentToolName("list_alerts"),
  ]);
});

test("Panther MCP status lists server tools without exposing auth values", async () => {
  const client = fakePantherClient({
    serverTools: [{
      name: "list_alerts",
      description: "List Panther alerts.",
      annotations: { readOnlyHint: true },
    }],
  });
  const config = testConfig({
    pantherMcp: {
      enabled: true,
      url: "https://panther-mcp.example.com/mcp",
      authToken: "secret-token",
      allowedTools: new Set(["list_alerts"]),
    },
  });
  const status = createPantherMcpTools({ config, cerebro: undefined as never, memory: undefined as never }, client)
    .find((tool) => tool.name === "panther_mcp_status");
  assert.ok(status);

  const result = await status.execute("call-1", { check_connection: true } as never);
  const details = result.details as any;

  assert.equal(client.listToolsCalls, 1);
  assert.equal(details.auth_configured, true);
  assert.equal(JSON.stringify(details).includes("secret-token"), false);
  assert.deepEqual(details.server_tools, [{
    name: "list_alerts",
    description: "List Panther alerts.",
    read_only: true,
    allowed: true,
  }]);
});

test("Panther MCP tool forwards JSON arguments to the configured MCP tool", async () => {
  const client = fakePantherClient({
    callResult: {
      content: [{ type: "text", text: "2 alerts" }],
      structuredContent: { count: 2 },
      isError: false,
    },
  });
  const config = testConfig({
    pantherMcp: {
      enabled: true,
      url: "https://panther-mcp.example.com/mcp",
      allowedTools: new Set(["list_alerts"]),
    },
  });
  const tool = createPantherMcpTools({ config, cerebro: undefined as never, memory: undefined as never }, client)
    .find((candidate) => candidate.name === pantherMcpAgentToolName("list_alerts"));
  assert.ok(tool);

  const result = await tool.execute("call-1", { arguments: { severity: "HIGH" } } as never);
  const details = result.details as any;

  assert.deepEqual(client.calls, [{
    toolName: "list_alerts",
    args: { severity: "HIGH" },
  }]);
  assert.deepEqual(details.result.structured_content, { count: 2 });
});

function fakePantherClient(options: {
  serverTools?: PantherMcpServerTool[];
  callResult?: unknown;
} = {}): PantherMcpRuntimeClient & {
  calls: Array<{ toolName: string; args: Record<string, unknown> }>;
  listToolsCalls: number;
} {
  return {
    calls: [],
    listToolsCalls: 0,
    async listTools() {
      this.listToolsCalls += 1;
      return options.serverTools ?? [];
    },
    async callTool(toolName, args) {
      this.calls.push({ toolName, args });
      return options.callResult ?? {
        content: [{ type: "text", text: "ok" }],
        isError: false,
      };
    },
  };
}
