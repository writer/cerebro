#!/usr/bin/env node

import { createRequire } from "node:module";
import path from "node:path";
import { pathToFileURL } from "node:url";

const endpoint = process.env.CEREBRO_MCP_URL;
const token = process.env.CEREBRO_MCP_BEARER_TOKEN;
const sdkRoot = process.env.CEREBRO_MCP_SDK_ROOT || path.join(process.cwd(), "tmp", "mcp-sdk-compat");

if (!endpoint) {
  console.error("mcp_sdk_compat: CEREBRO_MCP_URL is required");
  process.exit(2);
}
if (!token) {
  console.error("mcp_sdk_compat: CEREBRO_MCP_BEARER_TOKEN is required");
  process.exit(2);
}

const requireFromSdkRoot = createRequire(path.join(sdkRoot, "package.json"));
const clientModule = await import(pathToFileURL(requireFromSdkRoot.resolve("@modelcontextprotocol/sdk/client/index.js")).href);
const transportModule = await import(pathToFileURL(requireFromSdkRoot.resolve("@modelcontextprotocol/sdk/client/streamableHttp.js")).href);

const { Client } = clientModule;
const { StreamableHTTPClientTransport } = transportModule;

const client = new Client({ name: "cerebro-mcp-sdk-compat", version: "0" });
const transport = new StreamableHTTPClientTransport(new URL(endpoint), {
  requestInit: {
    headers: {
      Authorization: `Bearer ${token}`,
      "X-Cerebro-MCP-Toolsets": "full",
    },
  },
});

try {
  await client.connect(transport);
  const tools = await client.listTools();
  const toolNames = new Set((tools.tools || []).map((tool) => tool.name));
  if (!toolNames.has("cerebro.version")) {
    throw new Error("tools/list missing cerebro.version");
  }
  const result = await client.callTool({ name: "cerebro.version", arguments: {} });
  if (result?.isError) {
    throw new Error("cerebro.version returned isError");
  }
  console.log(`mcp_sdk_compat: SDK connected and listed ${toolNames.size} tools`);
} finally {
  await client.close();
}
