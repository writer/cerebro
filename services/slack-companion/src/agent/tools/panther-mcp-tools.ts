import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";
import type { AgentTool } from "@earendil-works/pi-agent-core";
import { Type } from "@earendil-works/pi-ai";
import type { AppConfig } from "../../config/index.js";
import type { SecurityToolDeps } from "./types.js";
import { safeToolResult, toolResult } from "./tool-result.js";

export interface PantherMcpRuntimeClient {
  listTools(signal?: AbortSignal): Promise<PantherMcpServerTool[]>;
  callTool(toolName: string, args: Record<string, unknown>, signal?: AbortSignal): Promise<unknown>;
}

export interface PantherMcpServerTool {
  name: string;
  title?: string;
  description?: string;
  inputSchema?: unknown;
  annotations?: {
    readOnlyHint?: boolean;
    destructiveHint?: boolean;
  };
}

interface PantherMcpToolArgs {
  arguments?: Record<string, unknown>;
}

const PANTHER_TOOL_PREFIX = "panther_mcp_";
const MUTATING_TOOL_NAME = /\b(create|update|delete|disable|enable|resolve|comment|assign|snooze|archive|trigger|write|set|patch|put|post)\b/i;

export function createPantherMcpTools(deps: SecurityToolDeps, runtimeClient?: PantherMcpRuntimeClient): AgentTool[] {
  const config = deps.config.pantherMcp;
  const client = runtimeClient ?? new SdkPantherMcpClient(deps.config);
  const statusParams = Type.Object({
    check_connection: Type.Optional(Type.Boolean({ description: "Connect to the Panther MCP server and list available tools." })),
  });
  const callParams = Type.Object({
    arguments: Type.Optional(Type.Record(Type.String(), Type.Any(), {
      description: "JSON arguments for the Panther MCP tool.",
    })),
  });

  const tools: AgentTool[] = [{
    name: "panther_mcp_status",
    label: "Panther MCP status",
    description: "Check Panther MCP configuration and optionally list the server tools available through the configured MCP endpoint.",
    parameters: statusParams,
    execute: async (_toolCallId, params, signal) => safeToolResult(async () => {
      const args = params as { check_connection?: boolean };
      const base = {
        enabled: config.enabled,
        configured: Boolean(config.url),
        url_configured: Boolean(config.url),
        auth_configured: Boolean(config.authToken),
        allowed_tools: sortedAllowedTools(config),
        mutating_tools_allowed: config.allowMutatingTools,
      };
      if (!config.enabled) return { ...base, ready: false, reason: "Panther MCP is disabled." };
      if (!config.url) return { ...base, ready: false, reason: "PANTHER_MCP_URL is not configured." };
      if (!args.check_connection) return { ...base, ready: true };
      const serverTools = await client.listTools(signal);
      return {
        ...base,
        ready: true,
        connected: true,
        server_tools: serverTools.map((tool) => ({
          name: tool.name,
          title: tool.title,
          description: tool.description,
          read_only: tool.annotations?.readOnlyHint,
          destructive: tool.annotations?.destructiveHint,
          allowed: config.allowedTools.has(tool.name),
        })),
      };
    }),
  }];

  if (!config.enabled || !config.url) return tools;

  for (const toolName of sortedAllowedTools(config)) {
    if (isMutatingPantherTool(toolName) && !config.allowMutatingTools) continue;
    tools.push({
      name: pantherMcpAgentToolName(toolName),
      label: `Panther ${toolName}`,
      description: [
        `Call Panther MCP tool ${toolName}.`,
        "Use for read-only Panther investigations.",
        "Pass arguments as the JSON object expected by Panther MCP; use panther_mcp_status with check_connection=true to inspect available tools.",
      ].join(" "),
      parameters: callParams,
      executionMode: "sequential",
      execute: async (_toolCallId, params, signal) => {
        const args = params as PantherMcpToolArgs;
        const toolArgs = args.arguments ?? {};
        if (!isPlainRecord(toolArgs)) {
          return toolResult({ error: "invalid_arguments", message: "Panther MCP arguments must be a JSON object." });
        }
        if (!config.allowedTools.has(toolName)) {
          return toolResult({ error: "tool_not_allowed", tool: toolName });
        }
        if (isMutatingPantherTool(toolName) && !config.allowMutatingTools) {
          return toolResult({ error: "mutating_tool_blocked", tool: toolName });
        }
        return safeToolResult(async () => {
          const result = await client.callTool(toolName, toolArgs, signal);
          return {
            server: "panther_mcp",
            tool: toolName,
            result: normalizeMcpToolResult(result),
          };
        });
      },
    });
  }

  return tools;
}

export function pantherMcpAgentToolName(toolName: string): string {
  return `${PANTHER_TOOL_PREFIX}${toolName.replace(/[^a-zA-Z0-9_]/g, "_")}`;
}

export function isPantherMcpAgentToolName(toolName: string): boolean {
  return toolName.startsWith(PANTHER_TOOL_PREFIX);
}

function sortedAllowedTools(config: AppConfig["pantherMcp"]): string[] {
  return [...config.allowedTools].sort((left, right) => left.localeCompare(right));
}

function isMutatingPantherTool(toolName: string): boolean {
  return MUTATING_TOOL_NAME.test(toolName.replace(/[^a-zA-Z0-9]+/g, " "));
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function normalizeMcpToolResult(result: unknown): unknown {
  if (!isPlainRecord(result)) return result;
  const callResult = result as Partial<CallToolResult>;
  return {
    is_error: callResult.isError ?? false,
    content: callResult.content,
    structured_content: callResult.structuredContent,
    tool_result: (result as { toolResult?: unknown }).toolResult,
  };
}

class SdkPantherMcpClient implements PantherMcpRuntimeClient {
  constructor(private readonly config: AppConfig) {}

  async listTools(signal?: AbortSignal): Promise<PantherMcpServerTool[]> {
    return this.withClient(async (client) => {
      const result = await client.listTools(undefined, {
        signal,
        timeout: this.config.pantherMcp.timeoutMs,
      });
      return result.tools.map(normalizeServerTool);
    }, signal);
  }

  async callTool(toolName: string, args: Record<string, unknown>, signal?: AbortSignal): Promise<unknown> {
    return this.withClient((client) => client.callTool({
      name: toolName,
      arguments: args,
    }, undefined, {
      signal,
      timeout: this.config.pantherMcp.timeoutMs,
    }), signal);
  }

  private async withClient<T>(work: (client: Client) => Promise<T>, signal?: AbortSignal): Promise<T> {
    const url = this.config.pantherMcp.url;
    if (!this.config.pantherMcp.enabled) throw new Error("Panther MCP is disabled.");
    if (!url) throw new Error("PANTHER_MCP_URL is not configured.");
    const client = new Client({
      name: "cerebro-slack-companion",
      version: this.config.coordination.version || "local",
    });
    const headers: Record<string, string> = {};
    if (this.config.pantherMcp.authToken) headers.authorization = `Bearer ${this.config.pantherMcp.authToken}`;
    const transport = new StreamableHTTPClientTransport(new URL(url), {
      requestInit: Object.keys(headers).length > 0 ? { headers } : undefined,
    });
    await client.connect(transport, {
      signal,
      timeout: this.config.pantherMcp.timeoutMs,
    });
    try {
      return await work(client);
    } finally {
      await client.close().catch(() => undefined);
    }
  }
}

function normalizeServerTool(tool: Tool): PantherMcpServerTool {
  return {
    name: tool.name,
    title: tool.title,
    description: tool.description,
    inputSchema: tool.inputSchema,
    annotations: tool.annotations,
  };
}
