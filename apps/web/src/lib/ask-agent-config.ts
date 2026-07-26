import { z } from "zod";

const askAgentEnvSchema = z.object({
  CEREBRO_API_BASE: z.string().optional(),
  CEREBRO_AGENT_MODEL: z.string().optional(),
  CEREBRO_MCP_BEARER_TOKEN: z.string().optional(),
  CEREBRO_MCP_TOKEN: z.string().optional(),
  CEREBRO_MCP_URL: z.string().optional(),
  OPENAI_API_KEY: z.string().optional(),
});

export type AskAgentRuntimeConfig = {
  canRunAgent: boolean;
  mcpUrl: string;
  mcpToken: string;
  modelOverride: string;
  openAIConfigured: boolean;
};

const trimmed = (value: string | undefined) => value?.trim() ?? "";

export const askAgentRuntimeConfig = (
  env: Record<string, string | undefined> = process.env,
): AskAgentRuntimeConfig => {
  const parsed = askAgentEnvSchema.parse(env);
  const configuredMcpUrl = trimmed(parsed.CEREBRO_MCP_URL);
  const apiBase = trimmed(parsed.CEREBRO_API_BASE);
  const mcpUrl = configuredMcpUrl || mcpUrlFromApiBase(apiBase);
  const openAIConfigured = Boolean(trimmed(parsed.OPENAI_API_KEY));
  return {
    canRunAgent: Boolean(openAIConfigured && mcpUrl),
    mcpUrl,
    mcpToken: trimmed(parsed.CEREBRO_MCP_BEARER_TOKEN) || trimmed(parsed.CEREBRO_MCP_TOKEN),
    modelOverride: trimmed(parsed.CEREBRO_AGENT_MODEL),
    openAIConfigured,
  };
};

export const mcpUrlFromApiBase = (apiBase: string) => {
  if (!apiBase) return "";
  try {
    return new URL("/api/v1/mcp", apiBase).toString();
  } catch {
    return "";
  }
};
