import { z } from "zod";

const askAgentEnvSchema = z.object({
  CEREBRO_API_BASE: z.string().optional(),
  CEREBRO_MCP_URL: z.string().optional(),
  OPENAI_API_KEY: z.string().optional(),
});

export type AskAgentRuntimeConfig = {
  canRunAgent: boolean;
  mcpUrl: string;
  openAIConfigured: boolean;
};

const trimmed = (value: string | undefined) => value?.trim() ?? "";

export const askAgentRuntimeConfig = (env: NodeJS.ProcessEnv = process.env): AskAgentRuntimeConfig => {
  const parsed = askAgentEnvSchema.parse(env);
  const configuredMcpUrl = trimmed(parsed.CEREBRO_MCP_URL);
  const apiBase = trimmed(parsed.CEREBRO_API_BASE);
  const mcpUrl = configuredMcpUrl || mcpUrlFromApiBase(apiBase);
  const openAIConfigured = Boolean(trimmed(parsed.OPENAI_API_KEY));
  return {
    canRunAgent: Boolean(openAIConfigured && mcpUrl),
    mcpUrl,
    openAIConfigured,
  };
};

const mcpUrlFromApiBase = (apiBase: string) => {
  if (!apiBase) return "";
  try {
    return new URL("/mcp", apiBase).toString();
  } catch {
    return "";
  }
};
