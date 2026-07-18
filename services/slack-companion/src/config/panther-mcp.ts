import type { ParsedEnv } from "./env.js";
import { csvSet, parseBoolean } from "./parsing.js";
import type { AppConfig } from "./types.js";

export const DEFAULT_PANTHER_MCP_ALLOWED_TOOLS = [
  "list_alerts",
  "get_alert",
  "get_alert_events",
  "query_data_lake",
  "get_table_schema",
  "list_databases",
  "list_database_tables",
  "list_detections",
  "get_detection",
  "get_permissions",
];

export function buildPantherMcpConfig(parsed: ParsedEnv): AppConfig["pantherMcp"] {
  const url = parsed.PANTHER_MCP_URL?.replace(/\/$/, "");
  return {
    enabled: parseBoolean(parsed.PANTHER_MCP_ENABLED),
    url,
    authToken: parsed.PANTHER_MCP_AUTH_TOKEN,
    allowedTools: csvSet(parsed.PANTHER_MCP_ALLOWED_TOOLS || DEFAULT_PANTHER_MCP_ALLOWED_TOOLS.join(",")),
    allowMutatingTools: parseBoolean(parsed.PANTHER_MCP_ALLOW_MUTATING_TOOLS),
    timeoutMs: parsed.PANTHER_MCP_TIMEOUT_MS,
  };
}
