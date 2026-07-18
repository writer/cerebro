import type { ParsedEnv } from "./env.js";
import { csv } from "./parsing.js";
import type { ActorMapping, AppConfig } from "./types.js";

export function buildCerebroConfig(parsed: ParsedEnv): AppConfig["cerebro"] {
  return {
    baseUrl: parsed.CEREBRO_BASE_URL.replace(/\/$/, ""),
    tenantId: parsed.CEREBRO_TENANT_ID,
    requestTimeoutMs: parsed.CEREBRO_REQUEST_TIMEOUT_MS,
    webBaseUrl: parsed.CEREBRO_WEB_BASE_URL?.replace(/\/$/, ""),
    defaultRuntimeIds: csv(parsed.CEREBRO_DEFAULT_RUNTIME_IDS),
    companionRuntimeId: parsed.CEREBRO_COMPANION_RUNTIME_ID,
    assistantHelpMention: parsed.CEREBRO_ASSISTANT_HELP_MENTION,
    apiKeys: {
      read: parsed.CEREBRO_READ_API_KEY,
      findings: parsed.CEREBRO_FINDINGS_API_KEY,
      source: parsed.CEREBRO_SOURCE_API_KEY,
      runtimeResponse: parsed.CEREBRO_RUNTIME_RESPONSE_API_KEY,
      graphActions: parsed.CEREBRO_GRAPH_ACTION_API_KEY,
    },
    slackUsers: parseSlackUserMap(parsed.CEREBRO_SLACK_USER_MAP_JSON),
  };
}

function parseSlackUserMap(raw: string | undefined): Map<string, ActorMapping> {
  if (!raw?.trim()) {
    return new Map();
  }
  const decoded = JSON.parse(raw) as Record<string, { actor_id?: string; actorId?: string; display_name?: string; displayName?: string }>;
  const entries = Object.entries(decoded).flatMap(([slackUserId, value]) => {
    const actorId = value.actor_id ?? value.actorId ?? "";
    if (!actorId.trim()) {
      return [];
    }
    return [[slackUserId, { actorId: actorId.trim(), displayName: value.display_name ?? value.displayName } satisfies ActorMapping] as const];
  });
  return new Map(entries);
}
