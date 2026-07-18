import type { ParsedEnv } from "./env.js";
import { csvSet, parseBoolean } from "./parsing.js";
import type { AppConfig, AssistantBotHandoffPolicy, ProactiveSlackChannelPolicy } from "./types.js";

export function buildSlackConfig(parsed: ParsedEnv): AppConfig["slack"] {
  const socketMode = parseBoolean(parsed.SLACK_SOCKET_MODE);
  return {
    botToken: parsed.SLACK_BOT_TOKEN!,
    signingSecret: parsed.SLACK_SIGNING_SECRET,
    socketMode,
    appToken: parsed.SLACK_APP_TOKEN,
    defaultChannelId: parsed.SLACK_DEFAULT_CHANNEL_ID,
    allowedTeamIds: csvSet(parsed.SLACK_ALLOWED_TEAM_IDS),
    auditLogsToken: parsed.SLACK_AUDIT_LOGS_TOKEN,
    findingWriteUserIds: csvSet(parsed.SLACK_FINDING_WRITE_USER_IDS),
    sourceWriteUserIds: csvSet(parsed.SLACK_SOURCE_WRITE_USER_IDS),
    responseWriteUserIds: csvSet(parsed.SLACK_RESPONSE_WRITE_USER_IDS),
    graphActionUserIds: csvSet(parsed.SLACK_GRAPH_ACTION_USER_IDS),
    autonomyApprovalUserIds: csvSet(parsed.SLACK_AUTONOMY_APPROVAL_USER_IDS),
    operatorUserIds: csvSet(parsed.SLACK_OPERATOR_USER_IDS),
    triageChannelIds: csvSet(parsed.SLACK_TRIAGE_CHANNEL_IDS),
    riskAttestationChannelIds: csvSet(parsed.SLACK_RISK_ATTESTATION_CHANNEL_IDS ?? parsed.SLACK_TRIAGE_CHANNEL_IDS),
    riskAttestationTimeoutMs: parsed.SLACK_RISK_ATTESTATION_TIMEOUT_MS,
    triageChannelPolicies: channelPolicies(parsed.SLACK_TRIAGE_CHANNEL_POLICIES),
    triageAutoReply: parseBoolean(parsed.SLACK_TRIAGE_AUTO_REPLY),
    lifecycleNoticesEnabled: parseBoolean(parsed.SLACK_LIFECYCLE_NOTICES_ENABLED),
    lifecycleChannelIds: csvSet(parsed.SLACK_LIFECYCLE_CHANNEL_IDS ?? parsed.SLACK_TRIAGE_CHANNEL_IDS),
    researchMaxChannels: parsed.SLACK_RESEARCH_MAX_CHANNELS,
    researchHistoryLimit: parsed.SLACK_RESEARCH_HISTORY_LIMIT,
    assistantBotUserIds: csvSet(parsed.SLACK_ASSISTANT_BOT_USER_IDS),
    assistantBotCooldownSeconds: parsed.SLACK_ASSISTANT_BOT_COOLDOWN_SECONDS,
    assistantBotMaxHandoffsPerThread: parsed.SLACK_ASSISTANT_BOT_MAX_HANDOFFS_PER_THREAD,
    assistantBotHandoffWindowSeconds: parsed.SLACK_ASSISTANT_BOT_HANDOFF_WINDOW_SECONDS,
    assistantBotHandoffPolicies: assistantBotHandoffPolicies(parsed.SLACK_ASSISTANT_BOT_HANDOFF_POLICIES_JSON),
  };
}

function channelPolicies(value: string | undefined): Map<string, ProactiveSlackChannelPolicy> {
  const result = new Map<string, ProactiveSlackChannelPolicy>();
  for (const raw of (value ?? "").split(",")) {
    const [channelId, policy] = raw.split(":").map((part) => part?.trim()).filter(Boolean);
    if (!channelId || !isChannelPolicy(policy)) continue;
    result.set(channelId, policy);
  }
  return result;
}

function isChannelPolicy(value: string | undefined): value is ProactiveSlackChannelPolicy {
  return value === "strict" || value === "quiet" || value === "watch" || value === "eager";
}

function assistantBotHandoffPolicies(value: string | undefined): AssistantBotHandoffPolicy[] {
  const trimmed = value?.trim();
  if (!trimmed) return [];
  let decoded: unknown;
  try {
    decoded = JSON.parse(trimmed);
  } catch (error) {
    throw new Error(`SLACK_ASSISTANT_BOT_HANDOFF_POLICIES_JSON must be valid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (!Array.isArray(decoded)) {
    throw new Error("SLACK_ASSISTANT_BOT_HANDOFF_POLICIES_JSON must be an array.");
  }
  return decoded.flatMap((item) => {
    const record = item as Record<string, unknown>;
    const channelId = stringValue(record.channel_id ?? record.channelId);
    const botUserIds = stringSet(record.bot_user_ids ?? record.botUserIds ?? record.bot_ids ?? record.botIds);
    if (!channelId || botUserIds.size === 0) return [];
    return [{
      channelId,
      botUserIds,
      cooldownSeconds: nonnegativeInteger(record.cooldown_seconds ?? record.cooldownSeconds),
      maxHandoffsPerThread: nonnegativeInteger(record.max_handoffs_per_thread ?? record.maxHandoffsPerThread),
      windowSeconds: positiveInteger(record.window_seconds ?? record.windowSeconds),
    }];
  });
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function stringSet(value: unknown): Set<string> {
  if (Array.isArray(value)) {
    return new Set(value.map((item) => String(item).trim()).filter(Boolean));
  }
  if (typeof value === "string" && value.trim()) {
    return csvSet(value);
  }
  return new Set();
}

function nonnegativeInteger(value: unknown): number | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed >= 0 ? parsed : undefined;
}

function positiveInteger(value: unknown): number | undefined {
  const parsed = nonnegativeInteger(value);
  return parsed && parsed > 0 ? parsed : undefined;
}

export function validateSlackConfig(parsed: ParsedEnv): void {
  const socketMode = parseBoolean(parsed.SLACK_SOCKET_MODE);
  if (!parsed.SLACK_BOT_TOKEN) {
    throw new Error("SLACK_BOT_TOKEN is required");
  }
  if (socketMode && !parsed.SLACK_APP_TOKEN) {
    throw new Error("SLACK_APP_TOKEN is required when SLACK_SOCKET_MODE=true");
  }
  if (!socketMode && !parsed.SLACK_SIGNING_SECRET) {
    throw new Error("SLACK_SIGNING_SECRET is required when SLACK_SOCKET_MODE=false");
  }
}
