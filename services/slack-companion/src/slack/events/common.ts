import type { DailyNoteInput } from "../../learning/daily-notes.js";
import { logger } from "../../logger.js";
import { trimForSlack } from "../format.js";
import type { EventDeps } from "./types.js";

export function stripMention(text: string, botUserId?: string): string {
  const escaped = botUserId ? escapeRegExp(botUserId) : undefined;
  const pattern = escaped ? new RegExp(`<@${escaped}>`, "g") : /<@[A-Z0-9]+>/;
  return text.replace(pattern, "").replace(/\s+([?.!,])/g, "$1").replace(/\s+/g, " ").trim();
}

export function botUserIdFrom(event: Record<string, unknown>, context: Record<string, unknown> | undefined): string | undefined {
  const contextBotUserId = stringValue(context?.botUserId) ?? stringValue(context?.bot_user_id);
  if (contextBotUserId) return contextBotUserId;
  const authorizations = Array.isArray(event.authorizations) ? event.authorizations : [];
  for (const authorization of authorizations) {
    const userId = stringValue((authorization as Record<string, unknown>).user_id);
    if (userId) return userId;
  }
  return undefined;
}

export function claimBotHandoffForEvent(deps: EventDeps, event: Record<string, unknown>): ReturnType<EventDeps["coordinator"]["claimBotHandoff"]> {
  return deps.coordinator.claimBotHandoff({
    channelId: stringValue(event.channel),
    threadTs: stringValue(event.thread_ts),
    ts: stringValue(event.ts),
    botId: stringValue(event.bot_id),
    userId: stringValue(event.user),
    appId: stringValue(event.app_id),
    subtype: stringValue(event.subtype),
  });
}

export async function setAssistantThreadWorking(client: any, channel: string, threadTs: string, question: string): Promise<void> {
  await Promise.all([
    assistantThreadApiCall(client, "assistant.threads.setStatus", {
      channel_id: channel,
      thread_ts: threadTs,
      status: "is checking Cerebro context",
      loading_messages: [
        "Checking graph context",
        "Reading thread context",
        "Looking for prior signal",
        "Preparing a short answer",
      ],
    }),
    assistantThreadApiCall(client, "assistant.threads.setTitle", {
      channel_id: channel,
      thread_ts: threadTs,
      title: assistantThreadTitle(question),
    }),
  ]);
}

export async function addReaction(client: any, channel: string, ts: string, name: string): Promise<void> {
  try {
    await client.reactions.add({ channel, timestamp: ts, name });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (!/already_reacted|missing_scope|not_in_channel|invalid_name/i.test(message)) {
      logger.warn("slack reaction failed", { error: message, channel, ts, name });
    }
  }
}

export async function recordDailyNote(deps: EventDeps, input: DailyNoteInput): Promise<void> {
  await deps.notes.record(input).catch((error) => logger.warn("daily note write failed", { error: String(error), kind: input.kind }));
}

export function questionTitle(question: string): string {
  return `Slack question: ${question.replace(/\s+/g, " ").trim().slice(0, 120) || "Cerebro mention"}`;
}

export function alertTitle(text: string): string {
  return `Slack alert: ${(text ?? "").replace(/\s+/g, " ").trim().slice(0, 120) || "message"}`;
}

export function unique<T>(values: T[]): T[] {
  return [...new Set(values)];
}

async function assistantThreadApiCall(client: any, method: string, args: Record<string, unknown>): Promise<void> {
  try {
    if (typeof client.apiCall !== "function") return;
    const response = await client.apiCall(method, args) as { ok?: boolean; error?: string; detail?: string };
    if (response?.ok === false) {
      throw new Error(response.detail ? `${response.error ?? "unknown"}: ${response.detail}` : response.error ?? "unknown");
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (/missing_scope|invalid_thread_ts|channel_not_found|no_permission|not_allowed_token_type|method_not_supported|unknown_method/i.test(message)) {
      logger.info("slack assistant thread api skipped", { method, reason: message.slice(0, 200) });
      return;
    }
    logger.warn("slack assistant thread api failed", { method, error: message.slice(0, 300) });
  }
}

function assistantThreadTitle(question: string): string {
  const normalized = question.replace(/\s+/g, " ").trim();
  return normalized ? trimForSlack(normalized, 80) : "Security question";
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
