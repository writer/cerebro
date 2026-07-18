import type { AppConfig, ProactiveSlackChannelPolicy } from "../config/index.js";
import type { SecurityMemoryRecord, SecurityMemoryStore } from "../learning/security-memory/index.js";
import { trimForSlack } from "../slack/format.js";
import { SlackResearchClient } from "../slack/research/index.js";
import type {
  SlackChannelContextResult,
  SlackMessageContextResult,
  SlackScopeCapabilitiesResult,
  SlackThreadContextResult,
} from "../slack/research/types.js";
import { channelPolicyFor, policyContextLine } from "./channel-policy.js";
import type { AlertTriageInput } from "./alert-triage-types.js";
import type { SlackThreadSessionState, SlackThreadSessionStateStore } from "./slack-thread-state.js";

export interface ProactiveSlackContextPacket {
  channelId: string;
  threadTs: string;
  sourceTs: string;
  channelPolicy: ProactiveSlackChannelPolicy;
  threadState: SlackThreadSessionState;
  thread?: SlackThreadContextResult;
  message?: SlackMessageContextResult;
  channel?: SlackChannelContextResult;
  memories: SecurityMemoryRecord[];
  scope?: SlackScopeCapabilitiesResult;
  errors: string[];
}

export interface ProactiveSlackContextOptions {
  slack?: SlackResearchClient;
}

export class ProactiveSlackContextCollector {
  constructor(
    private readonly config: AppConfig,
    private readonly memory: SecurityMemoryStore,
    private readonly threadState: SlackThreadSessionStateStore,
    private readonly options: ProactiveSlackContextOptions = {},
  ) {}

  async collect(input: AlertTriageInput): Promise<ProactiveSlackContextPacket> {
    const channelPolicy = channelPolicyFor(this.config, input.channelId);
    const threadTs = input.threadTs ?? input.ts;
    const state = await this.threadState.getOrCreate({
      channelId: input.channelId,
      threadTs,
      channelPolicy,
    });
    const slack = this.options.slack ?? new SlackResearchClient(this.config);
    const errors: string[] = [];

    const [thread, message, channel, memories] = await Promise.all([
      this.shouldFetchThread(input, state, channelPolicy)
        ? slack.threadContext(input.channelId, threadTs, 12).catch((error) => {
            errors.push(`slack_thread_context: ${shortError(error)}`);
            return undefined;
          })
        : undefined,
      this.shouldFetchMessage(input, state, channelPolicy)
        ? slack.messageContext(input.channelId, input.ts, 12).catch((error) => {
            errors.push(`slack_message_context: ${shortError(error)}`);
            return undefined;
          })
        : undefined,
      this.shouldFetchChannel(state, channelPolicy)
        ? slack.channelContext(input.channelId, 12).catch((error) => {
            errors.push(`slack_channel_context: ${shortError(error)}`);
            return undefined;
          })
        : undefined,
      this.memory.search(input.text, 4).catch((error) => {
        errors.push(`security_memory_search: ${shortError(error)}`);
        return [];
      }),
    ]);

    let updatedState = state;
    if (thread) {
      updatedState = await this.threadState.markContextFetched({
        channelId: input.channelId,
        threadTs,
        channelPolicy,
        messageCount: thread.messages.length,
      }).catch(() => state);
    }

    const scope = errors.some((error) => error.startsWith("slack_"))
      ? await slack.scopeCapabilities().catch((error) => {
          errors.push(`slack_scope_capabilities: ${shortError(error)}`);
          return undefined;
        })
      : undefined;

    return {
      channelId: input.channelId,
      threadTs,
      sourceTs: input.ts,
      channelPolicy,
      threadState: updatedState,
      thread,
      message,
      channel,
      memories,
      scope,
      errors: errors.slice(0, 8),
    };
  }

  private shouldFetchThread(input: AlertTriageInput, state: SlackThreadSessionState, policy: ProactiveSlackChannelPolicy): boolean {
    if (!input.threadTs) return false;
    if (!state.lastContextFetchedAt) return true;
    if (policy === "eager") return true;
    return isShortFollowUp(input.text);
  }

  private shouldFetchMessage(input: AlertTriageInput, state: SlackThreadSessionState, policy: ProactiveSlackChannelPolicy): boolean {
    if (policy === "eager") return true;
    if (!state.lastContextFetchedAt && input.threadTs) return true;
    return /false positive|what evidence|why|what actions?|permalink|reaction|linked|file|canvas/i.test(input.text);
  }

  private shouldFetchChannel(state: SlackThreadSessionState, policy: ProactiveSlackChannelPolicy): boolean {
    if (policy === "strict") return false;
    if (!state.lastContextFetchedAt) return true;
    return policy === "eager";
  }
}

export function renderProactiveContextPromptBlock(packet: ProactiveSlackContextPacket): string {
  const state = packet.threadState;
  const recentOutcomes = state.outcomes.slice(0, 5).map((outcome) => ({
    ts: outcome.sourceTs,
    outcome: outcome.outcome,
    topic: outcome.topic,
    classification: outcome.classification,
    confidence: outcome.confidence,
    summary: outcome.summary,
  }));
  const pendingSuggestions = state.suggestions
    .filter((suggestion) => suggestion.status === "pending")
    .slice(0, 5)
    .map((suggestion) => ({
      id: suggestion.id,
      title: suggestion.title,
      description: suggestion.description,
      source_ts: suggestion.sourceTs,
    }));

  const context = {
    channel_policy: packet.channelPolicy,
    policy_instruction: policyContextLine(packet.channelPolicy),
    durable_thread_state: {
      thread_ts: state.threadTs,
      last_reviewed_ts: state.lastReviewedTs,
      last_posted_ts: state.lastPostedTs,
      last_context_fetched_at: state.lastContextFetchedAt,
      context_message_count: state.contextMessageCount,
      latest_summary: state.latestSummary,
      recent_outcomes: recentOutcomes,
      pending_monitor_suggestions: pendingSuggestions,
    },
    visible_thread_context: packet.thread ? {
      message_count: packet.thread.messages.length,
      messages: packet.thread.messages.map((message) => ({
        ts: message.ts,
        user: message.user_name ?? message.user_id ?? message.bot_id ?? "unknown",
        text: trimForSlack(message.text, 500),
      })),
    } : undefined,
    exact_message_context: packet.message ? {
      permalink: packet.message.permalink,
      reaction_count: packet.message.reactions.length,
      errors: packet.message.errors,
    } : undefined,
    channel_context: packet.channel ? {
      channel: packet.channel.channel,
      bookmarks: packet.channel.bookmarks.slice(0, 6),
      pins: packet.channel.pins.slice(0, 6),
      recent_messages: packet.channel.recent_messages.slice(0, 6).map((message) => ({
        ts: message.ts,
        user: message.user_name ?? message.user_id ?? message.bot_id ?? "unknown",
        text: trimForSlack(message.text, 260),
      })),
      errors: packet.channel.errors,
    } : undefined,
    recalled_memory: packet.memories.slice(0, 4).map((memory) => ({
      kind: memory.kind,
      topic: memory.topic,
      summary: trimForSlack(memory.summary, 260),
      tags: memory.tags?.slice(0, 6),
    })),
    slack_scope_note: packet.scope?.note,
    context_errors: packet.errors,
  };

  return [
    "Proactive Slack context packet:",
    "```json",
    JSON.stringify(context, null, 2),
    "```",
    "Use durable_thread_state to avoid repeating prior Cerebro replies. Do not store raw Slack transcript text as memory.",
  ].join("\n");
}

function isShortFollowUp(text: string): boolean {
  const normalized = text.replace(/\s+/g, " ").trim();
  if (normalized.length <= 80) return true;
  return /\b(false positive|what evidence|what actions?|why|how so|which finding|same issue|still open)\b/i.test(normalized);
}

function shortError(error: unknown): string {
  return error instanceof Error ? error.message.slice(0, 160) : String(error).slice(0, 160);
}
