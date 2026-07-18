import type { AppConfig } from "../../config/index.js";
import { capabilityRows } from "./capabilities.js";
import {
  bookmarkSummary,
  channelSummary,
  fileCommentSummary,
  fileSummary,
  pinSummary,
  reactionSummaries,
  searchChannelSummary,
  searchFileSummary,
  searchMessageSummary,
  searchUserSummary,
  usergroupSummary,
  userSummary,
} from "./summaries.js";
import type {
  SlackApiResponse,
  SlackAppAuditResult,
  SlackAssistantSearchInput,
  SlackAssistantSearchResult,
  SlackChannelContextResult,
  SlackFileContextResult,
  SlackMessage,
  SlackMessageContextResult,
  SlackMessageHit,
  SlackMessageSearchInput,
  SlackMessageSearchResult,
  SlackParamValue,
  SlackScopeCapabilitiesResult,
  SlackThreadContextResult,
  SlackUserContextResult,
} from "./types.js";
import {
  arrayFrom,
  arrayFromRecord,
  boundedDays,
  boundedLimit,
  capture,
  isoFromSlackTs,
  messageText,
  nextCursor,
  objectValue,
  oldestForDays,
  safeSnippet,
  scoreText,
  scopeSet,
  searchTerms,
  shortError,
  stringValue,
  unique,
} from "./utils.js";
import { SlackResearchTransport } from "./transport.js";

export type {
  SlackAppAuditResult,
  SlackAssistantSearchInput,
  SlackAssistantSearchResult,
  SlackChannelContextResult,
  SlackFileContextResult,
  SlackMessageContextResult,
  SlackMessageHit,
  SlackMessageSearchInput,
  SlackMessageSearchResult,
  SlackScopeCapabilitiesResult,
  SlackThreadContextResult,
  SlackUserContextResult,
} from "./types.js";

export class SlackResearchClient {
  private readonly transport: SlackResearchTransport;

  constructor(private readonly config: AppConfig) {
    this.transport = new SlackResearchTransport(config);
  }

  async searchMessages(input: SlackMessageSearchInput): Promise<SlackMessageSearchResult> {
    const days = boundedDays(input.days);
    const limit = boundedLimit(input.limit, 20);
    const oldest = input.after ? String(Math.floor(input.after)) : oldestForDays(days);
    const latest = input.before ? String(Math.floor(input.before)) : undefined;
    const terms = searchTerms(input.query);
    const authorTerms = input.authorQuery ? searchTerms(input.authorQuery) : [];
    const channels = await this.transport.channels(input.channelIds, input.maxChannels);
    const hits: SlackMessageHit[] = [];
    let messagesChecked = 0;

    for (const channel of channels) {
      let cursor: string | undefined;
      let channelMessages = 0;
      do {
        const params: Record<string, string> = {
          channel: channel.id,
          limit: "200",
          oldest,
        };
        if (latest) params.latest = latest;
        if (cursor) params.cursor = cursor;
        const page = await this.transport.slack("conversations.history", params);
        const messages = arrayFrom<SlackMessage>(page, "messages");
        for (const message of messages) {
          channelMessages += 1;
          messagesChecked += 1;
          const text = messageText(message);
          const authorName = message.user ? await this.transport.userName(message.user) : undefined;
          const authorHaystack = [message.user ?? "", authorName ?? ""].join(" ");
          const authorScore = authorTerms.length > 0 ? scoreText(authorHaystack, authorTerms) : 0;
          const score = scoreText(text, terms) + authorScore * 3;
          if (!message.ts || score <= 0) continue;
          hits.push({
            channel_id: channel.id,
            channel_name: channel.name ?? channel.id,
            ts: message.ts,
            datetime: isoFromSlackTs(message.ts),
            user_id: message.user,
            user_name: authorName,
            text: safeSnippet(text),
            score,
          });
        }
        cursor = nextCursor(page);
      } while (cursor && channelMessages < this.config.slack.researchHistoryLimit && hits.length < limit * 4);
    }

    hits.sort((left, right) => right.score - left.score || Number(right.ts) - Number(left.ts));
    return {
      query: input.query,
      days,
      channels_checked: channels.length,
      messages_checked: messagesChecked,
      coverage: this.transport.coverage(channels, input.channelIds),
      hits: hits.slice(0, limit),
    };
  }

  async recentBotQuestions(input: { days?: number; channelIds?: string[]; limit?: number; maxChannels?: number } = {}): Promise<SlackMessageSearchResult> {
    const auth = await this.transport.slack("auth.test");
    const botUserId = typeof auth.user_id === "string" ? auth.user_id : undefined;
    if (!botUserId) {
      return {
        query: "recent Cerebro mentions",
        days: boundedDays(input.days),
        channels_checked: 0,
        messages_checked: 0,
        coverage: "Slack auth did not return the bot user id.",
        hits: [],
      };
    }
    return this.searchMessages({
      query: botUserId,
      days: input.days,
      channelIds: input.channelIds,
      limit: input.limit,
      maxChannels: input.maxChannels,
    });
  }

  async threadContext(channelId: string, threadTs: string, limit = 20): Promise<SlackThreadContextResult> {
    const response = await this.transport.slack("conversations.replies", {
      channel: channelId,
      ts: threadTs,
      limit: String(boundedLimit(limit, 20)),
    });
    const messages = await Promise.all(arrayFrom<SlackMessage>(response, "messages").flatMap(async (message) => {
      if (!message.ts) return [];
      const text = safeSnippet(messageText(message));
      if (!text) return [];
      return [{
        ts: message.ts,
        datetime: isoFromSlackTs(message.ts),
        user_id: message.user,
        user_name: message.user ? await this.transport.userName(message.user) : undefined,
        bot_id: message.bot_id,
        text,
      }];
    }));
    return {
      channel_id: channelId,
      thread_ts: threadTs,
      messages: messages.flat(),
    };
  }

  async appInstallAudit(appName: string, days = 90, limit = 10): Promise<SlackAppAuditResult> {
    const bounded = boundedDays(days, 365);
    const eventLimit = boundedLimit(limit, 20);
    if (!this.config.slack.auditLogsToken) {
      return {
        app_name: appName,
        days: bounded,
        audit_logs_configured: false,
        audit_events: [],
        fallback_search: await this.searchMessages({
          query: `${appName} installed app approval scopes`,
          days: bounded,
          limit: eventLimit,
          maxChannels: this.config.slack.researchMaxChannels,
        }),
        note: "Slack Audit Logs are not configured for this companion. Message search can show discussion, but installation time and installer require Audit Logs coverage.",
      };
    }

    const params = new URLSearchParams({
      action: "app_installed",
      oldest: oldestForDays(bounded),
      limit: String(eventLimit),
    });
    const response = await fetch(`https://api.slack.com/audit/v1/logs?${params}`, {
      headers: {
        Authorization: `Bearer ${this.config.slack.auditLogsToken}`,
        Accept: "application/json",
      },
    });
    const body = await response.json() as SlackApiResponse;
    if (!response.ok || !body.ok) {
      return {
        app_name: appName,
        days: bounded,
        audit_logs_configured: true,
        audit_events: [],
        fallback_search: await this.searchMessages({ query: `${appName} installed`, days: bounded, limit: eventLimit }),
        note: `Slack Audit Logs request failed: ${String(body.error ?? response.statusText)}`,
      };
    }
    const events = arrayFrom<Record<string, unknown>>(body, "entries")
      .filter((event) => JSON.stringify(event).toLowerCase().includes(appName.toLowerCase()))
      .slice(0, eventLimit);
    return {
      app_name: appName,
      days: bounded,
      audit_logs_configured: true,
      audit_events: events,
      note: events.length > 0 ? undefined : "No matching app installation events were returned by Slack Audit Logs.",
    };
  }

  async scopeCapabilities(): Promise<SlackScopeCapabilitiesResult> {
    const response = await this.transport.slackRaw("auth.test");
    const granted = scopeSet(response.headers.get("x-oauth-scopes"));
    const capabilities = capabilityRows(granted, Boolean(this.config.slack.auditLogsToken));
    const missing = capabilities
      .filter((capability) => !capability.available)
      .flatMap((capability) => capability.required_scopes)
      .filter((scope) => scope !== "SLACK_AUDIT_LOGS_TOKEN");
    return {
      ok: response.json.ok === true,
      bot_user_id: stringValue(response.json.user_id),
      team_id: stringValue(response.json.team_id),
      enterprise_id: stringValue(response.json.enterprise_id),
      team_url: stringValue(response.json.url),
      granted_scopes: [...granted].sort(),
      capabilities,
      missing_recommended_scopes: unique(missing).sort(),
      note: granted.size > 0
        ? "Capabilities are based on the x-oauth-scopes header returned by Slack auth.test."
        : "Slack did not return x-oauth-scopes. Capability coverage is partial; run a live scope probe from the installed app if a tool reports missing_scope.",
    };
  }

  async assistantSearchContext(input: SlackAssistantSearchInput): Promise<SlackAssistantSearchResult> {
    const params: Record<string, SlackParamValue> = {
      query: input.query,
      limit: Math.min(boundedLimit(input.limit, 10), 20),
      cursor: input.cursor,
      content_types: input.contentTypes?.length ? unique(input.contentTypes) : ["messages"],
      channel_types: input.channelTypes?.length ? unique(input.channelTypes) : ["public_channel"],
      include_context_messages: input.includeContextMessages ?? true,
      context_channel_id: input.contextChannelId,
      include_bots: input.includeBots,
      action_token: input.actionToken,
      after: input.after,
      before: input.before,
      sort: input.sort,
      sort_dir: input.sortDir,
    };

    try {
        const response = await this.transport.slack("assistant.search.context", params);
      const results = objectValue(response.results);
      return {
        ok: true,
        api: "assistant.search.context",
        query: input.query,
        results: {
          messages: arrayFromRecord<Record<string, unknown>>(results, "messages")
            .map(searchMessageSummary)
            .filter((message) => message.text),
          files: arrayFromRecord<Record<string, unknown>>(results, "files").map(searchFileSummary),
          channels: arrayFromRecord<Record<string, unknown>>(results, "channels").map(searchChannelSummary),
          users: arrayFromRecord<Record<string, unknown>>(results, "users").map(searchUserSummary),
        },
        next_cursor: nextCursor(response),
        note: input.actionToken
          ? "Used Slack assistant.search.context with the provided action token."
          : "Used Slack assistant.search.context. Bot-token calls may require an action_token for some workspaces.",
      };
    } catch (error) {
      const fallback = await this.searchMessages({
        query: input.query,
        days: input.fallbackDays,
        channelIds: input.contextChannelId ? [input.contextChannelId] : undefined,
        limit: Math.min(boundedLimit(input.limit, 10), 20),
        maxChannels: this.config.slack.researchMaxChannels,
      }).catch((fallbackError) => ({
        query: input.query,
        days: boundedDays(input.fallbackDays),
        channels_checked: 0,
        messages_checked: 0,
        coverage: `assistant.search.context failed, and fallback message search failed: ${shortError(fallbackError)}`,
        hits: [],
      }));
      return {
        ok: false,
        api: "assistant.search.context+fallback",
        query: input.query,
        fallback_search: fallback,
        error: shortError(error),
        note: "assistant.search.context failed. The fallback only searches recent messages in channels visible to the Cerebro bot, so coverage is narrower than Slack AI search.",
      };
    }
  }

  async messageContext(channelId: string, ts: string, limit = 20): Promise<SlackMessageContextResult> {
    const [thread, permalink, reactions] = await Promise.all([
      capture("conversations.replies", () => this.threadContext(channelId, ts, limit)),
      capture("chat.getPermalink", () => this.transport.slack("chat.getPermalink", { channel: channelId, message_ts: ts })),
      capture("reactions.get", () => this.transport.slack("reactions.get", { channel: channelId, timestamp: ts })),
    ]);
    const reactionSource = objectValue(reactions.value?.message)?.reactions ?? reactions.value?.reactions;
    return {
      channel_id: channelId,
      ts,
      permalink: stringValue(permalink.value?.permalink),
      thread: thread.value,
      reactions: reactionSummaries(reactionSource),
      errors: [thread.error, permalink.error, reactions.error].filter(Boolean) as string[],
    };
  }

  async channelContext(channelId: string, limit = 20): Promise<SlackChannelContextResult> {
    const [info, bookmarks, pins, history] = await Promise.all([
      capture("conversations.info", () => this.transport.slack("conversations.info", { channel: channelId })),
      capture("bookmarks.list", () => this.transport.slack("bookmarks.list", { channel_id: channelId })),
      capture("pins.list", () => this.transport.slack("pins.list", { channel: channelId })),
      capture("conversations.history", () => this.transport.slack("conversations.history", { channel: channelId, limit: String(boundedLimit(limit, 20)) })),
    ]);
    const messages = await Promise.all(arrayFrom<SlackMessage>(history.value ?? {}, "messages").flatMap(async (message) => {
      if (!message.ts) return [];
      const text = safeSnippet(messageText(message));
      if (!text) return [];
      return [{
        ts: message.ts,
        datetime: isoFromSlackTs(message.ts),
        user_id: message.user,
        user_name: message.user ? await this.transport.userName(message.user) : undefined,
        bot_id: message.bot_id,
        text,
      }];
    }));
    return {
      channel_id: channelId,
      channel: channelSummary(objectValue(info.value?.channel)),
      bookmarks: arrayFrom<Record<string, unknown>>(bookmarks.value ?? {}, "bookmarks").map(bookmarkSummary).slice(0, 20),
      pins: arrayFrom<Record<string, unknown>>(pins.value ?? {}, "items").map(pinSummary).slice(0, 20),
      recent_messages: messages.flat(),
      errors: [info.error, bookmarks.error, pins.error, history.error].filter(Boolean) as string[],
    };
  }

  async userContext(userId: string): Promise<SlackUserContextResult> {
    const [info, usergroups] = await Promise.all([
      capture("users.info", () => this.transport.slack("users.info", { user: userId })),
      capture("usergroups.list", () => this.transport.slack("usergroups.list", { include_disabled: false, include_users: true, include_count: true })),
    ]);
    return {
      user_id: userId,
      user: userSummary(objectValue(info.value?.user)),
      usergroups: arrayFrom<Record<string, unknown>>(usergroups.value ?? {}, "usergroups")
        .filter((group) => arrayFromRecord<string>(group, "users").includes(userId))
        .map(usergroupSummary),
      errors: [info.error, usergroups.error].filter(Boolean) as string[],
    };
  }

  async fileContext(fileId: string, limit = 20): Promise<SlackFileContextResult> {
    const info = await capture("files.info", () => this.transport.slack("files.info", {
      file: fileId,
      count: String(boundedLimit(limit, 20)),
    }));
    return {
      file_id: fileId,
      file: fileSummary(objectValue(info.value?.file)),
      comments: arrayFrom<Record<string, unknown>>(info.value ?? {}, "comments").map(fileCommentSummary),
      errors: [info.error].filter(Boolean) as string[],
    };
  }

}
