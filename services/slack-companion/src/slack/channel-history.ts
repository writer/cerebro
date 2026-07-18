import type { AppConfig } from "../config/index.js";
import type { SlackApiResponse, SlackChannel, SlackMessage, SlackParamValue } from "./research/types.js";
import { arrayFrom, nextCursor, slackParams } from "./research/utils.js";

const DEFAULT_PAGE_SIZE = 100;
const DEFAULT_MAX_THREAD_MESSAGES = 500;
const MAX_ATTEMPTS = 5;

export interface JoinedSlackChannel {
  id: string;
  name: string;
  isPrivate: boolean;
}

export interface SlackHistoryPage {
  messages: SlackMessage[];
  hasMore: boolean;
}

export type SlackLearningCandidateRejection =
  | "machine"
  | "subtype"
  | "missing_user"
  | "missing_timestamp"
  | "empty"
  | "cerebro_mention";

export interface SlackChannelHistoryReader {
  botUserId(): Promise<string>;
  joinedChannels(maxChannels: number): Promise<JoinedSlackChannel[]>;
  historyPage(channelId: string, input: { oldestTs: string; latestTs: string; limit?: number }): Promise<SlackHistoryPage>;
  threadReplies(channelId: string, threadTs: string, maxMessages?: number): Promise<SlackMessage[]>;
}

interface SlackChannelHistoryClientOptions {
  fetch?: typeof fetch;
  sleep?: (milliseconds: number) => Promise<void>;
}

export class SlackChannelHistoryClient implements SlackChannelHistoryReader {
  private readonly fetchFn: typeof fetch;
  private readonly sleep: (milliseconds: number) => Promise<void>;

  constructor(
    private readonly config: AppConfig,
    options: SlackChannelHistoryClientOptions = {},
  ) {
    this.fetchFn = options.fetch ?? fetch;
    this.sleep = options.sleep ?? ((milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)));
  }

  async botUserId(): Promise<string> {
    const response = await this.call("auth.test");
    const userId = typeof response.user_id === "string" ? response.user_id.trim() : "";
    if (!userId) throw new Error("Slack auth.test did not return a bot user id.");
    return userId;
  }

  async joinedChannels(maxChannels: number): Promise<JoinedSlackChannel[]> {
    const boundedMax = Math.max(1, Math.min(500, Math.floor(maxChannels)));
    const channels: JoinedSlackChannel[] = [];
    const seen = new Set<string>();
    let cursor: string | undefined;
    do {
      const response = await this.call("conversations.list", {
        types: "public_channel,private_channel",
        exclude_archived: true,
        limit: 200,
        cursor,
      });
      for (const channel of arrayFrom<SlackChannel>(response, "channels")) {
        if (!channel.id || !channel.is_member || channel.is_archived || seen.has(channel.id)) continue;
        seen.add(channel.id);
        channels.push({
          id: channel.id,
          name: channel.name?.trim() || channel.id,
          isPrivate: Boolean(channel.is_private),
        });
        if (channels.length >= boundedMax) return channels;
      }
      cursor = nextCursor(response);
    } while (cursor);
    return channels;
  }

  async historyPage(
    channelId: string,
    input: { oldestTs: string; latestTs: string; limit?: number },
  ): Promise<SlackHistoryPage> {
    const limit = Math.max(1, Math.min(200, Math.floor(input.limit ?? DEFAULT_PAGE_SIZE)));
    const response = await this.call("conversations.history", {
      channel: channelId,
      oldest: input.oldestTs,
      latest: input.latestTs,
      inclusive: false,
      limit,
    });
    return {
      messages: arrayFrom<SlackMessage>(response, "messages"),
      hasMore: Boolean(response.has_more) || Boolean(nextCursor(response)),
    };
  }

  async threadReplies(
    channelId: string,
    threadTs: string,
    maxMessages = DEFAULT_MAX_THREAD_MESSAGES,
  ): Promise<SlackMessage[]> {
    const boundedMax = Math.max(1, Math.min(2_000, Math.floor(maxMessages)));
    const messages: SlackMessage[] = [];
    let cursor: string | undefined;
    do {
      const response = await this.call("conversations.replies", {
        channel: channelId,
        ts: threadTs,
        limit: Math.min(200, boundedMax - messages.length),
        cursor,
      });
      messages.push(...arrayFrom<SlackMessage>(response, "messages"));
      if (messages.length >= boundedMax) break;
      cursor = nextCursor(response);
    } while (cursor);
    return messages.slice(0, boundedMax);
  }

  private async call(method: string, params: Record<string, SlackParamValue> = {}): Promise<SlackApiResponse> {
    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt += 1) {
      const response = await this.fetchFn(`https://slack.com/api/${method}`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${this.config.slack.botToken}`,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: slackParams(params),
        signal: AbortSignal.timeout(30_000),
      });
      if (response.status === 429) {
        await this.waitForRetry(response, attempt);
        continue;
      }
      if (response.status >= 500 && attempt < MAX_ATTEMPTS) {
        await this.sleep(500 * 2 ** (attempt - 1));
        continue;
      }
      const json = await response.json() as SlackApiResponse;
      if (json.ok) return json;
      if (json.error === "ratelimited" && attempt < MAX_ATTEMPTS) {
        await this.waitForRetry(response, attempt);
        continue;
      }
      throw new Error(`Slack ${method} failed: ${String(json.error ?? response.statusText)}`);
    }
    throw new Error(`Slack ${method} rate limit retries exhausted.`);
  }

  private async waitForRetry(response: Response, attempt: number): Promise<void> {
    const retryAfterSeconds = Number(response.headers.get("retry-after"));
    const milliseconds = Number.isFinite(retryAfterSeconds) && retryAfterSeconds > 0
      ? retryAfterSeconds * 1_000
      : 1_000 * 2 ** (attempt - 1);
    await this.sleep(Math.min(milliseconds, 120_000));
  }
}

export function slackLearningCandidateRejection(
  message: SlackMessage,
  cerebroBotUserId: string,
): SlackLearningCandidateRejection | undefined {
  if (message.bot_id || message.app_id) return "machine";
  if (message.subtype) return "subtype";
  if (typeof message.user !== "string" || !message.user.trim()) return "missing_user";
  if (typeof message.ts !== "string" || !message.ts.trim()) return "missing_timestamp";
  if (typeof message.text !== "string" || !message.text.trim()) return "empty";
  if (mentionsUser(message.text, cerebroBotUserId)) return "cerebro_mention";
  return undefined;
}

function mentionsUser(text: string, userId: string): boolean {
  if (!userId.trim()) return false;
  return text.includes(`<@${userId}>`);
}
