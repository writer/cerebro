import type { AppConfig } from "../../config/index.js";
import type { SlackApiResponse, SlackChannel, SlackParamValue } from "./types.js";
import {
  arrayFrom,
  nextCursor,
  normalizeSlackUserName,
  slackParams,
  unique,
} from "./utils.js";

export class SlackResearchTransport {
  private readonly users = new Map<string, string>();

  constructor(private readonly config: AppConfig) {}

  async channels(channelIds: string[] | undefined, maxChannels: number | undefined): Promise<SlackChannel[]> {
    const explicit = unique(channelIds ?? []);
    if (explicit.length > 0) {
      return Promise.all(explicit.map(async (id) => {
        try {
          const info = await this.slack("conversations.info", { channel: id });
          const channel = info.channel as SlackChannel | undefined;
          return { id, name: channel?.name ?? id, is_member: channel?.is_member };
        } catch {
          return { id, name: id };
        }
      }));
    }

    const configured = [...this.config.slack.triageChannelIds].map((id) => ({ id, name: id }));
    const seen = new Set(configured.map((channel) => channel.id));
    const channels: SlackChannel[] = [...configured];
    let cursor: string | undefined;
    do {
      const params: Record<string, string> = {
        types: "public_channel,private_channel",
        exclude_archived: "true",
        limit: "200",
      };
      if (cursor) params.cursor = cursor;
      const page = await this.slack("conversations.list", params);
      for (const channel of arrayFrom<SlackChannel>(page, "channels")) {
        if (!channel.id || seen.has(channel.id) || !channel.is_member) continue;
        seen.add(channel.id);
        channels.push(channel);
        if (channels.length >= (maxChannels ?? this.config.slack.researchMaxChannels)) {
          return channels;
        }
      }
      cursor = nextCursor(page);
    } while (cursor);
    return channels.slice(0, maxChannels ?? this.config.slack.researchMaxChannels);
  }

  async userName(userId: string): Promise<string | undefined> {
    const cached = this.users.get(userId);
    if (cached) return cached;
    try {
      const response = await this.slack("users.info", { user: userId });
      const name = normalizeSlackUserName(response.user, userId);
      this.users.set(userId, name);
      return name;
    } catch {
      return userId;
    }
  }

  async slack(method: string, params: Record<string, SlackParamValue> = {}): Promise<SlackApiResponse> {
    const { json, statusText } = await this.slackRaw(method, params);
    if (!json.ok) {
      throw new Error(`Slack ${method} failed: ${String(json.error ?? statusText)}`);
    }
    return json;
  }

  async slackRaw(method: string, params: Record<string, SlackParamValue> = {}): Promise<{ json: SlackApiResponse; headers: Headers; statusText: string }> {
    const body = slackParams(params);
    const response = await fetch(`https://slack.com/api/${method}`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.config.slack.botToken}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body,
    });
    const json = await response.json() as SlackApiResponse;
    return { json, headers: response.headers, statusText: response.statusText };
  }

  coverage(channels: SlackChannel[], explicitChannelIds: string[] | undefined): string {
    if (explicitChannelIds?.length) {
      return `Searched ${channels.length} requested Slack channel(s).`;
    }
    return `Searched configured triage channels and joined channels visible to the Cerebro bot, capped at ${this.config.slack.researchMaxChannels} channel(s).`;
  }
}
