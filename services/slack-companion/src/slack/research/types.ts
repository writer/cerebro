export interface SlackApiResponse {
  ok?: boolean;
  error?: string;
  response_metadata?: {
    next_cursor?: string;
  };
  [key: string]: unknown;
}

export interface SlackChannel {
  id: string;
  name?: string;
  is_member?: boolean;
  is_private?: boolean;
  is_archived?: boolean;
}

export interface SlackMessage {
  type?: string;
  subtype?: string;
  user?: string;
  bot_id?: string;
  app_id?: string;
  ts?: string;
  thread_ts?: string;
  text?: string;
  reply_count?: number;
}

export type SlackParamValue = string | number | boolean | string[] | undefined;

export interface SlackMessageSearchInput {
  query: string;
  authorQuery?: string;
  days?: number;
  after?: number;
  before?: number;
  channelIds?: string[];
  limit?: number;
  maxChannels?: number;
}

export interface SlackMessageHit {
  channel_id: string;
  channel_name: string;
  ts: string;
  datetime: string;
  user_id?: string;
  user_name?: string;
  text: string;
  score: number;
}

export interface SlackMessageSearchResult {
  query: string;
  days: number;
  channels_checked: number;
  messages_checked: number;
  coverage: string;
  hits: SlackMessageHit[];
}

export interface SlackThreadContextResult {
  channel_id: string;
  thread_ts: string;
  messages: Array<{
    ts: string;
    datetime: string;
    user_id?: string;
    user_name?: string;
    bot_id?: string;
    text: string;
  }>;
}

export interface SlackAppAuditResult {
  app_name: string;
  days: number;
  audit_logs_configured: boolean;
  audit_events: unknown[];
  fallback_search?: SlackMessageSearchResult;
  note?: string;
}

export interface SlackScopeCapabilitiesResult {
  ok: boolean;
  bot_user_id?: string;
  team_id?: string;
  enterprise_id?: string;
  team_url?: string;
  granted_scopes: string[];
  capabilities: Array<{
    name: string;
    available: boolean;
    required_scopes: string[];
    note?: string;
  }>;
  missing_recommended_scopes: string[];
  note: string;
}

export interface SlackAssistantSearchInput {
  query: string;
  limit?: number;
  cursor?: string;
  contentTypes?: string[];
  channelTypes?: string[];
  includeContextMessages?: boolean;
  contextChannelId?: string;
  includeBots?: boolean;
  actionToken?: string;
  after?: number;
  before?: number;
  sort?: "score" | "timestamp";
  sortDir?: "asc" | "desc";
  fallbackDays?: number;
}

export interface SlackAssistantSearchResult {
  ok: boolean;
  api: "assistant.search.context" | "assistant.search.context+fallback";
  query: string;
  results?: {
    messages: Array<{
      channel_id?: string;
      channel_name?: string;
      ts?: string;
      datetime?: string;
      author_user_id?: string;
      author_name?: string;
      is_author_bot?: boolean;
      text: string;
      permalink?: string;
      context_messages?: {
        before: Array<{ ts?: string; datetime?: string; user_id?: string; text: string }>;
        after: Array<{ ts?: string; datetime?: string; user_id?: string; text: string }>;
      };
    }>;
    files: Array<{
      file_id?: string;
      title?: string;
      file_type?: string;
      author_user_id?: string;
      uploader_user_id?: string;
      permalink?: string;
      content?: string;
    }>;
    channels: Array<{
      channel_id?: string;
      name?: string;
      purpose?: string;
      topic?: string;
      permalink?: string;
    }>;
    users: Array<{
      user_id?: string;
      name?: string;
      title?: string;
      team_id?: string;
    }>;
  };
  next_cursor?: string;
  fallback_search?: SlackMessageSearchResult;
  error?: string;
  note?: string;
}

export interface SlackMessageContextResult {
  channel_id: string;
  ts: string;
  permalink?: string;
  thread?: SlackThreadContextResult;
  reactions: Array<{ name?: string; count?: number; user_count_returned?: number }>;
  errors: string[];
}

export interface SlackChannelContextResult {
  channel_id: string;
  channel?: Record<string, unknown>;
  bookmarks: Array<Record<string, unknown>>;
  pins: Array<Record<string, unknown>>;
  recent_messages: SlackThreadContextResult["messages"];
  errors: string[];
}

export interface SlackUserContextResult {
  user_id: string;
  user?: Record<string, unknown>;
  usergroups: Array<Record<string, unknown>>;
  errors: string[];
}

export interface SlackFileContextResult {
  file_id: string;
  file?: Record<string, unknown>;
  comments: Array<Record<string, unknown>>;
  errors: string[];
}

export type SlackAssistantSearchResults = NonNullable<SlackAssistantSearchResult["results"]>;
export type SlackAssistantSearchMessageSummary = SlackAssistantSearchResults["messages"][number];
export type SlackAssistantSearchFileSummary = SlackAssistantSearchResults["files"][number];
export type SlackAssistantSearchChannelSummary = SlackAssistantSearchResults["channels"][number];
export type SlackAssistantSearchUserSummary = SlackAssistantSearchResults["users"][number];
