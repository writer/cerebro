import type { SlackThreadScratchpadPort } from "@writer/cerebro-slack-companion";
import type { AssistantTurnHostAdapter } from "../assistant-turn.js";
import type { FileAgentDeliveryOutbox } from "./agent-delivery-outbox.js";
import type { SlackRuntimeConfig } from "./config.js";
import type { FileOutcomeStore } from "./outcome-store.js";
import type { FileSlackIngressQueue } from "./slack-ingress-store.js";
import type { FileSlackThreadRouteStore } from "./slack-thread-route-store.js";
import {
  type AssistantQuestionService,
  handleSlackMention,
  handleSlackThreadReply,
  type SlackMentionClient,
} from "./slack-runtime.js";

const INPUT_SCHEMA_VERSION = "slack-event-envelope/v1";
const OUTPUT_SCHEMA_VERSION = "slack-transport-result/v1";
const MAX_INPUT_TEXT_BYTES = 64 * 1024;

type PostMessageInput = Parameters<SlackMentionClient["chat"]["postMessage"]>[0];
type UpdateMessageInput = Parameters<SlackMentionClient["chat"]["update"]>[0];
type RepliesInput = Parameters<SlackMentionClient["conversations"]["replies"]>[0];

export interface SlackTransportAppMentionEvent {
  channel: string;
  text: string;
  thread_ts?: string;
  ts: string;
  type: "app_mention";
  user: string;
}

export interface SlackTransportThreadReplyEvent {
  channel: string;
  text: string;
  thread_ts: string;
  ts: string;
  type: "message";
  user: string;
}

export interface SlackTransportEnvelope {
  authorizations: readonly [{ user_id: string }, ...Array<{ user_id: string }>];
  event: SlackTransportAppMentionEvent | SlackTransportThreadReplyEvent;
  event_id?: string;
  schema_version: typeof INPUT_SCHEMA_VERSION;
  team_id: string;
  type: "event_callback";
}

export interface SlackTransportMetadata {
  event_payload: Record<string, string>;
  event_type: string;
}

export interface SlackTransportMessage {
  metadata?: SlackTransportMetadata;
  text: string;
  thread_ts?: string;
  ts: string;
  type: "message";
  user: string;
}

export type SlackTransportOperation =
  | {
    method: "chat.postMessage";
    request: {
      channel: string;
      metadata?: SlackTransportMetadata;
      text: string;
      thread_ts: string;
    };
    response: { ts: string };
  }
  | {
    method: "chat.update";
    request: { channel: string; text: string; ts: string };
    response: { ts: string };
  };

export interface SlackTransportResult {
  attempt: number;
  event_id?: string;
  handled: boolean;
  messages: SlackTransportMessage[];
  operations: SlackTransportOperation[];
  schema_version: typeof OUTPUT_SCHEMA_VERSION;
  thread: { channel: string; thread_ts: string };
}

export interface OffSlackTransportDependencies {
  agentDeliveries?: FileAgentDeliveryOutbox;
  config: SlackRuntimeConfig;
  host: AssistantTurnHostAdapter;
  ingressQueue: FileSlackIngressQueue;
  outcomes: FileOutcomeStore;
  questions: AssistantQuestionService;
  scratchpads?: SlackThreadScratchpadPort;
  threadRoutes: FileSlackThreadRouteStore;
}

interface StoredSlackMessage extends SlackTransportMessage {
  channel: string;
  rootTs: string;
}

export class InMemorySlackWebApi {
  private botUserId?: string;
  private lastTimestampMicros = 0n;
  private readonly messages: StoredSlackMessage[] = [];
  private readonly operations: SlackTransportOperation[] = [];

  readonly client: SlackMentionClient = {
    chat: {
      postMessage: async (input) => this.postMessage(input),
      update: async (input) => this.update(input),
    },
    conversations: {
      replies: async (input) => this.replies(input),
    },
  };

  bindBotUser(userId: string): void {
    requireSlackId(userId, "bot user");
    this.botUserId = userId;
  }

  operationCount(): number {
    return this.operations.length;
  }

  operationsAfter(index: number): SlackTransportOperation[] {
    if (!Number.isSafeInteger(index) || index < 0 || index > this.operations.length) {
      throw new Error("The Slack operation cursor is invalid.");
    }
    return structuredClone(this.operations.slice(index));
  }

  recordIncoming(
    teamId: string,
    event: SlackTransportAppMentionEvent | SlackTransportThreadReplyEvent,
  ): void {
    requireSlackId(teamId, "team");
    const rootTs = event.type === "message" ? event.thread_ts : event.thread_ts ?? event.ts;
    const existing = this.messages.find((message) =>
      message.channel === event.channel && message.ts === event.ts
    );
    const candidate: StoredSlackMessage = {
      channel: event.channel,
      rootTs,
      text: event.text,
      ...(event.ts === rootTs ? {} : { thread_ts: rootTs }),
      ts: event.ts,
      type: "message",
      user: event.user,
    };
    if (existing) {
      if (JSON.stringify(existing) !== JSON.stringify(candidate)) {
        throw new Error("A Slack event timestamp was reused with different message content.");
      }
      return;
    }
    this.observeTimestamp(event.ts);
    this.messages.push(candidate);
  }

  thread(channel: string, threadTs: string): SlackTransportMessage[] {
    return this.messages
      .filter((message) => message.channel === channel && message.rootTs === threadTs)
      .sort((left, right) => compareSlackTimestamps(left.ts, right.ts))
      .map(({ channel: _channel, rootTs: _rootTs, ...message }) => structuredClone(message));
  }

  private async postMessage(input: PostMessageInput): Promise<{ ts?: string }> {
    const botUserId = this.botUserId;
    if (!botUserId) throw new Error("The in-memory Slack client has no bound bot user.");
    requireSlackId(input.channel, "channel");
    requireSlackTimestamp(input.thread_ts, "thread timestamp");
    requireText(input.text, "Slack message text");
    const ts = this.nextTimestamp();
    const metadata = input.metadata === undefined
      ? undefined
      : structuredClone(input.metadata) as SlackTransportMetadata;
    this.messages.push({
      channel: input.channel,
      ...(metadata === undefined ? {} : { metadata }),
      rootTs: input.thread_ts,
      text: input.text,
      thread_ts: input.thread_ts,
      ts,
      type: "message",
      user: botUserId,
    });
    this.operations.push({
      method: "chat.postMessage",
      request: {
        channel: input.channel,
        ...(metadata === undefined ? {} : { metadata: structuredClone(metadata) }),
        text: input.text,
        thread_ts: input.thread_ts,
      },
      response: { ts },
    });
    return { ts };
  }

  private async update(input: UpdateMessageInput): Promise<{ ts: string }> {
    requireSlackId(input.channel, "channel");
    requireSlackTimestamp(input.ts, "message timestamp");
    requireText(input.text, "Slack message text");
    const message = this.messages.find((candidate) =>
      candidate.channel === input.channel && candidate.ts === input.ts
    );
    if (!message || message.user !== this.botUserId) {
      throw new Error("Slack cannot update an unknown assistant message.");
    }
    message.text = input.text;
    this.operations.push({
      method: "chat.update",
      request: structuredClone(input),
      response: { ts: input.ts },
    });
    return { ts: input.ts };
  }

  private async replies(input: RepliesInput): Promise<{
    messages?: SlackTransportMessage[];
    response_metadata?: { next_cursor?: string };
  }> {
    requireSlackId(input.channel, "channel");
    requireSlackTimestamp(input.ts, "thread timestamp");
    if (input.oldest !== undefined) requireSlackTimestamp(input.oldest, "oldest timestamp");
    const offset = parseCursor(input.cursor);
    const candidates = this.thread(input.channel, input.ts)
      .filter((message) => input.oldest === undefined
        || (input.inclusive
          ? compareSlackTimestamps(message.ts, input.oldest) >= 0
          : compareSlackTimestamps(message.ts, input.oldest) > 0))
      .map((message) => input.include_all_metadata
        ? message
        : withoutMetadata(message));
    const messages = candidates.slice(offset, offset + input.limit);
    const nextOffset = offset + messages.length;
    return {
      messages,
      ...(nextOffset < candidates.length
        ? { response_metadata: { next_cursor: String(nextOffset) } }
        : {}),
    };
  }

  private nextTimestamp(): string {
    this.lastTimestampMicros += 1n;
    return formatSlackTimestamp(this.lastTimestampMicros);
  }

  private observeTimestamp(value: string): void {
    const timestamp = parseSlackTimestamp(value);
    if (timestamp > this.lastTimestampMicros) this.lastTimestampMicros = timestamp;
  }
}

export class OffSlackTransportAdapter {
  private readonly attempts = new Map<string, number>();

  constructor(
    private readonly dependencies: OffSlackTransportDependencies,
    readonly slack = new InMemorySlackWebApi(),
  ) {}

  async dispatch(input: unknown): Promise<SlackTransportResult> {
    const envelope = parseSlackTransportEnvelope(input);
    const event = envelope.event;
    const botUserId = envelope.authorizations[0].user_id;
    this.slack.bindBotUser(botUserId);
    this.slack.recordIncoming(envelope.team_id, event);
    const operationCursor = this.slack.operationCount();
    const requestKey = [envelope.team_id, event.channel, event.thread_ts ?? event.ts, event.ts]
      .join(":");
    const attempt = (this.attempts.get(requestKey) ?? 0) + 1;
    this.attempts.set(requestKey, attempt);
    const common = {
      agentDeliveries: this.dependencies.agentDeliveries,
      client: this.slack.client,
      config: this.dependencies.config,
      host: this.dependencies.host,
      ingressQueue: this.dependencies.ingressQueue,
      outcomes: this.dependencies.outcomes,
      priorDeliveryAttempt: attempt > 1,
      questions: this.dependencies.questions,
      scratchpads: this.dependencies.scratchpads,
    };
    const handled = event.type === "app_mention"
      ? await handleSlackMention({
        ...common,
        event: {
          botUserId,
          channel: event.channel,
          eventTs: event.ts,
          hasThreadContext: event.thread_ts !== undefined,
          teamId: envelope.team_id,
          text: event.text,
          threadTs: event.thread_ts ?? event.ts,
          userId: event.user,
        },
        threadRoutes: this.dependencies.threadRoutes,
      })
      : await handleSlackThreadReply({
        ...common,
        botUserId,
        event,
        teamId: envelope.team_id,
        threadRoutes: this.dependencies.threadRoutes,
      });
    const threadTs = event.thread_ts ?? event.ts;
    return {
      attempt,
      ...(envelope.event_id === undefined ? {} : { event_id: envelope.event_id }),
      handled,
      messages: this.slack.thread(event.channel, threadTs),
      operations: this.slack.operationsAfter(operationCursor),
      schema_version: OUTPUT_SCHEMA_VERSION,
      thread: { channel: event.channel, thread_ts: threadTs },
    };
  }

  async dispatchJsonLine(line: string): Promise<string> {
    if (!line.trim()) throw new Error("A Slack transport JSONL record cannot be blank.");
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      throw new Error("A Slack transport JSONL record is not valid JSON.");
    }
    return JSON.stringify(await this.dispatch(parsed));
  }
}

export async function runOffSlackTransportJsonl(
  lines: AsyncIterable<string>,
  adapter: OffSlackTransportAdapter,
  write: (line: string) => void | Promise<void>,
): Promise<void> {
  for await (const line of lines) {
    if (!line.trim()) continue;
    await write(`${await adapter.dispatchJsonLine(line)}\n`);
  }
}

export function parseSlackTransportEnvelope(input: unknown): SlackTransportEnvelope {
  const envelope = record(input, "Slack transport envelope");
  if (envelope.schema_version !== INPUT_SCHEMA_VERSION || envelope.type !== "event_callback") {
    throw new Error("The Slack transport envelope version or type is invalid.");
  }
  const teamId = requireSlackId(envelope.team_id, "team");
  const authorizations = Array.isArray(envelope.authorizations)
    ? envelope.authorizations.map((authorization) => {
      const value = record(authorization, "Slack authorization");
      return { user_id: requireSlackId(value.user_id, "authorized bot user") };
    })
    : [];
  if (authorizations.length === 0) {
    throw new Error("The Slack transport envelope requires an authorized bot user.");
  }
  const botUserId = authorizations[0]!.user_id;
  const rawEvent = record(envelope.event, "Slack event");
  const type = rawEvent.type;
  const channel = requireSlackId(rawEvent.channel, "channel");
  const user = requireSlackId(rawEvent.user, "user");
  const ts = requireSlackTimestamp(rawEvent.ts, "event timestamp");
  const text = requireText(rawEvent.text, "event text");
  if (user === botUserId) throw new Error("The Slack transport event cannot come from its bot.");
  let event: SlackTransportAppMentionEvent | SlackTransportThreadReplyEvent;
  if (type === "app_mention") {
    if (!text.includes(`<@${botUserId}>`)) {
      throw new Error("A Slack app mention must mention the authorized bot user.");
    }
    const threadTs = rawEvent.thread_ts === undefined
      ? undefined
      : requireSlackTimestamp(rawEvent.thread_ts, "thread timestamp");
    event = {
      channel,
      text,
      ...(threadTs === undefined ? {} : { thread_ts: threadTs }),
      ts,
      type,
      user,
    };
  } else if (type === "message") {
    if (
      rawEvent.subtype !== undefined
      || rawEvent.bot_id !== undefined
      || rawEvent.app_id !== undefined
      || text.includes(`<@${botUserId}>`)
    ) throw new Error("The Slack thread reply must be an unadorned human message.");
    event = {
      channel,
      text,
      thread_ts: requireSlackTimestamp(rawEvent.thread_ts, "thread timestamp"),
      ts,
      type,
      user,
    };
  } else {
    throw new Error("The Slack transport supports app mentions and human thread replies only.");
  }
  const eventId = envelope.event_id === undefined
    ? undefined
    : requireSlackEventId(envelope.event_id);
  return {
    authorizations: [authorizations[0]!, ...authorizations.slice(1)],
    event,
    ...(eventId === undefined ? {} : { event_id: eventId }),
    schema_version: INPUT_SCHEMA_VERSION,
    team_id: teamId,
    type: "event_callback",
  };
}

function withoutMetadata(message: SlackTransportMessage): SlackTransportMessage {
  const { metadata: _metadata, ...plain } = message;
  return plain;
}

function parseCursor(cursor?: string): number {
  if (cursor === undefined || cursor === "") return 0;
  if (!/^\d+$/u.test(cursor)) throw new Error("The Slack reply cursor is invalid.");
  const offset = Number(cursor);
  if (!Number.isSafeInteger(offset)) throw new Error("The Slack reply cursor is invalid.");
  return offset;
}

function requireSlackId(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^[A-Z][A-Z0-9]{1,31}$/u.test(value)) {
    throw new Error(`The Slack ${label} ID is invalid.`);
  }
  return value;
}

function requireSlackEventId(value: unknown): string {
  if (typeof value !== "string" || !/^Ev[A-Za-z0-9]{1,62}$/u.test(value)) {
    throw new Error("The Slack event ID is invalid.");
  }
  return value;
}

function requireSlackTimestamp(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^\d{1,12}\.\d{6}$/u.test(value)) {
    throw new Error(`The Slack ${label} is invalid.`);
  }
  return value;
}

function requireText(value: unknown, label: string): string {
  if (
    typeof value !== "string"
    || !value.trim()
    || Buffer.byteLength(value, "utf8") > MAX_INPUT_TEXT_BYTES
  ) throw new Error(`The ${label} is invalid or exceeds its bound.`);
  return value;
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`The ${label} is invalid.`);
  }
  return value as Record<string, unknown>;
}

function compareSlackTimestamps(left: string, right: string): number {
  const first = parseSlackTimestamp(left);
  const second = parseSlackTimestamp(right);
  return first < second ? -1 : first > second ? 1 : 0;
}

function parseSlackTimestamp(value: string): bigint {
  requireSlackTimestamp(value, "timestamp");
  const [seconds, micros] = value.split(".");
  return BigInt(seconds!) * 1_000_000n + BigInt(micros!);
}

function formatSlackTimestamp(value: bigint): string {
  const seconds = value / 1_000_000n;
  const micros = value % 1_000_000n;
  return `${seconds}.${micros.toString().padStart(6, "0")}`;
}
