import { createHash } from "node:crypto";
import type { AgentGymJson, AgentGymSlackEventV1 } from "./fixture-case.js";
import { AgentGymContractError } from "./index.js";

export type AgentGymSlackInvocationRoute =
  | "assistant_turn"
  | "interaction"
  | "publish_home";

export interface AgentGymSlackInvocationV1 {
  readonly action?: {
    readonly action_id: string;
    readonly value: string;
  };
  readonly actor_ref: string;
  readonly conversation_ref: string;
  readonly event_ref: string;
  readonly invocation_ref: string;
  readonly occurred_at: string;
  readonly route: AgentGymSlackInvocationRoute;
  readonly schema_version: "agent-gym-slack-invocation/v1";
  readonly text?: string;
}

/** Simulates an App Home open as a request to publish current operator state. */
export function simulateSlackAppHomeOpened(
  event: AgentGymSlackEventV1,
): AgentGymSlackInvocationV1 {
  if (event.kind !== "app_home_opened") invalid("App Home event");
  const payload = object(event.payload);
  const teamId = field(payload, "team_id");
  const userId = field(payload, "user_id");
  if (field(payload, "tab", 20) !== "home") invalid("App Home tab");
  return invocation(event, {
    actor_ref: ref("slack-user", teamId, userId),
    conversation_ref: ref("slack-home", teamId, userId),
    route: "publish_home",
  });
}

/** Simulates normalization of one direct message without contacting Slack. */
export function simulateSlackDirectMessage(
  event: AgentGymSlackEventV1,
): AgentGymSlackInvocationV1 {
  if (event.kind !== "direct_message") invalid("direct-message event");
  const payload = object(event.payload);
  const teamId = field(payload, "team_id");
  const channelId = field(payload, "channel_id");
  if (!/^D[A-Z0-9]+$/u.test(channelId)) invalid("direct-message channel");
  const userId = field(payload, "user_id");
  const messageTs = timestampField(payload, "ts");
  const text = field(payload, "text", 12_000).trim();
  return invocation(event, {
    actor_ref: ref("slack-user", teamId, userId),
    conversation_ref: ref("slack-dm", teamId, channelId, messageTs),
    route: "assistant_turn",
    text,
  });
}

/** Simulates normalization of one Slack app mention without Slack network access. */
export function simulateSlackMention(
  event: AgentGymSlackEventV1,
): AgentGymSlackInvocationV1 {
  if (event.kind !== "mention") invalid("mention event");
  const payload = object(event.payload);
  const teamId = field(payload, "team_id");
  const channelId = field(payload, "channel_id");
  const userId = field(payload, "user_id");
  const messageTs = timestampField(payload, "ts");
  const threadTs = optionalTimestampField(payload, "thread_ts") ?? messageTs;
  const botUserId = field(payload, "bot_user_id");
  const rawText = field(payload, "text", 12_000);
  const mention = `<@${botUserId}>`;
  const text = rawText.replace(mention, "").trim();
  if (!rawText.includes(mention) || !text) invalid("mention text");
  return invocation(event, {
    actor_ref: ref("slack-user", teamId, userId),
    conversation_ref: ref("slack-thread", teamId, channelId, threadTs),
    route: "assistant_turn",
    text,
  });
}

/** Simulates a reply bound to the exact existing Slack thread identity. */
export function simulateSlackThreadReply(
  event: AgentGymSlackEventV1,
): AgentGymSlackInvocationV1 {
  if (event.kind !== "thread_reply") invalid("thread-reply event");
  const payload = object(event.payload);
  const teamId = field(payload, "team_id");
  const channelId = field(payload, "channel_id");
  if (!/^[CG][A-Z0-9]+$/u.test(channelId)) invalid("thread-reply channel");
  const userId = field(payload, "user_id");
  const messageTs = timestampField(payload, "ts");
  const threadTs = timestampField(payload, "thread_ts");
  if (threadTs === messageTs) invalid("thread-reply timestamp");
  const text = field(payload, "text", 12_000).trim();
  return invocation(event, {
    actor_ref: ref("slack-user", teamId, userId),
    conversation_ref: ref("slack-thread", teamId, channelId, threadTs),
    route: "assistant_turn",
    text,
  });
}

function invocation(
  event: AgentGymSlackEventV1,
  input: Omit<AgentGymSlackInvocationV1,
    "event_ref" | "invocation_ref" | "occurred_at" | "schema_version">,
): AgentGymSlackInvocationV1 {
  return Object.freeze({
    ...input,
    event_ref: event.event_ref,
    invocation_ref: `slack-invocation://sha256/${digest(JSON.stringify({
      event_ref: event.event_ref,
      ...input,
    }))}`,
    occurred_at: event.occurred_at,
    schema_version: "agent-gym-slack-invocation/v1",
  });
}

function digest(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
function field(
  payload: Readonly<Record<string, AgentGymJson>>,
  name: string,
  maximum = 240,
): string {
  const value = payload[name];
  if (typeof value !== "string" || !value.trim() || value.length > maximum
    || /[\u0000-\u001f\u007f]/u.test(value)) invalid(name);
  return value;
}
function object(value: AgentGymJson): Readonly<Record<string, AgentGymJson>> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) invalid("payload");
  return value;
}
function optionalTimestampField(
  payload: Readonly<Record<string, AgentGymJson>>,
  name: string,
): string | undefined {
  return payload[name] === undefined ? undefined : timestampField(payload, name);
}
function ref(kind: string, ...parts: readonly string[]): string {
  return `${kind}://sha256/${digest(parts.join(":"))}`;
}
function timestampField(
  payload: Readonly<Record<string, AgentGymJson>>,
  name: string,
): string {
  const value = field(payload, name, 40);
  if (!/^\d{10,16}\.\d{6}$/u.test(value)) invalid(name);
  return value;
}
function invalid(fieldName: string): never {
  throw new AgentGymContractError(`Agent gym Slack ${fieldName} is invalid.`);
}
