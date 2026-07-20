import type { SlackIngressEnvelope } from "../contracts.js";
import type {
  SlackEventCallbackEnvelope,
  SlackEventNormalizationInput,
  SlackEventNormalizer,
  SlackEventsApiEnvelope,
  SlackInteractiveEnvelope,
  SlackInvocationEnvelope,
  SlackInvocationNormalizationInput,
  SlackInvocationNormalizer,
  SlackSlashCommandEnvelope,
  SlackSocketModeEnvelope,
} from "./contracts.js";

export class StructuralSlackEventNormalizer implements SlackEventNormalizer {
  normalize(input: SlackEventNormalizationInput): SlackIngressEnvelope {
    const { envelope, payload, received_at: receivedAt, route } = input;
    const eventType = requiredString(envelope.event, "type");
    const conversationId = requiredString(envelope.event, "channel");
    const eventTimestamp = requiredString(envelope.event, "ts");
    const threadId = optionalString(envelope.event, "thread_ts") ?? eventTimestamp;

    return {
      app_id: envelope.api_app_id,
      binding_id: route.binding_id,
      conversation_id: conversationId,
      event_id: envelope.event_id,
      event_type: eventType,
      payload_digest: payload.digest,
      payload_ref: payload.payload_ref,
      received_at: receivedAt,
      required_capabilities: route.required_capabilities,
      retention_policy_ref: route.retention_policy_ref,
      run_kind: route.run_kind,
      subject_ref: `slack-thread:${conversationId}:${threadId}`,
      tenant_id: route.tenant_id,
      thread_id: threadId,
    };
  }
}

export class StructuralSlackInvocationNormalizer
  implements SlackInvocationNormalizer
{
  normalize(input: SlackInvocationNormalizationInput): SlackIngressEnvelope {
    const { envelope, payload, received_at: receivedAt, route } = input;
    if (envelope.type === "slash_command") {
      return {
        app_id: envelope.api_app_id,
        binding_id: route.binding_id,
        conversation_id: envelope.channel_id,
        event_id: `slash_command:${envelope.trigger_id}`,
        event_type: `slash_command:${envelope.command}`,
        payload_digest: payload.digest,
        payload_ref: payload.payload_ref,
        received_at: receivedAt,
        required_capabilities: route.required_capabilities,
        retention_policy_ref: route.retention_policy_ref,
        run_kind: route.run_kind,
        subject_ref: `slack-command:${envelope.channel_id}:${envelope.trigger_id}`,
        tenant_id: route.tenant_id,
        thread_id: envelope.trigger_id,
      };
    }

    const conversationId = envelope.conversation_id ?? route.conversation_id;
    if (conversationId === undefined) {
      throw new Error("interactive conversation identity is required");
    }
    const threadId = envelope.thread_id ?? route.thread_id ?? envelope.trigger_id;
    return {
      app_id: envelope.api_app_id,
      binding_id: route.binding_id,
      conversation_id: conversationId,
      event_id: `interactive:${envelope.trigger_id}`,
      event_type: `interactive:${envelope.interaction_type}:${envelope.action_id}`,
      payload_digest: payload.digest,
      payload_ref: payload.payload_ref,
      received_at: receivedAt,
      required_capabilities: route.required_capabilities,
      retention_policy_ref: route.retention_policy_ref,
      run_kind: route.run_kind,
      subject_ref: `slack-thread:${conversationId}:${threadId}`,
      tenant_id: route.tenant_id,
      thread_id: threadId,
    };
  }
}

export function parseEventsApiEnvelope(
  rawBody: Uint8Array,
): SlackEventsApiEnvelope {
  const value = parseObject(rawBody);
  const type = requiredString(value, "type");
  if (type === "url_verification") {
    return {
      challenge: requiredString(value, "challenge"),
      type,
    };
  }
  if (type !== "event_callback") {
    throw new Error("unsupported Events API envelope type");
  }

  const event = requiredObject(value, "event");
  return {
    api_app_id: requiredString(value, "api_app_id"),
    event: { ...event, type: requiredString(event, "type") },
    event_id: requiredString(value, "event_id"),
    event_time: requiredNumber(value, "event_time"),
    team_id: requiredString(value, "team_id"),
    type,
  };
}

export function parseSocketModeEnvelope(
  rawBody: Uint8Array,
): SlackSocketModeEnvelope {
  const value = parseObject(rawBody);
  const type = requiredString(value, "type");
  if (
    type !== "events_api" &&
    type !== "interactive" &&
    type !== "slash_commands"
  ) {
    throw new Error("unsupported Socket Mode envelope type");
  }
  if (!("payload" in value)) {
    throw new Error("payload is required");
  }
  const acceptsResponsePayload = optionalBoolean(
    value,
    "accepts_response_payload",
  );
  const retryAttempt = optionalNumber(value, "retry_attempt");
  const retryReason = optionalString(value, "retry_reason");
  return {
    ...(acceptsResponsePayload === undefined
      ? {}
      : { accepts_response_payload: acceptsResponsePayload }),
    envelope_id: requiredString(value, "envelope_id"),
    payload: value.payload,
    ...(retryAttempt === undefined ? {} : { retry_attempt: retryAttempt }),
    ...(retryReason === undefined ? {} : { retry_reason: retryReason }),
    type,
  };
}

export function parseSlashCommandEnvelope(
  rawBody: Uint8Array,
): SlackSlashCommandEnvelope {
  const form = parseForm(rawBody);
  return {
    api_app_id: requiredFormValue(form, "api_app_id"),
    channel_id: requiredFormValue(form, "channel_id"),
    command: requiredFormValue(form, "command"),
    team_id: requiredFormValue(form, "team_id"),
    text: optionalFormValue(form, "text") ?? "",
    trigger_id: requiredFormValue(form, "trigger_id"),
    type: "slash_command",
    user_id: requiredFormValue(form, "user_id"),
  };
}

export function parseInteractiveEnvelope(
  rawBody: Uint8Array,
): SlackInteractiveEnvelope {
  const form = parseForm(rawBody);
  return interactiveEnvelopeFromValue(
    parseJsonObject(requiredFormValue(form, "payload")),
  );
}

export function eventCallbackFromSocketMode(
  envelope: SlackSocketModeEnvelope,
): SlackEventCallbackEnvelope {
  if (envelope.type !== "events_api") {
    throw new Error("unsupported Socket Mode envelope type");
  }
  const payload = envelope.payload;
  if (!isRecord(payload) || payload.type !== "event_callback") {
    throw new Error("Socket Mode payload must contain an event callback");
  }
  const event = requiredObject(payload, "event");
  return {
    api_app_id: requiredString(payload, "api_app_id"),
    event: { ...event, type: requiredString(event, "type") },
    event_id: requiredString(payload, "event_id"),
    event_time: requiredNumber(payload, "event_time"),
    team_id: requiredString(payload, "team_id"),
    type: "event_callback",
  };
}

export function invocationFromSocketMode(
  envelope: SlackSocketModeEnvelope,
): SlackInvocationEnvelope {
  if (envelope.type === "slash_commands") {
    const payload = requiredRecord(envelope.payload, "payload");
    return {
      api_app_id: requiredString(payload, "api_app_id"),
      channel_id: requiredString(payload, "channel_id"),
      command: requiredString(payload, "command"),
      team_id: requiredString(payload, "team_id"),
      text: optionalString(payload, "text") ?? "",
      trigger_id: requiredString(payload, "trigger_id"),
      type: "slash_command",
      user_id: requiredString(payload, "user_id"),
    };
  }
  if (envelope.type !== "interactive") {
    throw new Error("Socket Mode envelope is not an invocation");
  }
  return interactiveEnvelopeFromValue(requiredRecord(envelope.payload, "payload"));
}

function interactiveEnvelopeFromValue(
  value: Record<string, unknown>,
): SlackInteractiveEnvelope {
  const team = requiredObject(value, "team");
  const user = requiredObject(value, "user");
  const channel = optionalObject(value, "channel");
  const container = optionalObject(value, "container");
  const actions = optionalArray(value, "actions");
  const action = actions === undefined
    ? undefined
    : requiredRecord(actions[0], "actions[0]");
  const interactionType = requiredString(value, "type");
  const callbackId = optionalString(value, "callback_id");
  const actionId =
    (action === undefined ? undefined : optionalString(action, "action_id")) ??
    callbackId ??
    interactionType;
  const conversationId =
    optionalString(container ?? {}, "channel_id") ??
    optionalString(channel ?? {}, "id");
  const threadId =
    optionalString(container ?? {}, "thread_ts") ??
    optionalString(container ?? {}, "message_ts");
  return {
    action_id: actionId,
    api_app_id: requiredString(value, "api_app_id"),
    ...(conversationId === undefined ? {} : { conversation_id: conversationId }),
    interaction_type: interactionType,
    team_id: requiredString(team, "id"),
    ...(threadId === undefined ? {} : { thread_id: threadId }),
    trigger_id: requiredString(value, "trigger_id"),
    type: "interactive",
    user_id: requiredString(user, "id"),
  };
}

function parseObject(rawBody: Uint8Array): Record<string, unknown> {
  const parsed = parseJson(Buffer.from(rawBody).toString("utf8"));
  if (!isRecord(parsed)) {
    throw new Error("request body must be a JSON object");
  }
  return parsed;
}

function parseJsonObject(value: string): Record<string, unknown> {
  const parsed = parseJson(value);
  if (!isRecord(parsed)) {
    throw new Error("payload must be a JSON object");
  }
  return parsed;
}

function parseJson(value: string): unknown {
  try {
    return JSON.parse(value);
  } catch {
    throw new Error("request body must be valid JSON");
  }
}

function parseForm(rawBody: Uint8Array): URLSearchParams {
  return new URLSearchParams(Buffer.from(rawBody).toString("utf8"));
}

function requiredFormValue(form: URLSearchParams, field: string): string {
  const values = form.getAll(field);
  if (values.length !== 1 || values[0]?.trim() === "") {
    throw new Error(`${field} must occur once with a non-empty value`);
  }
  return values[0];
}

function optionalFormValue(
  form: URLSearchParams,
  field: string,
): string | undefined {
  const values = form.getAll(field);
  if (values.length === 0) {
    return undefined;
  }
  if (values.length !== 1) {
    throw new Error(`${field} must occur at most once`);
  }
  return values[0];
}

function requiredObject(
  value: Record<string, unknown>,
  field: string,
): Record<string, unknown> {
  const candidate = value[field];
  if (!isRecord(candidate)) {
    throw new Error(`${field} must be an object`);
  }
  return candidate;
}

function requiredRecord(value: unknown, field: string): Record<string, unknown> {
  if (!isRecord(value)) {
    throw new Error(`${field} must be an object`);
  }
  return value;
}

function optionalObject(
  value: Record<string, unknown>,
  field: string,
): Record<string, unknown> | undefined {
  const candidate = value[field];
  if (candidate === undefined) {
    return undefined;
  }
  return requiredRecord(candidate, field);
}

function optionalArray(
  value: Record<string, unknown>,
  field: string,
): unknown[] | undefined {
  const candidate = value[field];
  if (candidate === undefined) {
    return undefined;
  }
  if (!Array.isArray(candidate) || candidate.length === 0) {
    throw new Error(`${field} must be a non-empty array when present`);
  }
  return candidate;
}

function requiredNumber(value: Record<string, unknown>, field: string): number {
  const candidate = value[field];
  if (typeof candidate !== "number" || !Number.isFinite(candidate)) {
    throw new Error(`${field} must be a number`);
  }
  return candidate;
}

function requiredString(value: Record<string, unknown>, field: string): string {
  const candidate = value[field];
  if (typeof candidate !== "string" || candidate.trim() === "") {
    throw new Error(`${field} must be a non-empty string`);
  }
  return candidate;
}

function optionalString(
  value: Record<string, unknown>,
  field: string,
): string | undefined {
  const candidate = value[field];
  if (candidate === undefined) {
    return undefined;
  }
  if (typeof candidate !== "string" || candidate.trim() === "") {
    throw new Error(`${field} must be a non-empty string when present`);
  }
  return candidate;
}

function optionalBoolean(
  value: Record<string, unknown>,
  field: string,
): boolean | undefined {
  const candidate = value[field];
  if (candidate === undefined) {
    return undefined;
  }
  if (typeof candidate !== "boolean") {
    throw new Error(`${field} must be a boolean when present`);
  }
  return candidate;
}

function optionalNumber(
  value: Record<string, unknown>,
  field: string,
): number | undefined {
  const candidate = value[field];
  if (candidate === undefined) {
    return undefined;
  }
  if (typeof candidate !== "number" || !Number.isFinite(candidate)) {
    throw new Error(`${field} must be a number when present`);
  }
  return candidate;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
