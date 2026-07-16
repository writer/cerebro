import type { SlackIngressEnvelope } from "../contracts.js";
import type {
  SlackEventCallbackEnvelope,
  SlackEventNormalizationInput,
  SlackEventNormalizer,
  SlackEventsApiEnvelope,
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

function parseObject(rawBody: Uint8Array): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(rawBody).toString("utf8"));
  } catch {
    throw new Error("request body must be valid JSON");
  }
  if (!isRecord(parsed)) {
    throw new Error("request body must be a JSON object");
  }
  return parsed;
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
