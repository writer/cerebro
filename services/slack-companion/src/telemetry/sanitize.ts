import { createHash } from "node:crypto";
import { cleanTelemetryName, compactKeyPart } from "./names.js";
import type { TelemetryAttributes } from "./types.js";

const maxAttributeStringLength = 1024;

export function hashTelemetryId(value: unknown): string {
  const text = String(value ?? "").trim();
  if (!text) return "";
  return createHash("sha256").update(text).digest("hex").slice(0, 16);
}

export function slackTelemetryAttributes(input: {
  channelId?: string;
  userId?: string;
  ts?: string;
  threadTs?: string;
  teamId?: string;
  eventKind?: string;
}): TelemetryAttributes {
  return {
    ...(input.eventKind ? { "slack.event.kind": cleanTelemetryName(input.eventKind) } : {}),
    "slack.channel_id_hash": hashTelemetryId(input.channelId),
    "slack.user_id_hash": hashTelemetryId(input.userId),
    "slack.event_ts_hash": hashTelemetryId(input.ts),
    "slack.thread_ts_hash": hashTelemetryId(input.threadTs),
    "slack.team_id_hash": hashTelemetryId(input.teamId),
    "slack.thread.present": Boolean(input.threadTs),
  };
}

export function telemetryErrorKind(error: unknown): string {
  if (error instanceof Error) {
    if (error.name === "AbortError") return "abort_error";
    if (/timeout|timed out/i.test(error.message)) return "timeout";
    return compactKeyPart(error.name || error.constructor.name || "error");
  }
  if (typeof error === "string") return "error";
  if (error && typeof error === "object" && "name" in error) {
    return compactKeyPart(String((error as { name?: unknown }).name ?? "error"));
  }
  return "error";
}

export function telemetryErrorFingerprint(name: string, error: unknown, attributes: TelemetryAttributes = {}): string {
  const component = String(attributes.component ?? "");
  const operation = String(attributes.operation ?? "");
  return createHash("sha256")
    .update([cleanTelemetryName(name), telemetryErrorKind(error), component, operation].join("|"))
    .digest("hex")
    .slice(0, 16);
}

export function safeAttributeValue(key: string, value: unknown): unknown {
  if (secretLikeKey(key)) return "[redacted]";
  if (rawTextLikeKey(key)) return "[redacted]";
  if (typeof value === "string") return boundString(value, maxAttributeStringLength);
  if (value instanceof Date) return value.toISOString();
  if (typeof value === "bigint") return value.toString();
  if (Array.isArray(value)) {
    return value.slice(0, 20).map((item) => safeAttributeValue(key, item));
  }
  if (value && typeof value === "object") {
    return boundString(JSON.stringify(value), maxAttributeStringLength);
  }
  return value;
}

function secretLikeKey(key: string): boolean {
  const lower = key.toLowerCase();
  return [
    "authorization",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "id_token",
    "token",
    "secret",
    "password",
    "cookie",
    "credential_id",
    "credential_secret",
    "credential_value",
  ].some((fragment) => lower.includes(fragment));
}

function rawTextLikeKey(key: string): boolean {
  const lower = key.toLowerCase();
  if (lower === "event.name" || lower === "operation.name" || lower === "service.name" || lower === "host.name") return false;
  if (/[._-](length|count|size|present|hash|source|status|kind|reaction|route|mode|classification|severity|type|reason|family|enabled)$/.test(lower)) return false;
  return /(^|[._-])(question|prompt|text|message|answer|summary|details|raw|body|payload|content|transcript|cypher|arguments?|args)([._-]|$)/.test(lower);
}

function boundString(value: string, limit: number): string {
  const trimmed = value.trim();
  if (trimmed.length <= limit) return trimmed;
  return `${trimmed.slice(0, limit)}...`;
}
