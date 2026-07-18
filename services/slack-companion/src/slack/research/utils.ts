import { redactSecurityText } from "../../security/redaction.js";
import { trimForSlack } from "../format.js";
import type { SlackApiResponse, SlackMessage, SlackParamValue } from "./types.js";

export function slackParams(params: Record<string, SlackParamValue>): URLSearchParams {
  const body = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined) continue;
    body.set(key, Array.isArray(value) ? value.join(",") : String(value));
  }
  return body;
}

export function arrayFrom<T>(record: SlackApiResponse, key: string): T[] {
  const value = record[key];
  return Array.isArray(value) ? value as T[] : [];
}

export function arrayFromRecord<T>(record: Record<string, unknown> | undefined, key: string): T[] {
  const value = record?.[key];
  return Array.isArray(value) ? value as T[] : [];
}

export function nextCursor(response: SlackApiResponse): string | undefined {
  const cursor = response.response_metadata?.next_cursor?.trim();
  return cursor || undefined;
}

export function messageText(message: SlackMessage): string {
  return redactSecurityText(message.text ?? "").replace(/<mailto:([^|>]+)\|[^>]+>/g, "$1");
}

export function safeSnippet(text: string): string {
  return trimForSlack(redactSecurityText(text).replace(/\s+/g, " ").trim(), 700);
}

export function scoreText(text: string, terms: string[]): number {
  const lower = text.toLowerCase();
  return terms.reduce((score, term) => score + (lower.includes(term) ? 1 : 0), 0);
}

export function searchTerms(query: string): string[] {
  const terms = query
    .toLowerCase()
    .replace(/<@[a-z0-9]+>/gi, " ")
    .split(/[^a-z0-9_.-]+/i)
    .map((term) => term.trim())
    .filter((term) => term.length >= 2 && !STOP_WORDS.has(term));
  return unique(terms.length > 0 ? terms : [query.toLowerCase().trim()].filter(Boolean));
}

export function unique<T>(values: T[]): T[] {
  return [...new Set(values)];
}

export function objectValue(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}

export function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

export function normalizeSlackUserName(user: unknown, fallback: string): string {
  const record = objectValue(user);
  const profile = objectValue(record?.profile);
  return stringValue(profile?.display_name)
    ?? stringValue(profile?.real_name)
    ?? stringValue(record?.real_name)
    ?? stringValue(record?.name)
    ?? fallback;
}

export function numberValue(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

export function booleanValue(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

export async function capture<T>(label: string, work: () => Promise<T>): Promise<{ value?: T; error?: string }> {
  try {
    return { value: await work() };
  } catch (error) {
    return { error: `${label}: ${shortError(error)}` };
  }
}

export function scopeSet(header: string | null): Set<string> {
  return new Set((header ?? "")
    .split(",")
    .map((scope) => scope.trim())
    .filter(Boolean));
}

export function searchText(record: Record<string, unknown>): string {
  const text = stringValue(record.text) ?? stringValue(record.content) ?? "";
  return redactSecurityText(text);
}

export function safeOptionalSnippet(value: unknown): string | undefined {
  const text = typeof value === "string" ? safeSnippet(value) : undefined;
  return text || undefined;
}

export function oldestForDays(days: number): string {
  return String(Math.floor(Date.now() / 1000) - days * 24 * 60 * 60);
}

export function boundedDays(value: number | undefined, max = 30): number {
  if (!value || Number.isNaN(value)) return Math.min(14, max);
  return Math.max(1, Math.min(max, Math.floor(value)));
}

export function boundedLimit(value: number | undefined, fallback: number): number {
  if (!value || Number.isNaN(value)) return fallback;
  return Math.max(1, Math.min(50, Math.floor(value)));
}

export function isoFromSlackTs(ts: string): string {
  return new Date(Number(ts.split(".")[0]) * 1000).toISOString();
}

export function shortError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return message.replace(/\s+/g, " ").slice(0, 300);
}

const STOP_WORDS = new Set([
  "about",
  "after",
  "am",
  "and",
  "an",
  "app",
  "are",
  "as",
  "be",
  "been",
  "by",
  "can",
  "do",
  "for",
  "from",
  "has",
  "have",
  "he",
  "how",
  "if",
  "in",
  "installed",
  "into",
  "is",
  "it",
  "last",
  "looking",
  "me",
  "my",
  "of",
  "on",
  "or",
  "our",
  "pm",
  "please",
  "to",
  "slack",
  "talking",
  "that",
  "the",
  "this",
  "two",
  "was",
  "what",
  "when",
  "where",
  "who",
  "we",
  "with",
  "weeks",
  "you",
]);
