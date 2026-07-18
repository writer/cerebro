import { trimForSlack } from "../slack/format.js";

export function shortError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return trimForSlack(message.replace(/\s+/g, " ").trim(), 300);
}

export function unique<T>(values: T[]): T[] {
  return [...new Set(values)];
}
