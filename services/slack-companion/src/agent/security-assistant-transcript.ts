import { redactSecurityText } from "../security/redaction.js";
import { trimForSlack } from "../slack/format.js";

export function compactAgentTranscript(messages: unknown[]): string {
  const compact = messages.slice(-18).map((message) => compactAgentMessage(message)).filter(Boolean);
  return trimForSlack(redactSecurityText(JSON.stringify(compact, null, 2)), 16_000);
}

export function latestAssistantText(messages: unknown[]): string {
  for (let index = messages.length - 1; index >= 0; index -= 1) {
    const message = messages[index] as { role?: string; content?: unknown };
    if (message?.role !== "assistant" || !Array.isArray(message.content)) continue;
    return message.content
      .flatMap((part) => {
        const item = part as { type?: string; text?: unknown };
        return item.type === "text" && typeof item.text === "string" ? [item.text] : [];
      })
      .join("\n")
      .trim();
  }
  return "";
}

function compactAgentMessage(message: unknown): Record<string, unknown> | undefined {
  if (!message || typeof message !== "object") return undefined;
  const record = message as Record<string, unknown>;
  const role = stringField(record, "role") ?? "unknown";
  const toolName = stringField(record, "toolName") ?? stringField(record, "tool_name");
  const parts = Array.isArray(record.content) ? record.content.flatMap(compactMessagePart) : [];
  const result: Record<string, unknown> = { role };
  if (toolName) result.tool_name = toolName;
  if (parts.length > 0) result.content = parts;
  return result;
}

function compactMessagePart(part: unknown): Record<string, unknown>[] {
  if (!part || typeof part !== "object") return [];
  const record = part as Record<string, unknown>;
  const type = stringField(record, "type") ?? "unknown";
  if (type === "text") {
    const text = stringField(record, "text");
    return text ? [{ type, text: trimForSlack(redactSecurityText(text), 2400) }] : [];
  }
  if (type === "toolCall") {
    return [{
      type,
      name: stringField(record, "name") ?? "unknown",
      arguments: trimForSlack(redactSecurityText(JSON.stringify(record.arguments ?? {}, null, 2)), 1600),
    }];
  }
  return [{ type }];
}

function stringField(record: Record<string, unknown>, field: string): string | undefined {
  const value = record[field];
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}
