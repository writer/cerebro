import type { AgentTool } from "@earendil-works/pi-agent-core";
import { trimForSlack } from "../../slack/format.js";
import { annotateSpan, withTelemetrySpan } from "../../telemetry.js";
import { securityAgentToolMetadata } from "./tool-metadata.js";

const jsonSafeOmit = Symbol("jsonSafeOmit");
export const TOOL_DETAILS_MAX_CHARS = 20_000;

export interface ToolResultObserver {
  recordToolResult(toolName: string, result: unknown, latencyMs: number): { evidenceReceipt?: string } | undefined;
  recordToolFailure(toolName: string, latencyMs: number): void;
}

export function instrumentTools(tools: AgentTool[], observer?: ToolResultObserver): AgentTool[] {
  return tools.map((tool) => instrumentTool(tool, observer));
}

export function toolResult(details: unknown) {
  const safeDetails = boundedToolDetails(details);
  return {
    content: [{ type: "text" as const, text: trimForSlack(JSON.stringify(safeDetails, null, 2), 6000) }],
    details: safeDetails,
  };
}

export function boundedToolDetails(details: unknown, maxChars = TOOL_DETAILS_MAX_CHARS): unknown {
  const limit = Math.max(1_000, Math.floor(maxChars));
  const safeDetails = jsonSafeValue(details);
  const serialized = JSON.stringify(safeDetails);
  if (serialized.length <= limit) return safeDetails;

  const meta = {
    truncated: true,
    original_chars: serialized.length,
    returned_char_limit: limit,
    note: "Tool details were bounded before model delivery. Narrow the query for omitted rows or fields.",
  };
  let compactLimit = Math.max(500, limit - 600);
  for (let attempt = 0; attempt < 6; attempt += 1) {
    const budget = { remaining: compactLimit, truncated: false };
    const compacted = compactJsonValue(safeDetails, budget);
    const compactedRecord = objectValue(compacted);
    const bounded = compactedRecord
      ? { ...compactedRecord, tool_result_meta: meta }
      : { value: compacted, tool_result_meta: meta };
    const boundedLength = JSON.stringify(bounded).length;
    if (boundedLength <= limit) return bounded;
    compactLimit = Math.max(500, compactLimit - (boundedLength - limit) - 500);
  }
  return boundedPreview(serialized, meta, limit);
}

function boundedPreview(serialized: string, meta: Record<string, unknown>, limit: number): Record<string, unknown> {
  let low = 0;
  let high = serialized.length;
  let best = "";
  while (low <= high) {
    const middle = Math.floor((low + high) / 2);
    const preview = serialized.slice(0, middle);
    const candidate = { preview, tool_result_meta: meta };
    if (JSON.stringify(candidate).length <= limit) {
      best = preview;
      low = middle + 1;
    } else {
      high = middle - 1;
    }
  }
  return { preview: best, tool_result_meta: meta };
}

export async function safeToolResult(work: () => Promise<unknown>) {
  try {
    return toolResult(await work());
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return toolResult({ error: message.replace(/\s+/g, " ").slice(0, 500) });
  }
}

export function objectValue(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}

export function hasUsablePartialToolEvidence(details: Record<string, unknown> | undefined): boolean {
  if (details?.status !== "partial") return false;
  return [details.facts, details.records].some((value) => Array.isArray(value) && value.length > 0);
}

function instrumentTool(tool: AgentTool, observer?: ToolResultObserver): AgentTool {
  return {
    ...tool,
    execute: async (...args: Parameters<AgentTool["execute"]>) => withTelemetrySpan("assistant.tool.execute", {
      component: "assistant-tools",
      operation: "execute",
      "tool.name": tool.name,
      ...toolTelemetryAttributes(tool.name),
    }, async (span) => {
      const startedAt = Date.now();
      let result;
      try {
        result = await tool.execute(...args);
      } catch (error) {
        observer?.recordToolFailure(tool.name, Date.now() - startedAt);
        throw error;
      }
      const observation = observer?.recordToolResult(tool.name, result, Date.now() - startedAt);
      result = observation?.evidenceReceipt ? attachEvidenceReceipt(result, observation.evidenceReceipt) : result;
      const details = objectValue((result as { details?: unknown })?.details);
      annotateSpan(span, {
        "tool.result.error_present": Boolean(details?.error),
        "tool.result.success": details?.success,
        "tool.result.stored": details?.stored,
      });
      return result;
    }, {
      statusForResult: (result) => {
        const details = objectValue((result as { details?: unknown })?.details);
        return details?.error || details?.success === false
          ? hasUsablePartialToolEvidence(details) ? "completed" : "failed"
          : "completed";
      },
      errorEventName: "assistant.tool.error",
    }),
  };
}

function attachEvidenceReceipt<T>(result: T, evidenceReceipt: string): T {
  const value = objectValue(result);
  if (!value) return result;
  const details = objectValue(value.details);
  const content = Array.isArray(value.content) ? [...value.content] : [];
  const partial = hasUsablePartialToolEvidence(details);
  content.push({
    type: "text",
    text: partial
      ? `Partial evidence receipt: ${evidenceReceipt}. The receipt covers the non-empty facts and records returned above. The error applies only to the missing coverage; do not treat the whole source as unavailable.`
      : `Evidence receipt: ${evidenceReceipt}`,
  });
  return {
    ...value,
    content,
    details: {
      ...(details ?? {}),
      evidence_receipt: evidenceReceipt,
      ...(partial ? {
        evidence_status: "partial",
        returned_evidence_usable: true,
        evidence_coverage: "Receipt covers returned facts and records only; the error describes missing coverage.",
      } : {}),
    },
  } as T;
}

function toolTelemetryAttributes(name: string): Record<string, string> {
  const metadata = securityAgentToolMetadata(name);
  return {
    "tool.family": metadata.family,
    "tool.authority": metadata.authority,
    "tool.credential_scope": metadata.credentialScope,
    "tool.retry": metadata.retry,
    "tool.side_effect": metadata.sideEffect,
    "tool.target_source": metadata.targetSource,
  };
}

function jsonSafeValue(value: unknown, seen = new WeakSet<object>(), omitUndefined = false): unknown {
  if (value === undefined) return omitUndefined ? jsonSafeOmit : null;
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") return Number.isFinite(value) ? value : String(value);
  if (typeof value === "bigint") return value.toString();
  if (typeof value === "function") return "[Function]";
  if (typeof value === "symbol") return String(value);
  if (value instanceof Date) return value.toISOString();
  if (value instanceof Error) return { name: value.name, message: value.message };
  if (typeof value !== "object") return value;
  if (seen.has(value)) return "[Circular]";
  seen.add(value);
  if (Array.isArray(value)) return value.map((item) => jsonSafeValue(item, seen));
  if (value instanceof Set) return [...value].map((item) => jsonSafeValue(item, seen));
  if (value instanceof Map) {
    return [...value.entries()].map(([key, item]) => ({
      key: jsonSafeValue(key, seen),
      value: jsonSafeValue(item, seen),
    }));
  }
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>)
      .map(([key, item]) => [key, jsonSafeValue(item, seen, true)] as const)
      .filter((entry): entry is readonly [string, unknown] => entry[1] !== jsonSafeOmit),
  );
}

function compactJsonValue(value: unknown, budget: { remaining: number; truncated: boolean }, depth = 0): unknown {
  if (budget.remaining < 40) {
    budget.truncated = true;
    return "[truncated]";
  }
  if (value === null || typeof value === "boolean" || typeof value === "number") {
    budget.remaining -= JSON.stringify(value).length;
    return value;
  }
  if (typeof value === "string") {
    const max = Math.max(0, Math.min(4_000, budget.remaining - 20));
    const bounded = value.length <= max ? value : `${value.slice(0, Math.max(0, max - 14))}…[truncated]`;
    if (bounded.length < value.length) budget.truncated = true;
    budget.remaining -= bounded.length + 2;
    return bounded;
  }
  if (depth >= 8) {
    budget.truncated = true;
    budget.remaining -= 22;
    return "[max depth reached]";
  }
  if (Array.isArray(value)) {
    const output: unknown[] = [];
    const maxItems = Math.min(value.length, 50);
    for (let index = 0; index < maxItems && budget.remaining >= 40; index += 1) {
      output.push(compactJsonValue(value[index], budget, depth + 1));
    }
    if (output.length < value.length) {
      budget.truncated = true;
      output.push(`[${value.length - output.length} item(s) omitted]`);
    }
    return output;
  }
  const record = objectValue(value);
  if (!record) return String(value);
  const output: Record<string, unknown> = {};
  const entries = Object.entries(record);
  const maxEntries = Math.min(entries.length, 80);
  for (let index = 0; index < maxEntries && budget.remaining >= 40; index += 1) {
    const [key, item] = entries[index]!;
    budget.remaining -= key.length + 4;
    output[key] = compactJsonValue(item, budget, depth + 1);
  }
  if (Object.keys(output).length < entries.length) {
    budget.truncated = true;
    output.tool_result_omitted_fields = entries.length - Object.keys(output).length;
  }
  return output;
}
