import type { AppConfig } from "../config/index.js";
import { recordMetric, telemetryEvent } from "../telemetry.js";
import type { SecurityAssistantAnswer, SecurityAssistantInput } from "./security-assistant-types.js";

export interface AssistantPromptPreflightResult {
  ok: boolean;
  size: number;
  limit: number;
}

export interface AssistantPromptCompactionResult {
  userText: string;
  preflight: AssistantPromptPreflightResult;
  compacted: boolean;
  originalSize: number;
}

export function promptPreflight(config: AppConfig, systemText: string, userText: string): AssistantPromptPreflightResult {
  const limit = Math.max(8_000, config.triage.promptMaxChars);
  const size = systemText.length + userText.length;
  return { ok: size <= limit, size, limit };
}

export function userPromptWithPreflightCompaction(input: {
  config: AppConfig;
  systemText: string;
  threadContext: string;
  buildUserText: (threadContext: string) => string;
  researchTrail: string[];
}): AssistantPromptCompactionResult {
  const userText = input.buildUserText(input.threadContext);
  const preflight = promptPreflight(input.config, input.systemText, userText);
  if (preflight.ok || !input.threadContext.trim()) {
    return { userText, preflight, compacted: false, originalSize: preflight.size };
  }

  const fixedUserText = input.buildUserText("");
  const fixedSize = input.systemText.length + fixedUserText.length;
  const limit = preflight.limit;
  const targetSize = Math.min(input.config.triage.promptCompactionTargetChars, limit - 500);
  const threadBudget = Math.max(0, targetSize - fixedSize);
  if (threadBudget < 800) {
    return { userText, preflight, compacted: false, originalSize: preflight.size };
  }

  const compactedThreadContext = compactThreadContext(input.threadContext, threadBudget);
  const compactedUserText = input.buildUserText(compactedThreadContext);
  const compactedPreflight = promptPreflight(input.config, input.systemText, compactedUserText);
  if (compactedPreflight.size < preflight.size) {
    telemetryEvent("assistant.prompt_preflight.compacted", {
      component: "security-assistant",
      operation: "prompt_preflight",
      "assistant.prompt.original_size_chars": preflight.size,
      "assistant.prompt.size_chars": compactedPreflight.size,
      "assistant.prompt.limit_chars": compactedPreflight.limit,
      "assistant.prompt.thread_original_chars": input.threadContext.length,
      "assistant.prompt.thread_compacted_chars": compactedThreadContext.length,
    });
    recordMetric("cerebro_slack_companion_prompt_preflight_total", { outcome: compactedPreflight.ok ? "compacted_ok" : "compacted_blocked" }, 1);
    input.researchTrail.push(`prompt_preflight: compacted thread context (${input.threadContext.length}/${compactedThreadContext.length} chars)`);
  }
  return {
    userText: compactedUserText,
    preflight: compactedPreflight,
    compacted: compactedPreflight.size < preflight.size,
    originalSize: preflight.size,
  };
}

export function oversizedPromptAnswer(
  _input: SecurityAssistantInput,
  preflight: AssistantPromptPreflightResult,
  researchTrail: string[],
): SecurityAssistantAnswer {
  telemetryEvent("assistant.prompt_preflight.blocked", {
    component: "security-assistant",
    operation: "prompt_preflight",
    "assistant.prompt.size_chars": preflight.size,
    "assistant.prompt.limit_chars": preflight.limit,
  });
  recordMetric("cerebro_slack_companion_prompt_preflight_total", { outcome: "blocked" }, 1);
  const message = [
    `I stopped before calling the model because the assembled request is too large (${preflight.size} chars, limit ${preflight.limit}).`,
    "Ask for a narrower source, runtime, repo, finding, or time window and I can run the check safely.",
  ].join(" ");
  return {
    answer: message,
    messages: [message],
    reaction: "warning",
    keyPoints: ["Prompt preflight blocked an oversized request."],
    evidence: [],
    actionsTaken: ["Checked prompt size before model execution."],
    nextActions: ["Narrow the source, runtime, repo, finding, or time window."],
    research: [...researchTrail, `prompt_preflight: blocked (${preflight.size}/${preflight.limit} chars)`],
    memoryUpdates: [],
    source: "blocked",
  };
}

function compactThreadContext(threadContext: string, maxChars: number): string {
  const normalized = threadContext.replace(/\s+\n/g, "\n").trim();
  if (normalized.length <= maxChars) return normalized;
  const markerBudget = 180;
  const contentBudget = Math.max(0, maxChars - markerBudget);
  const lines = normalized.split(/\n+/).map((line) => line.trim()).filter(Boolean);
  const kept: string[] = [];
  let used = 0;
  for (let index = lines.length - 1; index >= 0; index -= 1) {
    const line = lines[index]!;
    const nextUsed = used + line.length + (kept.length > 0 ? 1 : 0);
    if (nextUsed > contentBudget) break;
    kept.unshift(line);
    used = nextUsed;
  }
  const omittedLines = Math.max(0, lines.length - kept.length);
  const keptText = kept.join("\n");
  const omittedChars = Math.max(0, normalized.length - keptText.length);
  return [
    `[Older Slack thread context omitted: ${omittedLines} line(s), ${omittedChars} char(s).]`,
    keptText,
  ].filter(Boolean).join("\n");
}
