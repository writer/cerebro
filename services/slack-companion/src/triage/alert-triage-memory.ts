import { redactAlertText } from "./alert-triage-output.js";
import type { AlertTriageInput, AlertTriageResult } from "./alert-triage-types.js";

export function triageMemoryExpiresAt(result: AlertTriageResult, willAutoReply: boolean): string | undefined {
  if (result.classification === "likely_noise") return undefined;
  const severe = result.severity === "critical" || result.severity === "high";
  const days = result.classification === "likely_security_issue" || severe
    ? 30
    : willAutoReply
      ? 14
      : 7;
  return new Date(Date.now() + days * 86_400_000).toISOString();
}

export function toolsCheckedFromResearch(research: string[]): string[] {
  return [...new Set(research
    .map((item) => item.split(":")[0]?.trim())
    .filter(Boolean))]
    .slice(0, 12) as string[];
}

export function sourceArtifactsFromTriage(input: AlertTriageInput, result: AlertTriageResult): string[] {
  const text = [input.text, result.summary, ...result.evidence, ...result.actionsTaken, ...result.recommendedActions, ...result.research].join(" ");
  return [...new Set([
    ...Array.from(text.matchAll(/\bPR\s*#?\s*(\d+)\b/gi)).map((match) => `pr#${match[1]}`),
    ...Array.from(text.matchAll(/\bsha-[a-f0-9]{7,40}\b/gi)).map((match) => match[0].toLowerCase()),
    ...Array.from(text.matchAll(/\bv\d+\.\d+\.\d+\b/gi)).map((match) => match[0]),
    ...Array.from(text.matchAll(/\b[a-z0-9-]+:\d{1,5}\b/gi)).map((match) => `task-definition:${match[0]}`),
    input.threadTs ? `slack-thread:${input.channelId}:${input.threadTs}` : `slack-message:${input.channelId}:${input.ts}`,
  ])].slice(0, 16);
}

export function topicFromAlert(text: string): string {
  const redacted = redactAlertText(text).replace(/\s+/g, " ").trim();
  return redacted.slice(0, 120) || "Slack security alert";
}
