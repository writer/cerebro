import { trimForSlack } from "../slack/format.js";
import { redactAlertText } from "./alert-triage-output.js";
import { hasSecuritySignal } from "./alert-triage-signals.js";
import type { AlertTriageInput, AlertTriageResult } from "./alert-triage-types.js";

export function heuristicTriage(input: AlertTriageInput, research: string[]): AlertTriageResult {
  const text = redactAlertText(input.text);
  const normalized = text.toLowerCase();
  const testSignal = /\b(canary|test-only|pipeline test|test alert|no action needed)\b/.test(normalized);
  if (testSignal) {
    return {
      classification: "likely_noise",
      severity: "info",
      confidence: 0.7,
      shouldRespond: false,
      responseReason: "The message is an explicit canary/test signal and does not need Cerebro to interrupt the thread.",
      summary: "The alert text is explicitly marked as a canary or test and says no action is needed. Cerebro graph reasoning was unavailable, so no graph evidence was verified.",
      evidence: ["Alert text contains a test or canary marker.", "Cerebro graph reasoning was unavailable during fallback."],
      actionsTaken: actionsFromResearch(research),
      recommendedActions: ["No response action is needed for the canary alert.", "Retry Cerebro graph reasoning if this was not intended as a test."],
      research,
      source: "cerebro_fallback",
    };
  }

  const securitySignal = hasSecuritySignal(normalized);
  return {
    classification: "needs_context",
    severity: securitySignal ? "medium" : "info",
    confidence: securitySignal ? 0.4 : 0.3,
    shouldRespond: false,
    responseReason: "Fallback did not verify enough signal to interrupt the thread.",
    summary: securitySignal
      ? "The alert text contains security-relevant terms, but Cerebro graph reasoning was unavailable. Treat this as unverified until the affected identity, resource, and related findings are checked."
      : "Cerebro graph reasoning was unavailable and the alert text does not contain enough verified context for a security classification.",
    evidence: ["Cerebro graph reasoning was unavailable during fallback.", "No graph evidence was verified for this alert."],
    actionsTaken: actionsFromResearch(research),
    recommendedActions: ["Review the source alert fields.", "Check related Cerebro findings or rerun triage when graph reasoning is available."],
    research,
    source: "cerebro_fallback",
  };
}

export function actionsFromResearch(research: string[]): string[] {
  return research
    .filter((item) => /: checked|fallback/i.test(item))
    .map((item) => item.replace(/_/g, " ").replace(/: checked$/i, "").replace(/^Pi fallback:/i, "Used fallback path:").trim())
    .filter(Boolean)
    .slice(0, 6);
}

export function shortError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return message.replace(/\s+/g, " ").slice(0, 160);
}

export function graphSummary(value: string | undefined): string {
  return trimForSlack(value ?? "", 900);
}
