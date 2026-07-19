import type { AlertTriageClassificationV1 } from "./contracts.js";
import { hasSecuritySignal } from "./alert-triage-signals.js";

export type TriageChannelPolicyV1 = "strict" | "quiet" | "watch" | "eager";

export interface TriageChannelPolicyInputV1 {
  channel_policies: ReadonlyMap<string, TriageChannelPolicyV1>;
  minimum_confidence: number;
  triage_channel_ids: ReadonlySet<string>;
}

export interface SlackMessageForTriageV1 {
  bot_id?: string;
  subtype?: string;
  text?: string;
  thread_ts?: string;
  ts?: string;
}

export function channelPolicyFor(
  input: TriageChannelPolicyInputV1,
  channelId: string | undefined,
): TriageChannelPolicyV1 {
  if (!channelId) return "strict";
  return input.channel_policies.get(channelId)
    ?? (input.triage_channel_ids.has(channelId) ? "watch" : "strict");
}

export function minimumConfidenceForPolicy(
  input: TriageChannelPolicyInputV1,
  policy: TriageChannelPolicyV1,
): number {
  if (policy === "strict") return Math.max(input.minimum_confidence, 0.85);
  if (policy === "quiet") return Math.max(input.minimum_confidence, 0.7);
  if (policy === "eager") return Math.max(0, input.minimum_confidence - 0.15);
  return input.minimum_confidence;
}

export function policyAllowsTriage(
  event: SlackMessageForTriageV1,
  policy: TriageChannelPolicyV1,
): boolean {
  const text = event.text ?? "";
  const isThreadReply = Boolean(event.thread_ts && event.thread_ts !== event.ts);
  const isBotMessage = Boolean(event.bot_id || event.subtype === "bot_message");
  if (policy === "eager") return true;
  if (policy === "watch") return true;
  if (hasSecuritySignal(text)) return true;
  if (
    isBotMessage
    && /\b(alert|incident|finding|runtime|deploy|deployment|rollback|failed|failure|blocked|policy|approval|pull request|pr #?\d+|ci|check run|sync failed)\b/i.test(text)
  ) {
    return true;
  }
  if (policy === "quiet") {
    return isThreadReply
      && /\b(false positive|what evidence|why|owner|admin|actions?|merged|shipped|fixed|resolved|blocked|failed)\b/i.test(text);
  }
  return false;
}

export function policyAllowsPost(
  classification: AlertTriageClassificationV1,
  policy: TriageChannelPolicyV1,
): boolean {
  if (policy === "strict" && classification !== "actionable") return false;
  if (policy === "quiet" && classification === "non_actionable") return false;
  return true;
}

export function policyContextLine(policy: TriageChannelPolicyV1): string {
  if (policy === "strict") return "Channel policy: strict. Speak only for high-confidence security issues with verified evidence.";
  if (policy === "quiet") return "Channel policy: quiet. Speak only when the reply changes an investigation, deploy, or security decision.";
  if (policy === "eager") return "Channel policy: eager. Review more messages, but still post only concrete, evidence-backed help.";
  return "Channel policy: watch. Review configured signals and post only when useful.";
}
