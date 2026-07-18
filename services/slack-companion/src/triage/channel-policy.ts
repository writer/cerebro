import type { AppConfig, ProactiveSlackChannelPolicy } from "../config/index.js";
import type { AlertTriageResult, SlackMessageForTriage } from "./alert-triage-types.js";
import { hasSecuritySignal } from "./alert-triage-signals.js";

export function channelPolicyFor(config: AppConfig, channelId: string | undefined): ProactiveSlackChannelPolicy {
  if (!channelId) return "strict";
  return config.slack.triageChannelPolicies.get(channelId)
    ?? (config.slack.triageChannelIds.has(channelId) ? "watch" : "strict");
}

export function minimumConfidenceForPolicy(config: AppConfig, policy: ProactiveSlackChannelPolicy): number {
  if (policy === "strict") return Math.max(config.triage.minConfidence, 0.85);
  if (policy === "quiet") return Math.max(config.triage.minConfidence, 0.7);
  if (policy === "eager") return Math.max(0, config.triage.minConfidence - 0.15);
  return config.triage.minConfidence;
}

export function policyAllowsTriage(event: SlackMessageForTriage, policy: ProactiveSlackChannelPolicy): boolean {
  const text = event.text ?? "";
  const isThreadReply = Boolean(event.thread_ts && event.thread_ts !== event.ts);
  const isBotMessage = Boolean(event.bot_id || event.subtype === "bot_message");
  if (policy === "eager") return true;
  if (policy === "watch") return true;
  if (hasSecuritySignal(text)) return true;
  if (isBotMessage && /\b(alert|incident|finding|runtime|deploy|deployment|rollback|failed|failure|blocked|policy|approval|pull request|pr #?\d+|ci|check run|sync failed)\b/i.test(text)) {
    return true;
  }
  if (policy === "quiet") {
    return isThreadReply && /\b(false positive|what evidence|why|owner|admin|actions?|merged|shipped|fixed|resolved|blocked|failed)\b/i.test(text);
  }
  return false;
}

export function policyAllowsPost(result: AlertTriageResult, policy: ProactiveSlackChannelPolicy): boolean {
  if (policy === "strict" && result.classification !== "likely_security_issue") return false;
  if (policy === "quiet" && result.classification === "likely_noise") return false;
  return true;
}

export function policyContextLine(policy: ProactiveSlackChannelPolicy): string {
  if (policy === "strict") return "Channel policy: strict. Speak only for high-confidence security issues with verified evidence.";
  if (policy === "quiet") return "Channel policy: quiet. Speak only when the reply changes an investigation, deploy, or security decision.";
  if (policy === "eager") return "Channel policy: eager. Review more messages, but still post only concrete, evidence-backed help.";
  return "Channel policy: watch. Review configured signals and post only when useful.";
}
