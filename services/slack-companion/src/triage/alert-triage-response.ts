import type { AppConfig } from "../config/index.js";
import type { AlertTriageResult, SlackMessageForTriage, TriageClassification } from "./alert-triage-types.js";
import { channelPolicyFor, minimumConfidenceForPolicy, policyAllowsPost, policyAllowsTriage } from "./channel-policy.js";
import { hasSecuritySignal, hasSpecificText, isGenericTriageText } from "./alert-triage-signals.js";

export function shouldTriageSlackMessage(config: AppConfig, event: SlackMessageForTriage, options: { botUserId?: string } = {}): boolean {
  if (!config.triage.enabled) return false;
  if (!event.channel || !config.slack.triageChannelIds.has(event.channel)) return false;
  if (!event.ts || !event.text?.trim()) return false;
  const channelPolicy = channelPolicyFor(config, event.channel);
  if (!policyAllowsTriage(event, channelPolicy)) return false;
  if (/^<@[A-Z0-9]+>(?:\s|$)/.test(event.text.trim())) return false;
  const isThreadReply = Boolean(event.thread_ts && event.thread_ts !== event.ts);
  const isOwnBot = Boolean(options.botUserId && event.user === options.botUserId);
  if (isOwnBot) return false;

  const isBotMessage = Boolean(event.bot_id || event.subtype === "bot_message");
  if (event.subtype && event.subtype !== "bot_message") return false;
  if (isBotMessage) {
    if (isThreadReply) return false;
    if (!hasProactiveBotAlertSignal(event.text)) return false;
  } else if (!event.user) {
    return false;
  }

  if (isLightweightConversation(event.text, { isThreadReply, isBotMessage })) return false;
  return true;
}

export function shouldPostTriageResponse(config: AppConfig, result: AlertTriageResult, options: { channelPolicy?: ReturnType<typeof channelPolicyFor> } = {}): boolean {
  if (!config.slack.triageAutoReply) return false;
  const channelPolicy = options.channelPolicy ?? "watch";
  if (result.confidence < minimumConfidenceForPolicy(config, channelPolicy)) return false;
  if (!result.shouldRespond) return false;
  if (!policyAllowsPost(result, channelPolicy)) return false;
  if (!hasConversationValue(result)) return false;
  if (!hasVerifiedTriageBasis(result)) return false;
  if (result.classification === "likely_noise" && !hasSpecificNoiseSignal(result)) return false;
  return true;
}

export function defaultShouldRespond(classification: TriageClassification, evidence: string[], recommendedActions: string[]): boolean {
  if (classification === "likely_noise") return false;
  return hasSpecificText(evidence) || hasSpecificText(recommendedActions);
}

function hasConversationValue(result: AlertTriageResult): boolean {
  if (!result.summary.trim()) return false;
  if (isGenericTriageText(result.summary)) return false;
  if (hasSpecificText(result.evidence) || hasSpecificText(result.recommendedActions)) return true;
  return Boolean(result.responseReason && !isGenericTriageText(result.responseReason));
}

export function hasVerifiedTriageBasis(result: AlertTriageResult): boolean {
  const research = result.research.join(" ");
  if (result.source === "cerebro_fallback") {
    return /\bcerebro_(graph_reason|evidence_packet): checked\b/.test(research);
  }
  if (hasAssistantFollowUpBasis(result)) return true;
  if (hasHighSignalResearch(result)) return true;
  if (result.classification === "likely_security_issue" && hasSpecificText(result.evidence)) {
    return true;
  }
  return false;
}

function hasHighSignalResearch(result: AlertTriageResult): boolean {
  const research = result.research.join("\n");
  if (/\b(cerebro_open_findings|cerebro_finding_evidence|cerebro_evidence_packet|cerebro_graph_reason|cerebro_graph_cypher_investigate|cerebro_entity_neighborhood|evidence_cas_resolve|infisical_secret_metadata|infisical_secret_fingerprint|slack_ai_search_context|slack_message_context|slack_channel_context|slack_message_search|slack_app_install_audit|cerebro_code_github_pr_status|cerebro_code_github_checks): checked\b/.test(research)) {
    return true;
  }
  if (result.classification === "likely_security_issue" && /\bcerebro_runtime_health: checked\b/.test(research)) {
    return true;
  }
  return false;
}

function hasAssistantFollowUpBasis(result: AlertTriageResult): boolean {
  if (result.topic !== "assistant_follow_up") return false;
  const research = result.research.join("\n");
  if (!/\bslack_thread_context: checked\b/.test(research)) return false;
  if (!hasSpecificText(result.evidence)) return false;
  return [...result.evidence, result.summary, ...result.recommendedActions].some((item) =>
    /\b(Cerebro|assistant|bot|prior|previous|thread|reply|answer|wording|clarif|correction|profile|role|owner|admin)\b/i.test(item),
  );
}

function hasSpecificNoiseSignal(result: AlertTriageResult): boolean {
  return [...result.evidence, result.summary, result.responseReason ?? ""].some((item) =>
    /\b(known|matched|matches|recurring|baseline|expected|maintenance|deploy|deployment|runtime|source|finding|rule|owner|ticket|case|okta|github|aws|gcp|azure|ip|role|service account)\b/i.test(item),
  );
}

function hasProactiveBotAlertSignal(text: string): boolean {
  if (hasSecuritySignal(text)) return true;
  return /\b(alert|incident|sev[0-9]?|pagerduty|rootly|guardduty|wiz|waf|cloudflare|sentinelone|crowdstrike|dependabot|secret scanning|code scanning|finding|runtime|source runtime|deploy|deployment|rollback|failed|failure|error|blocked|regression|policy|approval|pull request|pr #?\d+|ci|check run|job failed|sync failed)\b/i.test(text);
}

function isLightweightConversation(text: string, context: { isThreadReply?: boolean; isBotMessage?: boolean } = {}): boolean {
  const normalized = text
    .replace(/<https?:\/\/[^>]+>/g, "")
    .replace(/:[a-z0-9_+-]+:/gi, "")
    .replace(/[✅👍🙏🎉🚀]/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
  if (!normalized) return true;
  if (hasSecuritySignal(normalized)) return false;
  if (context.isBotMessage && hasProactiveBotAlertSignal(normalized)) return false;
  if (normalized.length > 80) return false;
  if (context.isThreadReply && /^(done|fixed|merged|resolved|shipped)\b/.test(normalized)) return false;
  return /^(ack|agreed|awesome|cool|done|fixed|great|lgtm|nice|ok|okay|perfect|sgtm|sounds good|thanks|thank you|ty|yep|yes|yeah|shipped|merged|resolved|on it|looking|checking)[.!?]*$/.test(normalized)
    || /^(cool|nice|great|thanks|thank you|ok|okay),?\s+(shipped|merged|done|fixed|resolved)\b/.test(normalized)
    || /^(shipped|merged|done|fixed|resolved)\b/.test(normalized);
}
