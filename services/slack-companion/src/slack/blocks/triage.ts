import type { AlertTriageResult } from "../../triage/alert-triage.js";
import type { ProactiveMonitorSuggestionRecord, ProactiveSuggestionRecord } from "../../triage/slack-thread-state.js";
import { encodeAction } from "../action-codec.js";
import { trimForSlack } from "../format.js";
import { firstUsefulAction, isRepeatedLine, uniqueLine } from "./conversation.js";
import { actionIds } from "./action-ids.js";
import { actions, button, context, escapeMrkdwn, header, listSection, section, type SlackBlock } from "./primitives.js";

export function triageBlocks(result: AlertTriageResult): SlackBlock[] {
  const status = result.classification.replace(/_/g, " ");
  const severity = result.severity ? ` · ${result.severity}` : "";
  const confidence = `confidence ${Math.round(result.confidence * 100)}%`;
  return [
    header("Alert triage"),
    context([`${status}${severity} · ${confidence}`, `Research: ${result.source === "pi" ? "Pi agent with Cerebro tools" : "Cerebro graph fallback"}`]),
    section(`*Summary*\n${escapeMrkdwn(trimForSlack(result.summary, 900))}`),
    ...listSection("Evidence", result.evidence),
    ...listSection("Done", result.actionsTaken),
    ...listSection("Next actions", result.recommendedActions),
    ...listSection("Checked", result.research),
  ];
}

export function triageResponseText(result: AlertTriageResult): string {
  const action = firstUsefulAction(result.recommendedActions);
  const lines = [
    trimForSlack(result.summary, 420),
    action && !isRepeatedLine(result.summary, action) ? `Next: ${trimForSlack(action, 260)}` : "",
  ].filter(Boolean).filter(uniqueLine);
  return trimForSlack(lines.join("\n"), 900);
}

export function triageResponseBlocks(
  result: AlertTriageResult,
  suggestion?: ProactiveMonitorSuggestionRecord,
  channelId?: string,
  threadTs?: string,
  proactiveSuggestion?: ProactiveSuggestionRecord,
): SlackBlock[] | undefined {
  if (proactiveSuggestion && channelId && threadTs) {
    return [
      section(escapeMrkdwn(triageResponseText(result))),
      ...proactiveSuggestionBlocks(result, proactiveSuggestion, channelId, threadTs),
    ];
  }
  if (!suggestion || !channelId || !threadTs) return undefined;
  return [
    section(escapeMrkdwn(triageResponseText(result))),
    context([`${suggestion.title}: ${suggestion.description}`]),
    actions([
      button("Start check", actionIds.monitorSuggestionAccept, encodeAction({
        kind: "monitor_suggestion_accept",
        suggestionId: suggestion.id,
        channelId,
        threadTs,
      }), "primary"),
      button("Dismiss", actionIds.monitorSuggestionDismiss, encodeAction({
        kind: "monitor_suggestion_dismiss",
        suggestionId: suggestion.id,
        channelId,
        threadTs,
      })),
    ]),
  ];
}

export function proactiveSuggestionText(result: AlertTriageResult, suggestion: ProactiveSuggestionRecord): string {
  return trimForSlack([
    `Suggested action: ${suggestion.title}`,
    suggestion.description,
    result.evidence[0] ? `Evidence: ${result.evidence[0]}` : "",
  ].filter(Boolean).join("\n"), 900);
}

export function proactiveSuggestionBlocks(
  result: AlertTriageResult,
  suggestion: ProactiveSuggestionRecord,
  channelId: string,
  threadTs: string,
): SlackBlock[] {
  return [
    section(`*Suggested action*\n${escapeMrkdwn(suggestion.title)}\n${escapeMrkdwn(suggestion.description)}`),
    context([`Evidence: ${trimForSlack(result.evidence[0] ?? result.summary, 240)}`]),
    actions([
      button("Create goal", actionIds.proactiveSuggestionAccept, encodeAction({
        kind: "proactive_suggestion_accept",
        suggestionId: suggestion.id,
        channelId,
        threadTs,
      }), "primary"),
      button("Dismiss", actionIds.proactiveSuggestionDismiss, encodeAction({
        kind: "proactive_suggestion_dismiss",
        suggestionId: suggestion.id,
        channelId,
        threadTs,
      })),
    ]),
  ];
}

export function triageFailureBlocks(reason: string): SlackBlock[] {
  return [
    header("Alert triage"),
    section(`Triage did not complete: ${escapeMrkdwn(trimForSlack(reason, 900))}`),
  ];
}
