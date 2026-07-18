import { logger } from "../../logger.js";
import { shouldPostTriageResponse, type AlertTriageInput, type AlertTriageService } from "../../triage/alert-triage.js";
import { channelPolicyFor } from "../../triage/channel-policy.js";
import { monitorSuggestionFor } from "../../triage/monitor-suggestions.js";
import { proactiveSuggestionFor } from "../../triage/proactive-suggestions.js";
import type { ProactiveTriageOutcome } from "../../triage/slack-thread-state.js";
import type { TriageClassification, TriageTopic } from "../../triage/alert-triage-types.js";
import {
  annotateMainDependency,
  annotateMainPhase,
  annotateSpan,
  captureTelemetryError,
  slackTelemetryAttributes,
  withTelemetrySpan,
} from "../../telemetry.js";
import { proactiveSuggestionBlocks, proactiveSuggestionText, triageResponseBlocks, triageResponseText } from "../blocks/index.js";
import { alertTitle, recordDailyNote } from "./common.js";
import type { EventDeps } from "./types.js";

export async function handleAlertTriage(deps: EventDeps, triage: AlertTriageService, client: any, input: AlertTriageInput): Promise<void> {
  let finalStatus: "completed" | "suppressed" | "failed" = "completed";
  return withTelemetrySpan("slack.alert_triage", {
    component: "slack-events",
    operation: "alert_triage",
    "slack.event.text.length": input.text.length,
    ...slackTelemetryAttributes(input),
  }, async (span) => {
  const actor = deps.auth.actorFor(input.userId ?? "unknown");
  await deps.cerebro.recordInteraction({
    actor,
    action: "slack_alert_triage",
    channelId: input.channelId,
    status: "received",
    subject: input.ts,
    details: { slack_event_ts: input.ts },
  }).catch((error) => logger.warn("triage interaction record failed", { error: String(error), status: "received" }));

  try {
    const result = await triage.triage(input);
    annotateSpan(span, {
      "triage.classification": result.classification,
      "triage.severity": result.severity ?? "",
      "triage.confidence": result.confidence,
      "triage.should_respond": result.shouldRespond,
      "triage.source": result.source,
      "triage.evidence.count": result.evidence.length,
      "triage.research.count": result.research.length,
    });
    const channelPolicy = channelPolicyFor(deps.config, input.channelId);
    const threadTs = input.threadTs ?? input.ts;
    const posted = shouldPostTriageResponse(deps.config, result, { channelPolicy });
    const proactiveDraft = proactiveSuggestionFor(deps.config, input, result, channelPolicy);
    const proactiveWrite = proactiveDraft && deps.threadState
      ? await deps.threadState.addProactiveSuggestion({
          channelId: input.channelId,
          threadTs,
          channelPolicy,
          title: proactiveDraft.title,
          description: proactiveDraft.description,
          goalText: proactiveDraft.goalText,
          dedupKey: proactiveDraft.dedupKey,
          sourceTs: input.ts,
        }).catch((error) => {
          logger.warn("proactive suggestion write failed", { error: String(error), channel: input.channelId, ts: input.ts });
          return undefined;
        })
      : undefined;
    const visibleProactiveSuggestion = proactiveWrite?.suggestion;
    const monitorDraft = visibleProactiveSuggestion ? undefined : monitorSuggestionFor(input, result, channelPolicy);
    const suggestionWrite = monitorDraft && deps.threadState
      ? await deps.threadState.addSuggestion({
          channelId: input.channelId,
          threadTs,
          channelPolicy,
          title: monitorDraft.title,
          description: monitorDraft.description,
          scheduleText: monitorDraft.scheduleText,
          dedupKey: monitorDraft.dedupKey,
          sourceTs: input.ts,
        }).catch((error) => {
          logger.warn("monitor suggestion write failed", { error: String(error), channel: input.channelId, ts: input.ts });
          return undefined;
        })
      : undefined;
    const visibleSuggestion = suggestionWrite?.suggestion;
    let suggestionPosted = false;
    if (posted) {
      const responseText = triageResponseText(result);
      const blocks = triageResponseBlocks(result, visibleSuggestion, input.channelId, threadTs, visibleProactiveSuggestion);
      await client.chat.postMessage({
        channel: input.channelId,
        thread_ts: threadTs,
        text: responseText,
        ...(blocks ? { blocks } : {}),
        unfurl_links: false,
        unfurl_media: false,
      });
      annotateMainDependency("slack", "events", "post_triage_response", "completed");
    } else if (visibleProactiveSuggestion) {
      suggestionPosted = true;
      const responseText = proactiveSuggestionText(result, visibleProactiveSuggestion);
      await client.chat.postMessage({
        channel: input.channelId,
        thread_ts: threadTs,
        text: responseText,
        blocks: proactiveSuggestionBlocks(result, visibleProactiveSuggestion, input.channelId, threadTs),
        unfurl_links: false,
        unfurl_media: false,
      });
      annotateMainDependency("slack", "events", "post_proactive_suggestion", "completed");
    } else {
      finalStatus = "suppressed";
      annotateMainPhase("slack.alert_triage.response", "suppressed", {
        "triage.classification": result.classification,
      });
      logger.info("alert triage response suppressed", {
        channel: input.channelId,
        ts: input.ts,
        classification: result.classification,
        confidence: result.confidence,
        shouldRespond: result.shouldRespond,
        reason: result.responseReason,
      });
    }
    await recordThreadOutcome(deps, input, {
      outcome: posted ? "posted" : suggestionPosted ? "suggested" : result.shouldRespond ? "drafted" : "suppressed",
      channelPolicy,
      summary: result.summary,
      reason: result.responseReason,
      topic: result.topic,
      classification: result.classification,
      confidence: result.confidence,
      research: result.research,
    });
    await recordDailyNote(deps, {
      kind: "triage_outcome",
      title: alertTitle(input.text),
      summary: result.summary,
      details: [
        `classification=${result.classification}`,
        result.severity ? `severity=${result.severity}` : "",
        `confidence=${result.confidence}`,
        `should_respond=${result.shouldRespond}`,
        result.responseReason ? `reason=${result.responseReason}` : "",
        result.evidence.length > 0 ? `Evidence: ${result.evidence.join(" | ")}` : "",
        result.actionsTaken.length > 0 ? `Actions taken: ${result.actionsTaken.join(" | ")}` : "",
        result.recommendedActions.length > 0 ? `Next actions: ${result.recommendedActions.join(" | ")}` : "",
        result.research.length > 0 ? `Research: ${result.research.join(" | ")}` : "",
      ].filter(Boolean).join("\n"),
      tags: ["slack-alert", result.classification, result.severity ?? "severity-unknown", result.source],
      channelId: input.channelId,
      sourceTs: input.ts,
      outcome: posted ? "posted" : suggestionPosted ? "suggested" : result.shouldRespond ? "drafted" : "suppressed",
    });
    await deps.cerebro.recordInteraction({
      actor,
      action: "slack_alert_triage",
      channelId: input.channelId,
      status: "completed",
      subject: input.ts,
      details: {
        slack_event_ts: input.ts,
        classification: result.classification,
        confidence: String(result.confidence),
        should_respond: String(result.shouldRespond),
        source: result.source,
        ...(result.responseReason ? { response_reason: result.responseReason } : {}),
      },
    }).catch((error) => logger.warn("triage interaction record failed", { error: String(error), status: "completed" }));
  } catch (error) {
    finalStatus = "failed";
    captureTelemetryError("slack.alert_triage.error", error, { component: "slack-events", operation: "alert_triage" });
    const message = error instanceof Error ? error.message : String(error);
    logger.warn("alert triage failed", { error: message, channel: input.channelId, ts: input.ts });
    await deps.cerebro.recordInteraction({
      actor,
      action: "slack_alert_triage",
      channelId: input.channelId,
      status: "failed",
      subject: input.ts,
      details: { slack_event_ts: input.ts, error: message.slice(0, 500) },
    }).catch((recordError) => logger.warn("triage interaction record failed", { error: String(recordError), status: "failed" }));
    await recordDailyNote(deps, {
      kind: "failure",
      title: alertTitle(input.text),
      summary: "Cerebro could not complete alert triage.",
      details: message,
      tags: ["slack-alert", "triage-failure"],
      channelId: input.channelId,
      sourceTs: input.ts,
      outcome: "failed",
    });
    await recordThreadOutcome(deps, input, {
      outcome: "blocked",
      channelPolicy: channelPolicyFor(deps.config, input.channelId),
      summary: "Cerebro could not complete alert triage.",
      reason: message,
      research: [],
    });
  }
  }, {
    main: true,
    statusForResult: () => finalStatus,
    errorEventName: "slack.alert_triage.error",
  });
}

async function recordThreadOutcome(
  deps: EventDeps,
  input: AlertTriageInput,
  details: {
    outcome: ProactiveTriageOutcome;
    channelPolicy: ReturnType<typeof channelPolicyFor>;
    summary: string;
    reason?: string;
    topic?: TriageTopic;
    classification?: TriageClassification;
    confidence?: number;
    research: string[];
  },
): Promise<void> {
  if (!deps.threadState) return;
  await deps.threadState.recordOutcome({
    channelId: input.channelId,
    threadTs: input.threadTs ?? input.ts,
    sourceTs: input.ts,
    channelPolicy: details.channelPolicy,
    outcome: details.outcome,
    topic: details.topic,
    classification: details.classification,
    confidence: details.confidence,
    summary: details.summary,
    reason: details.reason,
    research: details.research,
  }).catch((error) => logger.warn("thread outcome write failed", { error: String(error), channel: input.channelId, ts: input.ts }));
}
