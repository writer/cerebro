import { logger } from "../../logger.js";
import { assessDangerousIntent } from "../../security/safety.js";
import { shouldTriageSlackMessage, type AlertTriageInput, type AlertTriageService } from "../../triage/alert-triage.js";
import { annotateSpan, captureTelemetryError, type TelemetrySpan } from "../../telemetry.js";
import type { CompanionWorkLoop } from "../../work/companion-work-loop.js";
import { containsSlackMention, parseRememberCommand } from "../remember-command.js";
import { handleAlertTriage } from "./alert-triage-route.js";
import { addReaction, botUserIdFrom, claimBotHandoffForEvent, questionTitle, recordDailyNote, setAssistantThreadWorking, stripMention } from "./common.js";
import { handleRememberCommand } from "./remember-route.js";
import { logSkippedEvent, recordClaimTelemetry } from "./telemetry.js";
import type { EventDeps } from "./types.js";
import type { AssistantInitiativeThreadBinding } from "../../triage/slack-thread-state.js";

export async function handleMessageEvent(
  deps: EventDeps,
  triage: AlertTriageService,
  workLoop: CompanionWorkLoop,
  client: any,
  event: any,
  span: TelemetrySpan,
  context?: Record<string, unknown>,
): Promise<void> {
  const botUserId = botUserIdFrom(event, context);
  if (!event.bot_id && !event.subtype && !containsSlackMention(event.text ?? "")) {
    const actor = deps.auth.actorFor(event.user ?? "unknown");
    const rememberCommand = parseRememberCommand(event.text ?? "", { authorName: actor.displayName });
    if (rememberCommand) {
      const claim = await deps.coordinator.claimSlackEvent({
        kind: "remember",
        channelId: event.channel,
        ts: event.ts,
        eventId: event.event_ts,
        teamId: event.team,
      });
      recordClaimTelemetry(span, "remember", claim);
      if (!claim.claimed) {
        logSkippedEvent("remember", claim, event.channel, event.ts);
        return;
      }
      await handleRememberCommand(deps, client, {
        command: rememberCommand,
        channelId: event.channel,
        userId: event.user,
        ts: event.ts,
        threadTs: event.thread_ts ?? event.ts,
      });
      return;
    }
  }

  const initiativeReply = await assistantInitiativeReplyFromMessage(deps, event, span, botUserId);
  if (initiativeReply) {
    await recordImprovementInitiativeOutcome(deps, event, initiativeReply);
    await handleDirectAssistantQuestion(deps, workLoop, client, event, initiativeReply.question, span);
    return;
  }

  const assistantQuestion = assistantQuestionFromMessage(event, botUserId);
  if (assistantQuestion) {
    await handleDirectAssistantQuestion(deps, workLoop, client, event, assistantQuestion, span);
    return;
  }

  await observePassiveChannelMessage(deps, event, span, botUserId);

  if (!shouldTriageSlackMessage(deps.config, event, { botUserId })) {
    annotateSpan(span, {
      "slack.message.triage_candidate": false,
      "slack.message.bot_present": Boolean(event.bot_id),
      "slack.message.subtype.present": Boolean(event.subtype),
    });
    return;
  }
  annotateSpan(span, { "slack.message.triage_candidate": true });
  const claim = await deps.coordinator.claimSlackEvent({
    kind: "message",
    channelId: event.channel,
    ts: event.ts,
    eventId: event.event_ts,
    teamId: event.team,
  });
  recordClaimTelemetry(span, "message", claim);
  if (!claim.claimed) {
    logSkippedEvent("message", claim, event.channel, event.ts);
    return;
  }
  const input: AlertTriageInput = {
    channelId: event.channel,
    userId: event.user,
    text: event.text,
    ts: event.ts,
    threadTs: event.thread_ts,
  };
  void handleAlertTriage(deps, triage, client, input).catch((error) => {
    captureTelemetryError("slack.alert_triage.task.error", error, { component: "slack-events", operation: "alert_triage" });
    logger.warn("alert triage task failed", {
      error: String(error),
      channel: input.channelId,
      ts: input.ts,
    });
  });
}

async function observePassiveChannelMessage(deps: EventDeps, event: any, span: TelemetrySpan, botUserId?: string): Promise<void> {
  if (!deps.channelLearning || !deps.config.learning.channelLearningEnabled || !deps.config.learning.enabled) return;
  if (event.bot_id || event.app_id || event.subtype) return;
  const text = event.text ?? "";
  if (botUserId ? text.includes(`<@${botUserId}>`) : containsSlackMention(text)) return;
  if (typeof event.user !== "string" || !event.user.trim()) return;
  if (typeof event.channel !== "string" || !/^[CG][A-Z0-9]+$/i.test(event.channel)) return;
  if (deps.config.learning.channelLearningExcludedChannelIds.has(event.channel)) return;
  const claim = await deps.coordinator.claimSlackEvent({
    kind: "channel_learning",
    channelId: event.channel,
    ts: event.ts,
    eventId: event.event_ts,
    teamId: event.team,
  });
  recordClaimTelemetry(span, "channel_learning", claim);
  if (!claim.claimed) {
    logSkippedEvent("channel_learning", claim, event.channel, event.ts);
    return;
  }
  const result = deps.channelLearning.observe({ channelId: event.channel, ts: event.ts, text: event.text ?? "" });
  annotateSpan(span, {
    "slack.channel_learning.accepted": result.accepted,
    "slack.channel_learning.reason": result.reason,
    "slack.channel_learning.buffered": result.buffered,
  });
}

async function handleDirectAssistantQuestion(
  deps: EventDeps,
  workLoop: CompanionWorkLoop,
  client: any,
  event: any,
  question: string,
  span: TelemetrySpan,
): Promise<void> {
  const claim = await deps.coordinator.claimSlackEvent({
    kind: "assistant_message",
    channelId: event.channel,
    ts: event.ts,
    eventId: event.event_ts,
    teamId: event.team,
  });
  recordClaimTelemetry(span, "assistant_message", claim);
  if (!claim.claimed) {
    logSkippedEvent("assistant_message", claim, event.channel, event.ts);
    return;
  }
  const botHandoff = claimBotHandoffForEvent(deps, event);
  annotateSpan(span, {
    "slack.bot_handoff.accepted": botHandoff.accepted,
    "slack.bot_handoff.reason": botHandoff.reason,
  });
  if (!botHandoff.accepted) {
    logSkippedEvent("assistant_message", {
      claimed: false,
      reason: "local_duplicate",
      eventKey: `bot-handoff:${botHandoff.reason}`,
      detail: botHandoff.senderId,
    }, event.channel, event.ts);
    return;
  }
  const senderKind = botHandoff.reason === "not_bot" ? "human" : "bot";

  annotateSpan(span, {
    "slack.message.route": "assistant_message",
    "assistant.question.length": question.length,
  });
  const replyThreadTs = event.thread_ts ?? event.ts;
  const safety = assessDangerousIntent(question);
  if (!safety.allowed) {
    annotateSpan(span, {
      "safety.allowed": false,
      "safety.category": safety.category ?? "unsafe_request",
    });
    await addReaction(client, event.channel, event.ts, "no_entry");
    await client.chat.postMessage({
      channel: event.channel,
      thread_ts: replyThreadTs,
      text: safety.refusal ?? "I cannot help with that request.",
      unfurl_links: false,
      unfurl_media: false,
    });
    await recordDailyNote(deps, {
      kind: "safety_refusal",
      title: "Refused assistant message",
      summary: safety.reason ?? "Cerebro refused an unsafe assistant message.",
      details: [`Category: ${safety.category ?? "unsafe_request"}`, `Question: ${question}`].join("\n"),
      tags: ["safety-refusal", safety.category ?? "unsafe-request"],
      channelId: event.channel,
      sourceTs: event.ts,
      outcome: "refused",
    });
    return;
  }
  annotateSpan(span, { "safety.allowed": true });

  if (senderKind === "human") await addReaction(client, event.channel, event.ts, "eyes");
  const queued = await workLoop.enqueueSlackQuestion(client, {
    channelId: event.channel,
    userId: event.user,
    senderKind,
    question,
    ts: event.ts,
    threadTs: event.thread_ts,
    replyThreadTs,
  });
  if (!queued.accepted) {
    await addReaction(client, event.channel, event.ts, "hourglass_flowing_sand");
    return;
  }
  if (senderKind === "human") await setAssistantThreadWorking(client, event.channel, replyThreadTs, question);
  await recordDailyNote(deps, {
    kind: "encounter_story",
    title: `Assistant message queued: ${questionTitle(question)}`,
    summary: "Cerebro queued the assistant message for the background work loop.",
    details: `Work item: ${queued.id}\nPosition: ${queued.position}`,
    tags: ["story", "work-loop", "assistant-message"],
    channelId: event.channel,
    sourceTs: event.ts,
    outcome: "queued",
  });
}

function assistantQuestionFromMessage(event: any, botUserId?: string): string | undefined {
  const botAuthored = Boolean(event.bot_id || event.app_id || event.subtype === "bot_message");
  if (botAuthored && !containsSlackMention(event.text ?? "")) return undefined;
  if (!botAuthored && !isDirectAssistantChannel(event)) return undefined;
  const question = stripMention(event.text ?? "", botUserId);
  return question || undefined;
}

async function assistantInitiativeReplyFromMessage(
  deps: EventDeps,
  event: any,
  span: TelemetrySpan,
  botUserId?: string,
): Promise<{ question: string; binding: AssistantInitiativeThreadBinding } | undefined> {
  if (!deps.threadState || !botUserId) return undefined;
  if (event.bot_id || event.app_id || event.subtype) return undefined;
  if (typeof event.channel !== "string" || !/^[CDG][A-Z0-9]+$/i.test(event.channel)) return undefined;
  if (typeof event.thread_ts !== "string" || !event.thread_ts.trim()) return undefined;
  if (typeof event.user !== "string" || !event.user.trim()) return undefined;
  const question = stripMention(String(event.text ?? ""), botUserId);
  if (!question) return undefined;
  try {
    const binding = await deps.threadState.matchAssistantInitiativeReply({
      channelId: event.channel,
      threadTs: event.thread_ts,
      userId: event.user,
    });
    annotateSpan(span, {
      "slack.assistant_initiative.matched": Boolean(binding),
      "slack.assistant_initiative.status": binding?.status ?? "not_matched",
    });
    return binding ? { question, binding } : undefined;
  } catch (error) {
    captureTelemetryError("slack.assistant_initiative.binding_lookup_failed", error, {
      component: "slack-events",
      operation: "assistant_initiative_lookup",
    });
    logger.warn("slack.assistant_initiative.binding_lookup_failed", {
      channel: event.channel,
      threadTs: event.thread_ts,
      error: String(error).replace(/\s+/g, " ").trim().slice(0, 500),
    });
    return undefined;
  }
}

async function recordImprovementInitiativeOutcome(
  deps: EventDeps,
  event: any,
  reply: { question: string; binding: AssistantInitiativeThreadBinding },
): Promise<void> {
  const { binding, question } = reply;
  if (!deps.threadState) return;
  const safety = assessDangerousIntent(question);
  if (!safety.allowed) {
    await deps.threadState.closeAssistantInitiative({
      channelId: binding.channelId,
      threadTs: binding.threadTs,
      initiativeId: binding.initiativeId,
      reason: "cancelled",
    });
    return;
  }
  if (!binding.goalId?.match(/^improvement-[a-f0-9]{24}$/)) {
    await deps.threadState.closeAssistantInitiative({
      channelId: binding.channelId,
      threadTs: binding.threadTs,
      initiativeId: binding.initiativeId,
      reason: "completed",
    });
    return;
  }
  if (!deps.improvement?.recordHumanAssistanceOutcome) return;
  const run = await deps.improvement.recordHumanAssistanceOutcome({
    runId: binding.goalId,
    channelId: binding.channelId,
    intendedUserId: binding.intendedUserId,
    outcome: question,
  });
  await deps.threadState.closeAssistantInitiative({
    channelId: binding.channelId,
    threadTs: binding.threadTs,
    initiativeId: binding.initiativeId,
    reason: run ? "completed" : "cancelled",
  });
}

function isDirectAssistantChannel(event: any): boolean {
  if (event.channel_type === "im") return true;
  return typeof event.channel === "string" && event.channel.startsWith("D");
}
