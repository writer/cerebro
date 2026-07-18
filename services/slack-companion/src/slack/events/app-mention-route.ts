import { assessDangerousIntent } from "../../security/safety.js";
import { annotateMainPhase, annotateSpan, type TelemetrySpan } from "../../telemetry.js";
import type { CompanionWorkLoop } from "../../work/companion-work-loop.js";
import { parseRememberCommand } from "../remember-command.js";
import {
  addReaction,
  botUserIdFrom,
  claimBotHandoffForEvent,
  questionTitle,
  recordDailyNote,
  setAssistantThreadWorking,
  stripMention,
} from "./common.js";
import { handleRememberCommand } from "./remember-route.js";
import { logSkippedEvent, recordClaimTelemetry } from "./telemetry.js";
import type { EventDeps } from "./types.js";

export async function handleAppMention(
  deps: EventDeps,
  workLoop: CompanionWorkLoop,
  client: any,
  say: (message: any) => Promise<unknown>,
  context: Record<string, unknown> | undefined,
  event: any,
  span: TelemetrySpan,
): Promise<void> {
  const claim = await deps.coordinator.claimSlackEvent({
    kind: "app_mention",
    channelId: event.channel,
    ts: event.ts,
    eventId: event.event_ts,
    teamId: event.team,
  });
  recordClaimTelemetry(span, "app_mention", claim);
  if (!claim.claimed) {
    logSkippedEvent("app_mention", claim, event.channel, event.ts);
    return;
  }
  const botHandoff = claimBotHandoffForEvent(deps, event);
  annotateSpan(span, {
    "slack.bot_handoff.accepted": botHandoff.accepted,
    "slack.bot_handoff.reason": botHandoff.reason,
  });
  if (!botHandoff.accepted) {
    logSkippedEvent("app_mention", {
      claimed: false,
      reason: "local_duplicate",
      eventKey: `bot-handoff:${botHandoff.reason}`,
      detail: botHandoff.senderId,
    }, event.channel, event.ts);
    return;
  }
  const senderKind = botHandoff.reason === "not_bot" ? "human" : "bot";

  const question = stripMention(event.text ?? "", botUserIdFrom(event, context));
  annotateSpan(span, { "assistant.question.length": question.length });
  if (!question) {
    await addReaction(client, event.channel, event.ts, "wave");
    await say({ thread_ts: event.ts, text: "What should I look at?" });
    annotateMainPhase("slack.app_mention.empty_question", "completed");
    return;
  }
  const threadTs = event.thread_ts ?? event.ts;
  const actor = deps.auth.actorFor(event.user ?? "unknown");
  const rememberCommand = parseRememberCommand(question, { authorName: actor.displayName });
  if (rememberCommand) {
    annotateSpan(span, { "slack.app_mention.route": "remember" });
    await handleRememberCommand(deps, client, {
      command: rememberCommand,
      channelId: event.channel,
      userId: event.user,
      ts: event.ts,
      threadTs,
    });
    return;
  }
  const safety = assessDangerousIntent(question);
  if (!safety.allowed) {
    annotateSpan(span, {
      "safety.allowed": false,
      "safety.category": safety.category ?? "unsafe_request",
    });
    await addReaction(client, event.channel, event.ts, "no_entry");
    await say({
      thread_ts: threadTs,
      text: safety.refusal ?? "I cannot help with that request.",
    });
    await recordDailyNote(deps, {
      kind: "safety_refusal",
      title: "Refused Slack mention",
      summary: safety.reason ?? "Cerebro refused an unsafe Slack mention.",
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
    threadTs,
    replyThreadTs: threadTs,
  });
  if (!queued.accepted) {
    await addReaction(client, event.channel, event.ts, "hourglass_flowing_sand");
    annotateMainPhase("slack.app_mention.queue", "completed", {
      "work.queue.accepted": false,
      "work.queue.reason": queued.reason,
    });
    return;
  }
  if (senderKind === "human") await setAssistantThreadWorking(client, event.channel, threadTs, question);
  annotateMainPhase("slack.app_mention.queue", "queued", {
    "work.queue.position": queued.position,
  });
  await recordDailyNote(deps, {
    kind: "encounter_story",
    title: `Slack mention queued: ${questionTitle(question)}`,
    summary: "Cerebro reacted to the Slack mention and handed research to the background work loop.",
    details: `Work item: ${queued.id}\nPosition: ${queued.position}`,
    tags: ["story", "work-loop"],
    channelId: event.channel,
    sourceTs: event.ts,
    outcome: "queued",
  });
}
