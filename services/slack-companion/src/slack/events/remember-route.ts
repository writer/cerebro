import { logger } from "../../logger.js";
import { redactSecurityText } from "../../security/redaction.js";
import { assessDangerousIntent } from "../../security/safety.js";
import { trimForSlack } from "../format.js";
import type { RememberCommand } from "../remember-command.js";
import { addReaction, recordDailyNote, unique } from "./common.js";
import type { EventDeps } from "./types.js";

export async function handleRememberCommand(deps: EventDeps, client: any, input: {
  command: RememberCommand;
  channelId: string;
  userId?: string;
  ts: string;
  threadTs: string;
}): Promise<void> {
  const { command } = input;
  if (!command.content) {
    await addReaction(client, input.channelId, input.ts, "grey_question");
    await postRememberReply(client, input.channelId, input.threadTs, 'Add what I should remember after "Cerebro remember".');
    return;
  }

  if (redactSecurityText(command.content) !== command.content) {
    await addReaction(client, input.channelId, input.ts, "no_entry");
    await postRememberReply(client, input.channelId, input.threadTs, "I did not save that. It looks like it contains a secret or token.");
    await recordDailyNote(deps, {
      kind: "safety_refusal",
      title: "Refused Slack remember command",
      summary: "Cerebro refused to save an explicit memory command because it looked sensitive.",
      tags: ["slack-remember", "secret"],
      channelId: input.channelId,
      sourceTs: input.ts,
      outcome: "refused",
    });
    return;
  }

  const safety = assessDangerousIntent(command.content);
  if (!safety.allowed) {
    await addReaction(client, input.channelId, input.ts, "no_entry");
    await postRememberReply(client, input.channelId, input.threadTs, safety.refusal ?? "I cannot save that memory.");
    await recordDailyNote(deps, {
      kind: "safety_refusal",
      title: "Refused Slack remember command",
      summary: safety.reason ?? "Cerebro refused to save an unsafe explicit memory command.",
      details: `Category: ${safety.category ?? "unsafe_request"}`,
      tags: ["slack-remember", safety.category ?? "unsafe-request"],
      channelId: input.channelId,
      sourceTs: input.ts,
      outcome: "refused",
    });
    return;
  }

  try {
    const record = await deps.memory.remember({
      kind: command.workingMemoryTarget === "team" ? "team_context" : "normal_pattern",
      topic: command.topic,
      summary: command.summary,
      details: command.details,
      tags: command.tags,
      channelId: input.channelId,
      sourceTs: input.ts,
      classification: "user_provided_context",
      confidence: 1,
      sourceKind: "slack_remember",
    });
    const explicitRecord = await deps.memory.remember({
      kind: "explicit_memory",
      topic: command.explicitTopic,
      summary: command.explicitSummary,
      details: command.explicitDetails,
      tags: unique(["slack-remember", "explicit-memory", ...command.tags]),
      channelId: input.channelId,
      sourceTs: input.ts,
      classification: "user_provided_context",
      confidence: 1,
      sourceKind: "slack_remember",
    });
    const working = deps.memory.writeWorkingMemory({
      target: command.workingMemoryTarget,
      action: "add",
      content: `${command.topic}: ${command.summary}`,
    });
    await addReaction(client, input.channelId, input.ts, "memo");
    await postRememberReply(
      client,
      input.channelId,
      input.threadTs,
      working.success
        ? `Remembered: ${command.topic}.`
        : `Remembered: ${command.topic}. Searchable memory is saved; ${command.workingMemoryTarget.toUpperCase()}.md needs cleanup before adding this there.`,
    );
    await recordDailyNote(deps, {
      kind: "maintenance",
      title: `Slack remember: ${command.topic}`,
      summary: command.summary,
      details: [
        record ? `Memory record: ${record.id}` : "",
        explicitRecord ? `Explicit memory record: ${explicitRecord.id}` : "",
        `Working memory: ${working.message}`,
      ].filter(Boolean).join("\n"),
      tags: command.tags,
      channelId: input.channelId,
      sourceTs: input.ts,
      outcome: "remembered",
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    logger.warn("slack remember command failed", { error: message, channel: input.channelId, ts: input.ts, topic: command.topic });
    await addReaction(client, input.channelId, input.ts, "warning");
    await postRememberReply(client, input.channelId, input.threadTs, "I could not save that memory.");
    await recordDailyNote(deps, {
      kind: "failure",
      title: `Slack remember: ${command.topic}`,
      summary: "Cerebro could not save an explicit Slack memory command.",
      details: message,
      tags: ["slack-remember", "failure"],
      channelId: input.channelId,
      sourceTs: input.ts,
      outcome: "failed",
    });
  }
}

async function postRememberReply(client: any, channel: string, threadTs: string, text: string): Promise<void> {
  await client.chat.postMessage({
    channel,
    thread_ts: threadTs,
    text: trimForSlack(text, 500),
    unfurl_links: false,
    unfurl_media: false,
  });
}
