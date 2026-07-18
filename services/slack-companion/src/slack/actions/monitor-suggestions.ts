import { actionIds } from "../blocks/index.js";
import type { ActionDeps } from "./types.js";
import { errorMessage, payloadFromAction, recordDailyNote, required } from "./utils.js";

export function registerMonitorSuggestionActions(app: any, deps: ActionDeps): void {
  app.action(actionIds.monitorSuggestionAccept, async ({ body, action, ack, respond }: any) => {
    await ack();
    try {
      const payload = payloadFromAction(action, body);
      const channelId = required(payload.channelId ?? body.channel?.id, "channel id");
      const threadTs = required(payload.threadTs, "thread ts");
      const suggestionId = required(payload.suggestionId, "suggestion id");
      if (!deps.threadState) throw new Error("Thread state store is not configured.");
      const current = await deps.threadState.get(channelId, threadTs);
      const pending = current?.suggestions.find((suggestion) => suggestion.id === suggestionId && suggestion.status === "pending");
      if (!pending) throw new Error("Monitor suggestion is no longer pending.");
      const actor = deps.auth.actorFor(body.user.id);
      const job = await deps.scheduler.createFromText({
        text: pending.scheduleText,
        actor,
        channelId,
      });
      await deps.threadState.resolveSuggestion({ channelId, threadTs, suggestionId, status: "accepted" });
      await respond({ response_type: "ephemeral", text: `Created scheduled check ${job.id}.` });
      await recordDailyNote(deps, {
        kind: "maintenance",
        title: "Monitor suggestion accepted",
        summary: `Created scheduled check ${job.id} from ${suggestionId}.`,
        details: pending.scheduleText,
        tags: ["slack-action", "monitor-suggestion", "accepted"],
        channelId,
        sourceTs: threadTs,
        outcome: "accepted",
      });
    } catch (error) {
      await respond({ response_type: "ephemeral", text: errorMessage(error) });
      await recordDailyNote(deps, {
        kind: "failure",
        title: "Monitor suggestion accept failed",
        summary: errorMessage(error),
        tags: ["slack-action", "monitor-suggestion", "failure"],
        channelId: body.channel?.id,
        outcome: "failed",
      });
    }
  });

  app.action(actionIds.monitorSuggestionDismiss, async ({ body, action, ack, respond }: any) => {
    await ack();
    try {
      const payload = payloadFromAction(action, body);
      const channelId = required(payload.channelId ?? body.channel?.id, "channel id");
      const threadTs = required(payload.threadTs, "thread ts");
      const suggestionId = required(payload.suggestionId, "suggestion id");
      if (!deps.threadState) throw new Error("Thread state store is not configured.");
      await deps.threadState.resolveSuggestion({ channelId, threadTs, suggestionId, status: "dismissed" });
      await respond({ response_type: "ephemeral", text: `Dismissed monitor suggestion ${suggestionId}.` });
      await recordDailyNote(deps, {
        kind: "maintenance",
        title: "Monitor suggestion dismissed",
        summary: `Dismissed monitor suggestion ${suggestionId}.`,
        tags: ["slack-action", "monitor-suggestion", "dismissed"],
        channelId,
        sourceTs: threadTs,
        outcome: "dismissed",
      });
    } catch (error) {
      await respond({ response_type: "ephemeral", text: errorMessage(error) });
      await recordDailyNote(deps, {
        kind: "failure",
        title: "Monitor suggestion dismiss failed",
        summary: errorMessage(error),
        tags: ["slack-action", "monitor-suggestion", "failure"],
        channelId: body.channel?.id,
        outcome: "failed",
      });
    }
  });
}
