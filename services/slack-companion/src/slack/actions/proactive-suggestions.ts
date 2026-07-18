import { assessDangerousIntent } from "../../security/safety.js";
import { actionIds } from "../blocks/index.js";
import type { ActionDeps } from "./types.js";
import { errorMessage, payloadFromAction, recordDailyNote, required } from "./utils.js";

export function registerProactiveSuggestionActions(app: any, deps: ActionDeps): void {
  app.action(actionIds.proactiveSuggestionAccept, async ({ body, action, ack, respond }: any) => {
    await ack();
    try {
      const payload = payloadFromAction(action, body);
      const channelId = required(payload.channelId ?? body.channel?.id, "channel id");
      const threadTs = required(payload.threadTs, "thread ts");
      const suggestionId = required(payload.suggestionId, "suggestion id");
      if (!deps.threadState) throw new Error("Thread state store is not configured.");
      const current = await deps.threadState.get(channelId, threadTs);
      const pending = current?.proactiveSuggestions.find((suggestion) => suggestion.id === suggestionId && suggestion.status === "pending");
      if (!pending) throw new Error("Proactive suggestion is no longer pending.");
      const safety = assessDangerousIntent(pending.goalText);
      if (!safety.allowed) throw new Error(safety.refusal ?? "Cerebro cannot create that goal.");
      const actor = deps.auth.actorFor(body.user.id);
      const goal = await deps.goals.createFromText({
        text: pending.goalText,
        actor,
        channelId,
        threadTs,
      });
      await deps.threadState.resolveProactiveSuggestion({ channelId, threadTs, suggestionId, status: "accepted", goalId: goal.id });
      await respond({ response_type: "ephemeral", text: `Created goal ${goal.id}.` });
      await recordDailyNote(deps, {
        kind: "maintenance",
        title: "Proactive suggestion accepted",
        summary: `Created autonomy goal ${goal.id} from ${suggestionId}.`,
        details: pending.goalText,
        tags: ["slack-action", "proactive-suggestion", "accepted"],
        channelId,
        sourceTs: threadTs,
        outcome: "created",
      });
    } catch (error) {
      await respond({ response_type: "ephemeral", text: errorMessage(error) });
      await recordDailyNote(deps, {
        kind: "failure",
        title: "Proactive suggestion accept failed",
        summary: errorMessage(error),
        tags: ["slack-action", "proactive-suggestion", "failure"],
        channelId: body.channel?.id,
        outcome: "failed",
      });
    }
  });

  app.action(actionIds.proactiveSuggestionDismiss, async ({ body, action, ack, respond }: any) => {
    await ack();
    try {
      const payload = payloadFromAction(action, body);
      const channelId = required(payload.channelId ?? body.channel?.id, "channel id");
      const threadTs = required(payload.threadTs, "thread ts");
      const suggestionId = required(payload.suggestionId, "suggestion id");
      if (!deps.threadState) throw new Error("Thread state store is not configured.");
      await deps.threadState.resolveProactiveSuggestion({ channelId, threadTs, suggestionId, status: "dismissed" });
      await respond({ response_type: "ephemeral", text: `Dismissed suggestion ${suggestionId}.` });
      await recordDailyNote(deps, {
        kind: "maintenance",
        title: "Proactive suggestion dismissed",
        summary: `Dismissed proactive suggestion ${suggestionId}.`,
        tags: ["slack-action", "proactive-suggestion", "dismissed"],
        channelId,
        sourceTs: threadTs,
        outcome: "dismissed",
      });
    } catch (error) {
      await respond({ response_type: "ephemeral", text: errorMessage(error) });
      await recordDailyNote(deps, {
        kind: "failure",
        title: "Proactive suggestion dismiss failed",
        summary: errorMessage(error),
        tags: ["slack-action", "proactive-suggestion", "failure"],
        channelId: body.channel?.id,
        outcome: "failed",
      });
    }
  });
}
