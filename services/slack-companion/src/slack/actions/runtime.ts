import { actionIds } from "../blocks/index.js";
import type { ActionDeps } from "./types.js";
import { errorMessage, payloadFromAction, recordDailyNote, required } from "./utils.js";

export function registerRuntimeActions(app: any, deps: ActionDeps): void {
  for (const [actionId, operation] of [
    [actionIds.runtimeSync, "sync"],
    [actionIds.runtimeIngest, "ingest"],
    [actionIds.runtimeEvaluate, "evaluate"],
  ] as const) {
    app.action(actionId, async ({ body, action, ack, respond }: any) => {
      await ack();
      try {
        deps.auth.requireWrite(body.user.id, "source");
        const payload = payloadFromAction(action, body);
        const runtimeId = required(payload.runtimeId, "runtime id");
        if (operation === "sync") await deps.cerebro.syncRuntime(runtimeId);
        if (operation === "ingest") await deps.cerebro.runGraphIngest(runtimeId);
        if (operation === "evaluate") await deps.cerebro.evaluateFindings(runtimeId);
        await respond({ response_type: "ephemeral", text: `${operation} started for ${runtimeId}.` });
        await recordDailyNote(deps, {
          kind: "runtime_action",
          title: `Runtime ${operation}`,
          summary: `${operation} started for ${runtimeId} from a Slack action.`,
          details: `Runtime: ${runtimeId}`,
          tags: ["slack-action", "runtime-action", operation],
          channelId: body.channel?.id,
          outcome: "started",
        });
      } catch (error) {
        await respond({ response_type: "ephemeral", text: errorMessage(error) });
        await recordDailyNote(deps, {
          kind: "failure",
          title: `Runtime ${operation} failed`,
          summary: errorMessage(error),
          tags: ["slack-action", "runtime-action", operation, "failure"],
          channelId: body.channel?.id,
          outcome: "failed",
        });
      }
    });
  }
}
