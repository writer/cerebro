import { actionIds } from "../blocks/index.js";
import type { ActionDeps } from "./types.js";
import { errorMessage, payloadFromAction, recordDailyNote, required } from "./utils.js";

export function registerAutonomyActions(app: any, deps: ActionDeps): void {
  for (const [actionId, decision] of [
    [actionIds.autonomyApprove, "approved"],
    [actionIds.autonomyReject, "rejected"],
  ] as const) {
    app.action(actionId, async ({ body, action, ack, respond }: any) => {
      await ack();
      try {
        const payload = payloadFromAction(action, body);
        const goalId = required(payload.goalId, "goal id");
        const approvalId = required(payload.approvalId, "approval id");
        deps.auth.requireWrite(body.user.id, "autonomy");
        const actor = deps.auth.actorFor(body.user.id);
        const goal = await deps.goals.decideApproval({
          goalId,
          approvalId,
          decision,
          actor,
        });
        await respond({ response_type: "ephemeral", text: `${decision === "approved" ? "Approved" : "Rejected"} ${approvalId} for ${goal.id}.` });
        await recordDailyNote(deps, {
          kind: "runtime_action",
          title: `Autonomy approval ${decision}`,
          summary: `${decision === "approved" ? "Approved" : "Rejected"} ${approvalId} for ${goal.id}.`,
          details: `Goal: ${goal.objective}`,
          tags: ["slack-action", "autonomy", "approval", decision],
          channelId: body.channel?.id,
          outcome: decision,
        });
      } catch (error) {
        await respond({ response_type: "ephemeral", text: errorMessage(error) });
        await recordDailyNote(deps, {
          kind: "failure",
          title: `Autonomy approval ${decision} failed`,
          summary: errorMessage(error),
          tags: ["slack-action", "autonomy", "approval", decision, "failure"],
          channelId: body.channel?.id,
          outcome: "failed",
        });
      }
    });
  }
}
