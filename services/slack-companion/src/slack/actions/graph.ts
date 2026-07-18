import { assessDangerousIntent } from "../../security/safety.js";
import { decodeAction } from "../action-codec.js";
import { actionIds } from "../blocks/index.js";
import { openGraphActionModal, viewValue } from "../modals.js";
import type { ActionDeps } from "./types.js";
import { errorMessage, payloadFromAction, postModalResult, recordDailyNote, required } from "./utils.js";

export function registerGraphActions(app: any, deps: ActionDeps): void {
  app.action(actionIds.graphActionDryRun, async ({ body, action, ack, client }: any) => {
    await ack();
    await openGraphActionModal(client, body.trigger_id, payloadFromAction(action, body));
  });

  app.view("cerebro_graph_action_submit", async ({ ack, body, view, client }: any) => {
    await ack();
    const payload = decodeAction(view.private_metadata);
    const action = viewValue(view, "action");
    const reason = viewValue(view, "reason");
    try {
      deps.auth.requireWrite(body.user.id, "graphActions");
      const safety = assessDangerousIntent(`${action}\n${reason}`);
      if (!safety.allowed) {
        await postModalResult(client, payload, body.user.id, safety.refusal ?? "I cannot help with that request.");
        await recordDailyNote(deps, {
          kind: "safety_refusal",
          title: "Graph action refused",
          summary: safety.reason ?? "Cerebro refused an unsafe graph action request.",
          details: [`Category: ${safety.category ?? "unsafe_request"}`, `Action: ${action}`, `Reason: ${reason}`].join("\n"),
          tags: ["safety-refusal", safety.category ?? "unsafe-request", "graph-action"],
          channelId: payload.channelId,
          outcome: "refused",
        });
        return;
      }
      const findingId = required(payload.findingId, "finding id");
      const response = await deps.cerebro.executeGraphAction({
        action: action as any,
        finding_id: findingId,
        reason,
        dry_run: true,
        idempotency_key: deps.cerebro.stableIdempotencyKey(["slack-graph-action-dry-run", body.user.id, findingId, action]),
      });
      await postModalResult(client, payload, body.user.id, `Dry run complete for ${action}.`, response);
      await recordDailyNote(deps, {
        kind: "runtime_action",
        title: "Graph action dry run",
        summary: `Dry run completed for ${action}.`,
        details: [`Finding: ${findingId}`, `Reason: ${reason}`].join("\n"),
        tags: ["slack-action", "graph-action", "dry-run"],
        channelId: payload.channelId,
        outcome: "dry-run-completed",
      });
    } catch (error) {
      await postModalResult(client, payload, body.user.id, errorMessage(error));
      await recordDailyNote(deps, {
        kind: "failure",
        title: "Graph action dry run failed",
        summary: errorMessage(error),
        details: [`Action: ${action}`, `Reason: ${reason}`].join("\n"),
        tags: ["slack-action", "graph-action", "failure"],
        channelId: payload.channelId,
        outcome: "failed",
      });
    }
  });
}
