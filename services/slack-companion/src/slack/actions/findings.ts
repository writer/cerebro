import type { ActionPayload } from "../action-codec.js";
import { decodeAction } from "../action-codec.js";
import { actionIds, evidenceBlocks } from "../blocks/index.js";
import { openTextModal, viewValue } from "../modals.js";
import { logger } from "../../logger.js";
import type { ActionDeps } from "./types.js";
import { errorMessage, payloadFromAction, postModalResult, recordDailyNote, required } from "./utils.js";

export function registerFindingActions(app: any, deps: ActionDeps): void {
  app.action(actionIds.findingEvidence, async ({ body, action, ack, respond }: any) => {
    await ack();
    const payload = payloadFromAction(action, body);
    const evidence = await deps.cerebro.listFindingEvidence(required(payload.runtimeId, "runtime id"), required(payload.findingId, "finding id"), 8);
    await respond({ response_type: "ephemeral", text: "Finding evidence", blocks: evidenceBlocks(payload.runtimeId!, payload.findingId!, evidence) });
  });

  app.action(actionIds.findingNote, async ({ body, action, ack, client }: any) => {
    await ack();
    await openFindingTextModal(client, body.trigger_id, "Add note", "cerebro_finding_note_submit", payloadFromAction(action, body), "Note", true);
  });

  app.action(actionIds.findingAssign, async ({ body, action, ack, client }: any) => {
    await ack();
    await openFindingTextModal(client, body.trigger_id, "Assign finding", "cerebro_finding_assign_submit", payloadFromAction(action, body), "Assignee", false, "secops");
  });

  app.action(actionIds.findingDue, async ({ body, action, ack, client }: any) => {
    await ack();
    await openFindingTextModal(client, body.trigger_id, "Set due date", "cerebro_finding_due_submit", payloadFromAction(action, body), "Due date", false, "2026-07-01T17:00:00Z");
  });

  app.action(actionIds.findingResolve, async ({ body, action, ack, client }: any) => {
    await ack();
    await openFindingTextModal(client, body.trigger_id, "Resolve finding", "cerebro_finding_resolve_submit", payloadFromAction(action, body), "Reason", true);
  });

  app.action(actionIds.findingSuppress, async ({ body, action, ack, client }: any) => {
    await ack();
    await openFindingTextModal(client, body.trigger_id, "Suppress finding", "cerebro_finding_suppress_submit", payloadFromAction(action, body), "Reason", true);
  });

  registerFindingViewHandlers(app, deps);
}

function registerFindingViewHandlers(app: any, deps: ActionDeps): void {
  app.view("cerebro_finding_note_submit", async ({ ack, body, view, client }: any) => {
    await ack();
    await runFindingWrite(deps, body, view, client, "note", async (payload, value) => deps.cerebro.addFindingNote(required(payload.findingId, "finding id"), value), "Note added.");
  });

  app.view("cerebro_finding_assign_submit", async ({ ack, body, view, client }: any) => {
    await ack();
    await runFindingWrite(deps, body, view, client, "assign", async (payload, value) => deps.cerebro.assignFinding(required(payload.findingId, "finding id"), value), "Finding assigned.");
  });

  app.view("cerebro_finding_due_submit", async ({ ack, body, view, client }: any) => {
    await ack();
    await runFindingWrite(deps, body, view, client, "due", async (payload, value) => deps.cerebro.setFindingDueDate(required(payload.findingId, "finding id"), value), "Due date set.");
  });

  app.view("cerebro_finding_resolve_submit", async ({ ack, body, view, client }: any) => {
    await ack();
    await runFindingWrite(deps, body, view, client, "resolve", async (payload, value) => deps.cerebro.resolveFinding(required(payload.findingId, "finding id"), value), "Finding resolved.");
  });

  app.view("cerebro_finding_suppress_submit", async ({ ack, body, view, client }: any) => {
    await ack();
    await runFindingWrite(deps, body, view, client, "suppress", async (payload, value) => deps.cerebro.suppressFinding(required(payload.findingId, "finding id"), value), "Finding suppressed.");
  });
}

async function openFindingTextModal(
  client: any,
  triggerId: string,
  title: string,
  callbackId: string,
  payload: ActionPayload,
  label: string,
  multiline: boolean,
  placeholder?: string,
): Promise<void> {
  await openTextModal(client, triggerId, {
    title,
    callbackId,
    payload,
    label,
    actionId: "value",
    multiline,
    placeholder,
  });
}

async function runFindingWrite(
  deps: ActionDeps,
  body: any,
  view: any,
  client: any,
  operation: string,
  write: (payload: ActionPayload, value: string) => Promise<unknown>,
  success: string,
): Promise<void> {
  const payload = decodeAction(view.private_metadata);
  const value = viewValue(view, "input");
  try {
    deps.auth.requireWrite(body.user.id, "findings");
    if (!value.trim()) {
      throw new Error("A value is required.");
    }
    const response = await write(payload, value.trim());
    await postModalResult(client, payload, body.user.id, success, response);
    await recordDailyNote(deps, {
      kind: "finding_action",
      title: `Finding ${operation}`,
      summary: `${success} Finding ${payload.findingId ?? "unknown"} was updated from Slack.`,
      details: [`Finding: ${payload.findingId ?? "unknown"}`, `Runtime: ${payload.runtimeId ?? "unknown"}`, `Value: ${value.trim()}`].join("\n"),
      tags: ["slack-action", "finding-action", operation],
      channelId: payload.channelId,
      outcome: "completed",
    });
  } catch (error) {
    logger.warn("finding write failed", { error: String(error), user: body.user.id });
    await postModalResult(client, payload, body.user.id, errorMessage(error));
    await recordDailyNote(deps, {
      kind: "failure",
      title: `Finding ${operation} failed`,
      summary: errorMessage(error),
      details: [`Finding: ${payload.findingId ?? "unknown"}`, `Runtime: ${payload.runtimeId ?? "unknown"}`].join("\n"),
      tags: ["slack-action", "finding-action", operation, "failure"],
      channelId: payload.channelId,
      outcome: "failed",
    });
  }
}
