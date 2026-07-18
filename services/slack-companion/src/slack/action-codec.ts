export interface ActionPayload {
  kind:
    | "finding_note"
    | "finding_assign"
    | "finding_due"
    | "finding_resolve"
    | "finding_suppress"
    | "finding_evidence"
    | "graph_action_dry_run"
    | "graph_action_execute"
    | "runtime_sync"
    | "runtime_ingest"
    | "runtime_evaluate"
    | "autonomy_approval_approve"
    | "autonomy_approval_reject"
    | "proactive_suggestion_accept"
    | "proactive_suggestion_dismiss"
    | "monitor_suggestion_accept"
    | "monitor_suggestion_dismiss"
    | "assistant_feedback_helpful"
    | "assistant_feedback_helpful_detail"
    | "assistant_feedback_needs_work"
    | "assistant_feedback_evidence"
    | "risk_attestation_response";
  runtimeId?: string;
  findingId?: string;
  goalId?: string;
  approvalId?: string;
  suggestionId?: string;
  threadTs?: string;
  channelId?: string;
  action?: string;
  externalId?: string;
  answerId?: string;
  confirmationId?: string;
  confirmationResponse?: "yes" | "no" | "unsure";
  feedbackDetail?:
    | "correct"
    | "completed_action"
    | "useful_evidence"
    | "right_detail"
    | "identified_issue"
    | "initiative"
    | "clear_explanation";
}

export function encodeAction(payload: ActionPayload): string {
  return Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
}

export function decodeAction(value: string | undefined): ActionPayload {
  if (!value) {
    throw new Error("action value is missing");
  }
  const decoded = JSON.parse(Buffer.from(value, "base64url").toString("utf8")) as ActionPayload;
  if (!decoded.kind) {
    throw new Error("action kind is missing");
  }
  return decoded;
}
