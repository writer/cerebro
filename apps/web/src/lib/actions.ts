export type ActionState =
  | "proposed"
  | "simulated"
  | "waiting_for_approval"
  | "approved"
  | "claimed"
  | "executing"
  | "outcome_unknown"
  | "completed"
  | "reconciled"
  | "verified"
  | "failed"
  | "rolled_back";

export type ActionOperation = {
  proposal: {
    operation_id: string;
    tenant_id: string;
    finding_id: string;
    finding_revision_digest: string;
    finding_validation_receipt_digest: string;
    graph_revision: number;
    action_kind: string;
    action_definition_digest: string;
    target_id: string;
    expected_effects: Array<{
      target_id: string;
      effect_kind: string;
      expected_state_digest: string;
    }>;
    rollback_ref: string;
    idempotency_key: string;
    simulation_digest: string;
    verification_plan_digest: string;
    proposed_by: string;
    proposed_at_unix_ms: number;
    proposal_expires_at_unix_ms: number;
    proposal_digest: string;
  };
  state: ActionState;
  version: number;
  approval_receipt?: {
    decision_id: string;
    proposal_digest: string;
    approved: boolean;
    decided_by: string;
    decided_at_unix_ms: number;
  } | null;
  claimed_by?: string | null;
  claimed_at_unix_ms?: number | null;
  claim_expires_at_unix_ms?: number | null;
  executor_actor_id?: string | null;
  executed_at_unix_ms?: number | null;
  external_receipt_ref?: string | null;
  observed_effect_digest?: string | null;
  verification_state: "pending" | "verified" | "rejected" | "stale";
  verification_receipt?: {
    operation_id: string;
    proposal_digest: string;
    observed_effect_digest: string;
    receipt: {
      verification_id: string;
      executor_actor_id: string;
      verifier_actor_id: string;
      previous_source_revision: string;
      observed_source_revision: string;
      effective: boolean;
      evidence_urns: string[];
      verified_at_unix_ms: number;
    };
  } | null;
};

export type ActionPage = {
  actions: ActionOperation[];
  next_page_token?: string | null;
};

export type ActionEvent = {
  actor_id: string;
  event_kind: string;
  command_digest?: string | null;
  operation_digest: string;
  committed_at_unix_ms: number;
  operation: ActionOperation;
};

export const actionStateLabel = (state: string) =>
  state
    .split("_")
    .map((part) => part ? part[0].toUpperCase() + part.slice(1) : part)
    .join(" ");

export const actionTimeLabel = (unixMillis?: number | null) => {
  if (!unixMillis || !Number.isSafeInteger(unixMillis) || unixMillis < 1) return "Not recorded";
  const value = new Date(unixMillis);
  if (Number.isNaN(value.getTime())) return "Not recorded";
  return new Intl.DateTimeFormat(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(value);
};

export const actionStateIntent = (state: ActionState) => {
  if (state === "verified") return "success" as const;
  if (state === "failed" || state === "outcome_unknown") return "danger" as const;
  if (state === "waiting_for_approval" || state === "rolled_back") return "warning" as const;
  return "neutral" as const;
};

export const summarizeActionPage = (actions: ActionOperation[]) =>
  actions.reduce(
    (summary, action) => {
      if (action.state === "waiting_for_approval") summary.waitingForApproval += 1;
      if (["claimed", "executing", "outcome_unknown"].includes(action.state)) summary.inExecution += 1;
      if (action.state === "verified") summary.verified += 1;
      if (action.state === "failed" || action.state === "rolled_back") summary.failedOrRolledBack += 1;
      return summary;
    },
    { waitingForApproval: 0, inExecution: 0, verified: 0, failedOrRolledBack: 0 },
  );
