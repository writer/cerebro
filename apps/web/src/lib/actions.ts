export type ActionState =
  | "proposed"
  | "simulated"
  | "waiting_for_approval"
  | "approved"
  | "claimed"
  | "executing"
  | "dispatched"
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
  provider_receipt_digest?: string | null;
  provider_status?: string | null;
  provider_observed_at_unix_ms?: number | null;
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

/// Generated policy for one executable action kind, served by /v1/action-definitions.
export type ActionDefinition = {
  definition_digest: string;
  destructive: boolean;
  effect: string;
  id: string;
  provider: string;
  provider_action: string;
  reversible_by: string;
  target_kind: string;
};

export type ActionDefinitionIndex = Record<string, ActionDefinition>;

export const indexActionDefinitions = (definitions: ActionDefinition[] | undefined): ActionDefinitionIndex =>
  (definitions ?? []).reduce<ActionDefinitionIndex>((index, definition) => {
    if (definition?.id) index[definition.id] = definition;
    return index;
  }, {});

export const ACTION_STAGE_IDS = ["proposed", "awaitingApproval", "inFlight", "verified", "attention"] as const;

export type ActionStageID = typeof ACTION_STAGE_IDS[number];

export const ACTION_STAGE_LABELS: Record<ActionStageID, string> = {
  proposed: "Proposed",
  awaitingApproval: "Awaiting Approval",
  inFlight: "In Flight",
  verified: "Verified",
  attention: "Needs Attention",
};

export const ACTION_STAGE_DETAIL: Record<ActionStageID, string> = {
  proposed: "Validated, not yet queued for a decision",
  awaitingApproval: "Blocked on a human decision",
  inFlight: "Approved and running at the provider",
  verified: "Effect observed and independently confirmed",
  attention: "Failed, rolled back, or outcome unknown",
};

// Every authority state maps to exactly one stage, so a new state cannot be
// silently dropped from the queue: the compiler requires an entry here.
const STAGE_BY_ACTION_STATE: Record<ActionState, ActionStageID> = {
  proposed: "proposed",
  simulated: "proposed",
  waiting_for_approval: "awaitingApproval",
  approved: "inFlight",
  claimed: "inFlight",
  executing: "inFlight",
  dispatched: "inFlight",
  completed: "verified",
  reconciled: "verified",
  verified: "verified",
  outcome_unknown: "attention",
  failed: "attention",
  rolled_back: "attention",
};

export const actionStage = (state: ActionState | string): ActionStageID =>
  STAGE_BY_ACTION_STATE[state as ActionState] ?? "attention";

export const actionStageIntent = (stage: ActionStageID) => {
  if (stage === "attention") return "danger" as const;
  if (stage === "awaitingApproval") return "warning" as const;
  if (stage === "verified") return "success" as const;
  return "neutral" as const;
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

export const summarizeActionStages = (actions: ActionOperation[]) =>
  actions.reduce((summary, action) => {
    summary[actionStage(action.state)] += 1;
    return summary;
  }, ACTION_STAGE_IDS.reduce((all, stage) => {
    all[stage] = 0;
    return all;
  }, {} as Record<ActionStageID, number>));
