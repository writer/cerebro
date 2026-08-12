import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import {
  validateAgentGymCanaryActionPlan,
  type AgentGymCanaryActionPlanV1,
} from "./canary-action-plan.js";
import {
  validateAgentGymCanaryActionReceipt,
  type AgentGymCanaryActionReceiptV1,
} from "./canary-action-receipt.js";
import {
  validateAgentGymCanaryActionVerification,
  type AgentGymCanaryActionVerificationV1,
} from "./canary-action-verification.js";

export type AgentGymRolloutPhase = "active" | "canary" | "rolled_back";

export interface AgentGymRolloutStateV1 {
  readonly action: AgentGymCanaryActionPlanV1["action"];
  readonly action_receipt_digest: string;
  readonly active_candidate_ref: string;
  readonly candidate_ref: string;
  readonly candidate_traffic_percent: number;
  readonly effective_at: string;
  readonly phase: AgentGymRolloutPhase;
  readonly previous_state_digest: string | null;
  readonly schema_version: "agent-gym-rollout-state/v1";
  readonly sequence: number;
  readonly state_digest: string;
  readonly state_ref: string;
  readonly target_ref: string;
  readonly verification_digest: string;
}

/** Advances rollout state only from a successfully verified traffic action. */
export function advanceAgentGymRolloutState(
  planValue: AgentGymCanaryActionPlanV1,
  receiptValue: AgentGymCanaryActionReceiptV1,
  verificationValue: AgentGymCanaryActionVerificationV1,
  previousValue: AgentGymRolloutStateV1 | undefined,
  input: { readonly effective_at: string; readonly state_ref: string },
): AgentGymRolloutStateV1 {
  const plan = validateAgentGymCanaryActionPlan(planValue);
  const receipt = validateAgentGymCanaryActionReceipt(receiptValue);
  const verification = validateAgentGymCanaryActionVerification(verificationValue);
  const previous = previousValue === undefined ? undefined : validateAgentGymRolloutState(previousValue);
  timestamp(input.effective_at);
  reference(input.state_ref);
  if (!verification.verified || receipt.status !== "applied"
    || receipt.plan_digest !== plan.plan_digest || verification.plan_digest !== plan.plan_digest
    || verification.action_receipt_digest !== receipt.receipt_digest
    || Date.parse(input.effective_at) < Date.parse(verification.verified_at)) invalid();
  if (previous !== undefined && (previous.target_ref !== plan.target_ref
    || previous.candidate_ref !== plan.candidate_ref
    || previous.candidate_traffic_percent !== plan.from_traffic_percent)) invalid();
  const activeCandidateRef = plan.action === "rollback_candidate"
    ? plan.rollback_candidate_ref
    : plan.candidate_ref;
  if (activeCandidateRef === null) invalid();
  let phase: AgentGymRolloutPhase;
  if (plan.action === "rollback_candidate") phase = "rolled_back";
  else if (plan.action === "complete_rollout") phase = "active";
  else phase = "canary";
  const body = {
    action: plan.action,
    action_receipt_digest: receipt.receipt_digest,
    active_candidate_ref: activeCandidateRef,
    candidate_ref: plan.candidate_ref,
    candidate_traffic_percent: plan.to_traffic_percent,
    effective_at: input.effective_at,
    phase,
    previous_state_digest: previous?.state_digest ?? null,
    schema_version: "agent-gym-rollout-state/v1" as const,
    sequence: (previous?.sequence ?? 0) + 1,
    state_ref: input.state_ref,
    target_ref: plan.target_ref,
    verification_digest: verification.verification_digest,
  };
  return Object.freeze({ ...body, state_digest: digestAgentGymJson(body) });
}

export function validateAgentGymRolloutState(value: AgentGymRolloutStateV1): AgentGymRolloutStateV1 {
  if (value.schema_version !== "agent-gym-rollout-state/v1") invalid();
  for (const ref of [value.active_candidate_ref, value.candidate_ref, value.state_ref,
    value.target_ref]) reference(ref);
  timestamp(value.effective_at);
  for (const valueDigest of [value.action_receipt_digest, value.state_digest,
    value.verification_digest]) digest(valueDigest);
  if (value.previous_state_digest !== null) digest(value.previous_state_digest);
  if (!Number.isSafeInteger(value.sequence) || value.sequence < 1 || value.sequence > 1_000_000
    || !Number.isSafeInteger(value.candidate_traffic_percent)
    || value.candidate_traffic_percent < 0 || value.candidate_traffic_percent > 100) invalid();
  if ((value.sequence === 1) !== (value.previous_state_digest === null)) invalid();
  if (value.phase === "active") {
    if (value.action !== "complete_rollout" || value.candidate_traffic_percent !== 100
      || value.active_candidate_ref !== value.candidate_ref) invalid();
  } else if (value.phase === "rolled_back") {
    if (value.action !== "rollback_candidate" || value.candidate_traffic_percent !== 0
      || value.active_candidate_ref === value.candidate_ref) invalid();
  } else if (value.phase === "canary") {
    if (!(value.action === "increase_traffic" || value.action === "hold_traffic")
      || value.candidate_traffic_percent < 1 || value.candidate_traffic_percent > 99
      || value.active_candidate_ref !== value.candidate_ref) invalid();
  } else invalid();
  const body = {
    action: value.action,
    action_receipt_digest: value.action_receipt_digest,
    active_candidate_ref: value.active_candidate_ref,
    candidate_ref: value.candidate_ref,
    candidate_traffic_percent: value.candidate_traffic_percent,
    effective_at: value.effective_at,
    phase: value.phase,
    previous_state_digest: value.previous_state_digest,
    schema_version: value.schema_version,
    sequence: value.sequence,
    state_ref: value.state_ref,
    target_ref: value.target_ref,
    verification_digest: value.verification_digest,
  };
  if (digestAgentGymJson(body) !== value.state_digest) invalid();
  return Object.freeze({ ...value });
}

function digest(value: string): void { if (!/^sha256:[0-9a-f]{64}$/u.test(value)) invalid(); }
function reference(value: string): void {
  if (typeof value !== "string" || value.length > 240 || !/^[a-z][a-z0-9+.-]*:\/\/\S+$/u.test(value)) invalid();
}
function timestamp(value: string): void {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)
    || !Number.isFinite(Date.parse(value))) invalid();
}
function invalid(): never { throw new AgentGymContractError("Agent gym rollout state is invalid."); }
