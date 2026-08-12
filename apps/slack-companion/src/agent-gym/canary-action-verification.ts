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
  validateAgentGymCanaryStateObservation,
  type AgentGymCanaryStateObservationV1,
} from "./canary-state-observation.js";

export type AgentGymCanaryVerificationBlockerCode =
  | "verification.action_not_applied"
  | "verification.non_independent_observer"
  | "verification.observation_unavailable"
  | "verification.stale_observation"
  | "verification.state_mismatch";

export interface AgentGymCanaryActionVerificationV1 {
  readonly action_receipt_digest: string;
  readonly blocker_codes: readonly AgentGymCanaryVerificationBlockerCode[];
  readonly candidate_ref: string;
  readonly observation_digest: string;
  readonly plan_digest: string;
  readonly schema_version: "agent-gym-canary-action-verification/v1";
  readonly target_ref: string;
  readonly verification_digest: string;
  readonly verification_ref: string;
  readonly verified: boolean;
  readonly verified_at: string;
  readonly verifier_ref: string;
}

/** Verifies an action with a fresh observer that did not execute the action. */
export function verifyAgentGymCanaryAction(
  planValue: AgentGymCanaryActionPlanV1,
  receiptValue: AgentGymCanaryActionReceiptV1,
  observationValue: AgentGymCanaryStateObservationV1,
  input: {
    readonly verification_ref: string;
    readonly verified_at: string;
    readonly verifier_ref: string;
  },
): AgentGymCanaryActionVerificationV1 {
  const plan = validateAgentGymCanaryActionPlan(planValue);
  const receipt = validateAgentGymCanaryActionReceipt(receiptValue);
  const observation = validateAgentGymCanaryStateObservation(observationValue);
  reference(input.verification_ref);
  reference(input.verifier_ref);
  timestamp(input.verified_at);
  if (receipt.plan_digest !== plan.plan_digest || observation.plan_digest !== plan.plan_digest
    || receipt.candidate_ref !== plan.candidate_ref || observation.candidate_ref !== plan.candidate_ref
    || receipt.target_ref !== plan.target_ref || observation.target_ref !== plan.target_ref
    || input.verifier_ref !== observation.observer_ref
    || Date.parse(input.verified_at) < Date.parse(observation.observed_at)) invalid();
  const blockers = new Set<AgentGymCanaryVerificationBlockerCode>();
  if (receipt.status !== "applied") blockers.add("verification.action_not_applied");
  if (observation.status !== "observed") blockers.add("verification.observation_unavailable");
  if (observation.observer_ref === receipt.executor_ref) blockers.add("verification.non_independent_observer");
  if (Date.parse(observation.observed_at) < Date.parse(receipt.completed_at)) {
    blockers.add("verification.stale_observation");
  }
  const expectedActive = plan.action === "rollback_candidate"
    ? plan.rollback_candidate_ref
    : plan.candidate_ref;
  if (observation.status === "observed"
    && (observation.active_candidate_ref !== expectedActive
      || observation.candidate_traffic_percent !== plan.to_traffic_percent)) {
    blockers.add("verification.state_mismatch");
  }
  const blockerCodes = [...blockers].sort();
  const body = {
    action_receipt_digest: receipt.receipt_digest,
    blocker_codes: blockerCodes,
    candidate_ref: plan.candidate_ref,
    observation_digest: observation.observation_digest,
    plan_digest: plan.plan_digest,
    schema_version: "agent-gym-canary-action-verification/v1" as const,
    target_ref: plan.target_ref,
    verification_ref: input.verification_ref,
    verified: blockerCodes.length === 0,
    verified_at: input.verified_at,
    verifier_ref: input.verifier_ref,
  };
  return Object.freeze({
    ...body,
    blocker_codes: Object.freeze(blockerCodes),
    verification_digest: digestAgentGymJson(body),
  });
}

export function validateAgentGymCanaryActionVerification(
  value: AgentGymCanaryActionVerificationV1,
): AgentGymCanaryActionVerificationV1 {
  if (value.schema_version !== "agent-gym-canary-action-verification/v1") invalid();
  for (const ref of [value.candidate_ref, value.target_ref, value.verification_ref,
    value.verifier_ref]) reference(ref);
  timestamp(value.verified_at);
  for (const valueDigest of [value.action_receipt_digest, value.observation_digest,
    value.plan_digest, value.verification_digest]) digest(valueDigest);
  const allowed: readonly AgentGymCanaryVerificationBlockerCode[] = [
    "verification.action_not_applied", "verification.non_independent_observer",
    "verification.observation_unavailable", "verification.stale_observation",
    "verification.state_mismatch",
  ];
  if (!Array.isArray(value.blocker_codes) || value.blocker_codes.length > allowed.length
    || new Set(value.blocker_codes).size !== value.blocker_codes.length
    || value.blocker_codes.some((code) => !allowed.includes(code))
    || value.blocker_codes.some((code, index) => index > 0 && value.blocker_codes[index - 1]! >= code)
    || value.verified !== (value.blocker_codes.length === 0)) invalid();
  const body = {
    action_receipt_digest: value.action_receipt_digest,
    blocker_codes: value.blocker_codes,
    candidate_ref: value.candidate_ref,
    observation_digest: value.observation_digest,
    plan_digest: value.plan_digest,
    schema_version: value.schema_version,
    target_ref: value.target_ref,
    verification_ref: value.verification_ref,
    verified: value.verified,
    verified_at: value.verified_at,
    verifier_ref: value.verifier_ref,
  };
  if (digestAgentGymJson(body) !== value.verification_digest) invalid();
  return Object.freeze({ ...value, blocker_codes: Object.freeze([...value.blocker_codes]) });
}

function digest(value: string): void { if (!/^sha256:[0-9a-f]{64}$/u.test(value)) invalid(); }
function reference(value: string): void {
  if (typeof value !== "string" || value.length > 240 || !/^[a-z][a-z0-9+.-]*:\/\/\S+$/u.test(value)) invalid();
}
function timestamp(value: string): void {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)
    || !Number.isFinite(Date.parse(value))) invalid();
}
function invalid(): never { throw new AgentGymContractError("Agent gym canary action verification is invalid."); }
