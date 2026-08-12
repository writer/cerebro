import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import {
  validateAgentGymCanaryGateDecision,
  type AgentGymCanaryGateDecisionV1,
} from "./canary-gate.js";
import {
  validateAgentGymChampionTransition,
  type AgentGymChampionTransitionV1,
} from "./champion-transition.js";

export type AgentGymCanaryAction =
  | "complete_rollout"
  | "hold_traffic"
  | "increase_traffic"
  | "rollback_candidate";

export interface AgentGymCanaryActionPolicyV1 {
  readonly maximum_traffic_step_percent: number;
  readonly policy_ref: string;
  readonly schema_version: "agent-gym-canary-action-policy/v1";
}

export interface AgentGymCanaryActionPlanV1 {
  readonly action: AgentGymCanaryAction;
  readonly action_ref: string;
  readonly candidate_ref: string;
  readonly expires_at: string;
  readonly from_traffic_percent: number;
  readonly gate_decision_digest: string;
  readonly idempotency_key: string;
  readonly plan_digest: string;
  readonly planned_at: string;
  readonly policy_digest: string;
  readonly policy_ref: string;
  readonly rollback_candidate_ref: string | null;
  readonly schema_version: "agent-gym-canary-action-plan/v1";
  readonly target_ref: string;
  readonly to_traffic_percent: number;
  readonly transition_digest: string;
}

/** Plans one bounded traffic action from an exact canary gate decision. */
export function planAgentGymCanaryAction(
  transitionValue: AgentGymChampionTransitionV1,
  decisionValue: AgentGymCanaryGateDecisionV1,
  policy: AgentGymCanaryActionPolicyV1,
  input: {
    readonly action_ref: string;
    readonly expires_at: string;
    readonly planned_at: string;
    readonly requested_traffic_percent: number;
  },
): AgentGymCanaryActionPlanV1 {
  const transition = validateAgentGymChampionTransition(transitionValue);
  const decision = validateAgentGymCanaryGateDecision(decisionValue);
  validatePolicy(policy);
  reference(input.action_ref);
  timestamp(input.planned_at);
  timestamp(input.expires_at);
  percent(input.requested_traffic_percent);
  if (transition.active_candidate_ref !== decision.candidate_ref
    || transition.target_ref !== decision.target_ref
    || Date.parse(input.planned_at) < Date.parse(decision.evaluated_at)
    || Date.parse(input.expires_at) <= Date.parse(input.planned_at)) invalid();
  let action: AgentGymCanaryAction;
  let rollbackCandidateRef: string | null = null;
  if (decision.disposition === "rollback") {
    if (input.requested_traffic_percent !== 0) invalid();
    action = "rollback_candidate";
    rollbackCandidateRef = transition.from_candidate_ref;
  } else if (decision.disposition === "hold") {
    if (input.requested_traffic_percent !== transition.traffic_percent) invalid();
    action = "hold_traffic";
  } else if (transition.traffic_percent === 100) {
    if (input.requested_traffic_percent !== 100) invalid();
    action = "complete_rollout";
  } else {
    const step = input.requested_traffic_percent - transition.traffic_percent;
    if (step < 1 || step > policy.maximum_traffic_step_percent) invalid();
    action = "increase_traffic";
  }
  const policyBody = {
    maximum_traffic_step_percent: policy.maximum_traffic_step_percent,
    policy_ref: policy.policy_ref,
    schema_version: policy.schema_version,
  };
  const identity = {
    action_ref: input.action_ref,
    gate_decision_digest: decision.decision_digest,
    target_ref: transition.target_ref,
    transition_digest: transition.transition_digest,
  };
  const body = {
    action,
    action_ref: input.action_ref,
    candidate_ref: transition.active_candidate_ref,
    expires_at: input.expires_at,
    from_traffic_percent: transition.traffic_percent,
    gate_decision_digest: decision.decision_digest,
    idempotency_key: digestAgentGymJson(identity),
    planned_at: input.planned_at,
    policy_digest: digestAgentGymJson(policyBody),
    policy_ref: policy.policy_ref,
    rollback_candidate_ref: rollbackCandidateRef,
    schema_version: "agent-gym-canary-action-plan/v1" as const,
    target_ref: transition.target_ref,
    to_traffic_percent: input.requested_traffic_percent,
    transition_digest: transition.transition_digest,
  };
  return Object.freeze({ ...body, plan_digest: digestAgentGymJson(body) });
}

export function validateAgentGymCanaryActionPlan(
  value: AgentGymCanaryActionPlanV1,
): AgentGymCanaryActionPlanV1 {
  if (value.schema_version !== "agent-gym-canary-action-plan/v1") invalid();
  for (const ref of [value.action_ref, value.candidate_ref, value.policy_ref, value.target_ref]) reference(ref);
  if (value.rollback_candidate_ref !== null) reference(value.rollback_candidate_ref);
  timestamp(value.planned_at);
  timestamp(value.expires_at);
  if (Date.parse(value.expires_at) <= Date.parse(value.planned_at)) invalid();
  percent(value.from_traffic_percent);
  percent(value.to_traffic_percent);
  for (const valueDigest of [value.gate_decision_digest, value.idempotency_key,
    value.plan_digest, value.policy_digest, value.transition_digest]) digest(valueDigest);
  if (value.action === "rollback_candidate") {
    if (value.to_traffic_percent !== 0 || value.rollback_candidate_ref === null
      || value.rollback_candidate_ref === value.candidate_ref) invalid();
  } else if (value.action === "hold_traffic") {
    if (value.to_traffic_percent !== value.from_traffic_percent || value.rollback_candidate_ref !== null) invalid();
  } else if (value.action === "increase_traffic") {
    if (value.to_traffic_percent <= value.from_traffic_percent || value.rollback_candidate_ref !== null) invalid();
  } else if (value.action === "complete_rollout") {
    if (value.from_traffic_percent !== 100 || value.to_traffic_percent !== 100
      || value.rollback_candidate_ref !== null) invalid();
  } else invalid();
  const identity = {
    action_ref: value.action_ref,
    gate_decision_digest: value.gate_decision_digest,
    target_ref: value.target_ref,
    transition_digest: value.transition_digest,
  };
  if (digestAgentGymJson(identity) !== value.idempotency_key) invalid();
  const body = {
    action: value.action,
    action_ref: value.action_ref,
    candidate_ref: value.candidate_ref,
    expires_at: value.expires_at,
    from_traffic_percent: value.from_traffic_percent,
    gate_decision_digest: value.gate_decision_digest,
    idempotency_key: value.idempotency_key,
    planned_at: value.planned_at,
    policy_digest: value.policy_digest,
    policy_ref: value.policy_ref,
    rollback_candidate_ref: value.rollback_candidate_ref,
    schema_version: value.schema_version,
    target_ref: value.target_ref,
    to_traffic_percent: value.to_traffic_percent,
    transition_digest: value.transition_digest,
  };
  if (digestAgentGymJson(body) !== value.plan_digest) invalid();
  return Object.freeze({ ...value });
}

function validatePolicy(value: AgentGymCanaryActionPolicyV1): void {
  if (value.schema_version !== "agent-gym-canary-action-policy/v1") invalid();
  reference(value.policy_ref);
  if (!Number.isSafeInteger(value.maximum_traffic_step_percent)
    || value.maximum_traffic_step_percent < 1 || value.maximum_traffic_step_percent > 100) invalid();
}
function digest(value: string): void { if (!/^sha256:[0-9a-f]{64}$/u.test(value)) invalid(); }
function percent(value: number): void {
  if (!Number.isSafeInteger(value) || value < 0 || value > 100) invalid();
}
function reference(value: string): void {
  if (typeof value !== "string" || value.length > 240 || !/^[a-z][a-z0-9+.-]*:\/\/\S+$/u.test(value)) invalid();
}
function timestamp(value: string): void {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)
    || !Number.isFinite(Date.parse(value))) invalid();
}
function invalid(): never { throw new AgentGymContractError("Agent gym canary action plan is invalid."); }
