import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import {
  validateAgentGymPostRolloutWindow,
  type AgentGymPostRolloutWindowV1,
} from "./post-rollout-window.js";

export type AgentGymPostRolloutDecision = "healthy" | "hold" | "rollback";

export interface AgentGymPostRolloutPolicyV1 {
  readonly max_failed_rate: number;
  readonly max_p95_latency_ms: number;
  readonly min_mean_quality_score: number;
  readonly min_observation_count: number;
  readonly policy_ref: string;
  readonly schema_version: "agent-gym-post-rollout-policy/v1";
}

export interface AgentGymPostRolloutGateV1 {
  readonly blocker_codes: readonly string[];
  readonly candidate_ref: string;
  readonly decision: AgentGymPostRolloutDecision;
  readonly decided_at: string;
  readonly evidence_refs: readonly string[];
  readonly gate_digest: string;
  readonly gate_ref: string;
  readonly policy: AgentGymPostRolloutPolicyV1;
  readonly schema_version: "agent-gym-post-rollout-gate/v1";
  readonly target_ref: string;
  readonly window_digest: string;
}

/** Applies deterministic post-rollout thresholds without calling a provider. */
export function decideAgentGymPostRolloutGate(
  windowValue: AgentGymPostRolloutWindowV1,
  input: Pick<AgentGymPostRolloutGateV1, "decided_at" | "evidence_refs" | "gate_ref" | "policy">,
): AgentGymPostRolloutGateV1 {
  const window = validateAgentGymPostRolloutWindow(windowValue);
  policy(input.policy); reference(input.gate_ref); timestamp(input.decided_at); references(input.evidence_refs);
  if (Date.parse(input.decided_at) < Date.parse(window.sealed_at)) invalid();
  const blockers = [...window.blocker_codes];
  if (window.observation_count < input.policy.min_observation_count) blockers.push("post_rollout_samples_insufficient");
  const failedRate = window.failed_count / window.observation_count;
  if (failedRate > input.policy.max_failed_rate) blockers.push("post_rollout_failure_rate_exceeded");
  if (window.mean_quality_score < input.policy.min_mean_quality_score) blockers.push("post_rollout_quality_below_minimum");
  if (window.p95_latency_ms > input.policy.max_p95_latency_ms) blockers.push("post_rollout_latency_exceeded");
  const blockerCodes = [...new Set(blockers)].sort();
  const hardRegression = blockerCodes.some((code) => code !== "post_rollout_samples_insufficient");
  const body = {
    blocker_codes: blockerCodes,
    candidate_ref: window.candidate_ref,
    decision: hardRegression ? "rollback" as const : blockerCodes.length > 0 ? "hold" as const : "healthy" as const,
    decided_at: input.decided_at,
    evidence_refs: [...input.evidence_refs],
    gate_ref: input.gate_ref,
    policy: policyBody(input.policy),
    schema_version: "agent-gym-post-rollout-gate/v1" as const,
    target_ref: window.target_ref,
    window_digest: window.window_digest,
  };
  return freeze({ ...body, gate_digest: digestAgentGymJson(body) });
}

export function validateAgentGymPostRolloutGate(value: AgentGymPostRolloutGateV1): AgentGymPostRolloutGateV1 {
  if (value.schema_version !== "agent-gym-post-rollout-gate/v1") invalid();
  policy(value.policy); reference(value.candidate_ref); reference(value.target_ref); reference(value.gate_ref);
  timestamp(value.decided_at); references(value.evidence_refs);
  if (!Array.isArray(value.blocker_codes) || value.blocker_codes.length > 128
    || new Set(value.blocker_codes).size !== value.blocker_codes.length
    || value.blocker_codes.some((code) => typeof code !== "string" || !code.trim() || code.length > 160)
    || (value.decision === "healthy" && value.blocker_codes.length !== 0)
    || (value.decision !== "healthy" && value.blocker_codes.length === 0)
    || !["healthy", "hold", "rollback"].includes(value.decision)) invalid();
  digest(value.window_digest); digest(value.gate_digest);
  const { gate_digest: _digest, policy: _policy, ...fields } = value;
  const body = { ...fields, policy: policyBody(value.policy) };
  if (digestAgentGymJson(body) !== value.gate_digest) invalid();
  return freeze(value);
}

function policy(value: AgentGymPostRolloutPolicyV1): void {
  if (value.schema_version !== "agent-gym-post-rollout-policy/v1") invalid();
  reference(value.policy_ref);
  if (!Number.isSafeInteger(value.min_observation_count) || value.min_observation_count < 1
    || value.min_observation_count > 10_000 || !Number.isFinite(value.max_failed_rate)
    || value.max_failed_rate < 0 || value.max_failed_rate > 1
    || !Number.isFinite(value.min_mean_quality_score) || value.min_mean_quality_score < 0
    || value.min_mean_quality_score > 1 || !Number.isSafeInteger(value.max_p95_latency_ms)
    || value.max_p95_latency_ms < 0 || value.max_p95_latency_ms > 3_600_000) invalid();
}
function policyBody(value: AgentGymPostRolloutPolicyV1) {
  return {
    max_failed_rate: value.max_failed_rate,
    max_p95_latency_ms: value.max_p95_latency_ms,
    min_mean_quality_score: value.min_mean_quality_score,
    min_observation_count: value.min_observation_count,
    policy_ref: value.policy_ref,
    schema_version: value.schema_version,
  };
}
function freeze(value: AgentGymPostRolloutGateV1): AgentGymPostRolloutGateV1 {
  return Object.freeze({ ...value, blocker_codes: Object.freeze([...value.blocker_codes]),
    evidence_refs: Object.freeze([...value.evidence_refs]), policy: Object.freeze({ ...value.policy }) });
}
function references(values: readonly string[]): void {
  if (!Array.isArray(values) || values.length === 0 || values.length > 128 || new Set(values).size !== values.length) invalid();
  for (const value of values) reference(value);
}
function reference(value: string): void {
  if (typeof value !== "string" || value.length > 240 || !/^[a-z][a-z0-9+.-]*:\/\/\S+$/u.test(value)) invalid();
}
function timestamp(value: string): void {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) || !Number.isFinite(Date.parse(value))) invalid();
}
function digest(value: string): void { if (!/^sha256:[0-9a-f]{64}$/u.test(value)) invalid(); }
function invalid(): never { throw new AgentGymContractError("Agent gym post-rollout gate is invalid."); }
