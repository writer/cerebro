import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import {
  validateAgentGymCanaryWindow,
  type AgentGymCanaryWindowV1,
} from "./canary-window.js";

export type AgentGymCanaryGateDisposition = "advance" | "hold" | "rollback";
export type AgentGymCanaryGateBlockerCode =
  | "canary.critical_blocker"
  | "canary.failure_rate_exceeded"
  | "canary.insufficient_samples"
  | "canary.latency_exceeded"
  | "canary.quality_below_minimum";

export interface AgentGymCanaryGatePolicyV1 {
  readonly maximum_failure_rate: number;
  readonly maximum_p95_latency_ms: number;
  readonly minimum_mean_quality_score: number;
  readonly minimum_observation_count: number;
  readonly policy_ref: string;
  readonly rollback_blocker_codes: readonly string[];
  readonly schema_version: "agent-gym-canary-gate-policy/v1";
}

export interface AgentGymCanaryGateDecisionV1 {
  readonly blocker_codes: readonly AgentGymCanaryGateBlockerCode[];
  readonly candidate_ref: string;
  readonly decision_digest: string;
  readonly decision_ref: string;
  readonly disposition: AgentGymCanaryGateDisposition;
  readonly evaluated_at: string;
  readonly observed_failure_rate: number;
  readonly policy_digest: string;
  readonly policy_ref: string;
  readonly schema_version: "agent-gym-canary-gate-decision/v1";
  readonly target_ref: string;
  readonly window_digest: string;
}

/** Applies explicit canary thresholds without environment-specific mutation. */
export function decideAgentGymCanaryGate(
  windowValue: AgentGymCanaryWindowV1,
  policy: AgentGymCanaryGatePolicyV1,
  input: { readonly decision_ref: string; readonly evaluated_at: string },
): AgentGymCanaryGateDecisionV1 {
  const window = validateAgentGymCanaryWindow(windowValue);
  validatePolicy(policy);
  reference(input.decision_ref);
  timestamp(input.evaluated_at);
  if (Date.parse(input.evaluated_at) < Date.parse(window.ended_at)) invalid();
  const failureRate = window.failed_count / window.observation_count;
  const blockers = new Set<AgentGymCanaryGateBlockerCode>();
  const insufficient = window.observation_count < policy.minimum_observation_count;
  const critical = window.blocker_codes.some((code) => policy.rollback_blocker_codes.includes(code));
  if (insufficient) blockers.add("canary.insufficient_samples");
  if (critical) blockers.add("canary.critical_blocker");
  if (failureRate > policy.maximum_failure_rate) blockers.add("canary.failure_rate_exceeded");
  if (window.p95_latency_ms > policy.maximum_p95_latency_ms) blockers.add("canary.latency_exceeded");
  if (window.mean_quality_score < policy.minimum_mean_quality_score) {
    blockers.add("canary.quality_below_minimum");
  }
  const blockerCodes = [...blockers].sort();
  const thresholdFailure = blockerCodes.some((code) => code !== "canary.insufficient_samples");
  const disposition: AgentGymCanaryGateDisposition = critical || (!insufficient && thresholdFailure)
    ? "rollback"
    : insufficient ? "hold" : "advance";
  const policyBody = {
    maximum_failure_rate: policy.maximum_failure_rate,
    maximum_p95_latency_ms: policy.maximum_p95_latency_ms,
    minimum_mean_quality_score: policy.minimum_mean_quality_score,
    minimum_observation_count: policy.minimum_observation_count,
    policy_ref: policy.policy_ref,
    rollback_blocker_codes: [...policy.rollback_blocker_codes],
    schema_version: policy.schema_version,
  };
  const body = {
    blocker_codes: blockerCodes,
    candidate_ref: window.candidate_ref,
    decision_ref: input.decision_ref,
    disposition,
    evaluated_at: input.evaluated_at,
    observed_failure_rate: failureRate,
    policy_digest: digestAgentGymJson(policyBody),
    policy_ref: policy.policy_ref,
    schema_version: "agent-gym-canary-gate-decision/v1" as const,
    target_ref: window.target_ref,
    window_digest: window.window_digest,
  };
  return Object.freeze({
    ...body,
    blocker_codes: Object.freeze(blockerCodes),
    decision_digest: digestAgentGymJson(body),
  });
}

export function validateAgentGymCanaryGateDecision(
  value: AgentGymCanaryGateDecisionV1,
): AgentGymCanaryGateDecisionV1 {
  if (value.schema_version !== "agent-gym-canary-gate-decision/v1") invalid();
  for (const ref of [value.candidate_ref, value.decision_ref, value.policy_ref, value.target_ref]) reference(ref);
  timestamp(value.evaluated_at);
  for (const valueDigest of [value.decision_digest, value.policy_digest, value.window_digest]) digest(valueDigest);
  finite(value.observed_failure_rate, 0, 1);
  const allowed: readonly AgentGymCanaryGateBlockerCode[] = [
    "canary.critical_blocker", "canary.failure_rate_exceeded", "canary.insufficient_samples",
    "canary.latency_exceeded", "canary.quality_below_minimum",
  ];
  if (!Array.isArray(value.blocker_codes) || value.blocker_codes.length > allowed.length
    || new Set(value.blocker_codes).size !== value.blocker_codes.length
    || value.blocker_codes.some((code) => !allowed.includes(code))
    || value.blocker_codes.some((code, index) => index > 0 && value.blocker_codes[index - 1]! >= code)) invalid();
  if (value.disposition === "advance") {
    if (value.blocker_codes.length !== 0) invalid();
  } else if (value.disposition === "hold") {
    if (!value.blocker_codes.includes("canary.insufficient_samples")
      || value.blocker_codes.includes("canary.critical_blocker")) invalid();
  } else if (value.disposition === "rollback") {
    if (value.blocker_codes.length === 0) invalid();
  } else invalid();
  const body = {
    blocker_codes: value.blocker_codes,
    candidate_ref: value.candidate_ref,
    decision_ref: value.decision_ref,
    disposition: value.disposition,
    evaluated_at: value.evaluated_at,
    observed_failure_rate: value.observed_failure_rate,
    policy_digest: value.policy_digest,
    policy_ref: value.policy_ref,
    schema_version: value.schema_version,
    target_ref: value.target_ref,
    window_digest: value.window_digest,
  };
  if (digestAgentGymJson(body) !== value.decision_digest) invalid();
  return Object.freeze({ ...value, blocker_codes: Object.freeze([...value.blocker_codes]) });
}

function validatePolicy(value: AgentGymCanaryGatePolicyV1): void {
  if (value.schema_version !== "agent-gym-canary-gate-policy/v1") invalid();
  reference(value.policy_ref);
  finite(value.maximum_failure_rate, 0, 1);
  finite(value.minimum_mean_quality_score, 0, 1);
  integer(value.maximum_p95_latency_ms, 3_600_000, false);
  integer(value.minimum_observation_count, 1_000_000, false);
  if (!Array.isArray(value.rollback_blocker_codes) || value.rollback_blocker_codes.length > 64
    || new Set(value.rollback_blocker_codes).size !== value.rollback_blocker_codes.length) invalid();
  for (const code of value.rollback_blocker_codes) text(code);
}
function digest(value: string): void { if (!/^sha256:[0-9a-f]{64}$/u.test(value)) invalid(); }
function finite(value: number, minimum: number, maximum: number): void {
  if (!Number.isFinite(value) || value < minimum || value > maximum) invalid();
}
function integer(value: number, maximum: number, allowZero = true): void {
  if (!Number.isSafeInteger(value) || value < (allowZero ? 0 : 1) || value > maximum) invalid();
}
function reference(value: string): void {
  if (typeof value !== "string" || value.length > 240 || !/^[a-z][a-z0-9+.-]*:\/\/\S+$/u.test(value)) invalid();
}
function text(value: string): void {
  if (typeof value !== "string" || !value.trim() || value.length > 160
    || /[\u0000-\u001f\u007f]/u.test(value)) invalid();
}
function timestamp(value: string): void {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)
    || !Number.isFinite(Date.parse(value))) invalid();
}
function invalid(): never { throw new AgentGymContractError("Agent gym canary gate is invalid."); }
