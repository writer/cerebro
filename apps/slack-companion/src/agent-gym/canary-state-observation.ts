import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import {
  validateAgentGymCanaryActionPlan,
  type AgentGymCanaryActionPlanV1,
} from "./canary-action-plan.js";

export type AgentGymCanaryStateObservationStatus = "observed" | "unavailable";

export interface AgentGymCanaryStateObservationV1 {
  readonly active_candidate_ref: string | null;
  readonly candidate_ref: string;
  readonly candidate_traffic_percent: number | null;
  readonly evidence_refs: readonly string[];
  readonly observation_digest: string;
  readonly observation_ref: string;
  readonly observed_at: string;
  readonly observer_ref: string;
  readonly plan_digest: string;
  readonly reason_codes: readonly string[];
  readonly schema_version: "agent-gym-canary-state-observation/v1";
  readonly status: AgentGymCanaryStateObservationStatus;
  readonly target_ref: string;
}

/** Records a fresh provider-neutral observation after a planned traffic action. */
export function recordAgentGymCanaryStateObservation(
  planValue: AgentGymCanaryActionPlanV1,
  input: Omit<AgentGymCanaryStateObservationV1,
    "candidate_ref" | "observation_digest" | "plan_digest" | "schema_version" | "target_ref">,
): AgentGymCanaryStateObservationV1 {
  const plan = validateAgentGymCanaryActionPlan(planValue);
  validateInput(input);
  if (Date.parse(input.observed_at) < Date.parse(plan.planned_at)) invalid();
  const body = {
    active_candidate_ref: input.active_candidate_ref,
    candidate_ref: plan.candidate_ref,
    candidate_traffic_percent: input.candidate_traffic_percent,
    evidence_refs: [...input.evidence_refs],
    observation_ref: input.observation_ref,
    observed_at: input.observed_at,
    observer_ref: input.observer_ref,
    plan_digest: plan.plan_digest,
    reason_codes: [...input.reason_codes],
    schema_version: "agent-gym-canary-state-observation/v1" as const,
    status: input.status,
    target_ref: plan.target_ref,
  };
  return Object.freeze({
    ...body,
    evidence_refs: Object.freeze(body.evidence_refs),
    observation_digest: digestAgentGymJson(body),
    reason_codes: Object.freeze(body.reason_codes),
  });
}

export function validateAgentGymCanaryStateObservation(
  value: AgentGymCanaryStateObservationV1,
): AgentGymCanaryStateObservationV1 {
  if (value.schema_version !== "agent-gym-canary-state-observation/v1") invalid();
  validateInput(value);
  reference(value.candidate_ref);
  reference(value.target_ref);
  digest(value.observation_digest);
  digest(value.plan_digest);
  const body = {
    active_candidate_ref: value.active_candidate_ref,
    candidate_ref: value.candidate_ref,
    candidate_traffic_percent: value.candidate_traffic_percent,
    evidence_refs: value.evidence_refs,
    observation_ref: value.observation_ref,
    observed_at: value.observed_at,
    observer_ref: value.observer_ref,
    plan_digest: value.plan_digest,
    reason_codes: value.reason_codes,
    schema_version: value.schema_version,
    status: value.status,
    target_ref: value.target_ref,
  };
  if (digestAgentGymJson(body) !== value.observation_digest) invalid();
  return Object.freeze({
    ...value,
    evidence_refs: Object.freeze([...value.evidence_refs]),
    reason_codes: Object.freeze([...value.reason_codes]),
  });
}

function validateInput(value: {
  readonly active_candidate_ref: string | null;
  readonly candidate_traffic_percent: number | null;
  readonly evidence_refs: readonly string[];
  readonly observation_ref: string;
  readonly observed_at: string;
  readonly observer_ref: string;
  readonly reason_codes: readonly string[];
  readonly status: AgentGymCanaryStateObservationStatus;
}): void {
  reference(value.observation_ref);
  reference(value.observer_ref);
  timestamp(value.observed_at);
  if (value.active_candidate_ref !== null) reference(value.active_candidate_ref);
  if (value.candidate_traffic_percent !== null) percent(value.candidate_traffic_percent);
  if (!Array.isArray(value.evidence_refs) || value.evidence_refs.length > 64
    || new Set(value.evidence_refs).size !== value.evidence_refs.length
    || !Array.isArray(value.reason_codes) || value.reason_codes.length > 64
    || new Set(value.reason_codes).size !== value.reason_codes.length) invalid();
  for (const ref of value.evidence_refs) reference(ref);
  for (const code of value.reason_codes) text(code);
  if (value.status === "observed") {
    if (value.active_candidate_ref === null || value.candidate_traffic_percent === null
      || value.evidence_refs.length === 0 || value.reason_codes.length !== 0) invalid();
  } else if (value.status === "unavailable") {
    if (value.active_candidate_ref !== null || value.candidate_traffic_percent !== null
      || value.reason_codes.length === 0) invalid();
  } else invalid();
}
function digest(value: string): void { if (!/^sha256:[0-9a-f]{64}$/u.test(value)) invalid(); }
function percent(value: number): void {
  if (!Number.isSafeInteger(value) || value < 0 || value > 100) invalid();
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
function invalid(): never { throw new AgentGymContractError("Agent gym canary state observation is invalid."); }
