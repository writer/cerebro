import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import {
  validateAgentGymActivationPlan,
  type AgentGymActivationPlanV1,
} from "./activation-plan.js";

export type AgentGymActivationStatus = "applied" | "rejected";

export interface AgentGymActivationReceiptV1 {
  readonly activation_ref: string;
  readonly candidate_ref: string;
  readonly completed_at: string;
  readonly executor_ref: string;
  readonly failure_codes: readonly string[];
  readonly observed_active_candidate_ref: string;
  readonly observed_traffic_percent: number;
  readonly plan_digest: string;
  readonly previous_candidate_ref: string;
  readonly receipt_digest: string;
  readonly receipt_ref: string;
  readonly schema_version: "agent-gym-activation-receipt/v1";
  readonly started_at: string;
  readonly status: AgentGymActivationStatus;
  readonly target_ref: string;
}

/** Records the observed result of executing one exact activation plan. */
export function recordAgentGymActivation(
  planValue: AgentGymActivationPlanV1,
  input: Omit<AgentGymActivationReceiptV1,
    "activation_ref" | "candidate_ref" | "plan_digest" | "receipt_digest"
    | "schema_version" | "target_ref">,
): AgentGymActivationReceiptV1 {
  const plan = validateAgentGymActivationPlan(planValue);
  validateInput(input);
  if (input.previous_candidate_ref !== plan.baseline_candidate_ref
    || Date.parse(input.started_at) < Date.parse(plan.planned_at)
    || Date.parse(input.completed_at) < Date.parse(input.started_at)
    || Date.parse(input.started_at) >= Date.parse(plan.expires_at)) invalid();
  if (input.status === "applied") {
    if (input.failure_codes.length !== 0
      || input.observed_active_candidate_ref !== plan.candidate_ref
      || input.observed_traffic_percent !== plan.initial_traffic_percent) invalid();
  } else if (input.failure_codes.length === 0
    || input.observed_active_candidate_ref !== plan.baseline_candidate_ref
    || input.observed_traffic_percent !== 0) invalid();
  const body = {
    activation_ref: plan.activation_ref,
    candidate_ref: plan.candidate_ref,
    completed_at: input.completed_at,
    executor_ref: input.executor_ref,
    failure_codes: [...input.failure_codes],
    observed_active_candidate_ref: input.observed_active_candidate_ref,
    observed_traffic_percent: input.observed_traffic_percent,
    plan_digest: plan.plan_digest,
    previous_candidate_ref: input.previous_candidate_ref,
    receipt_ref: input.receipt_ref,
    schema_version: "agent-gym-activation-receipt/v1" as const,
    started_at: input.started_at,
    status: input.status,
    target_ref: plan.target_ref,
  };
  return Object.freeze({
    ...body,
    failure_codes: Object.freeze(body.failure_codes),
    receipt_digest: digestAgentGymJson(body),
  });
}

export function validateAgentGymActivationReceipt(
  value: AgentGymActivationReceiptV1,
): AgentGymActivationReceiptV1 {
  if (value.schema_version !== "agent-gym-activation-receipt/v1") invalid();
  validateInput(value);
  for (const ref of [value.activation_ref, value.candidate_ref, value.target_ref]) reference(ref);
  digest(value.plan_digest);
  digest(value.receipt_digest);
  if (Date.parse(value.completed_at) < Date.parse(value.started_at)) invalid();
  if (value.status === "applied") {
    if (value.failure_codes.length !== 0 || value.observed_active_candidate_ref !== value.candidate_ref
      || value.observed_traffic_percent < 1) invalid();
  } else if (value.status === "rejected") {
    if (value.failure_codes.length === 0
      || value.observed_active_candidate_ref !== value.previous_candidate_ref
      || value.observed_traffic_percent !== 0) invalid();
  } else invalid();
  const body = {
    activation_ref: value.activation_ref,
    candidate_ref: value.candidate_ref,
    completed_at: value.completed_at,
    executor_ref: value.executor_ref,
    failure_codes: value.failure_codes,
    observed_active_candidate_ref: value.observed_active_candidate_ref,
    observed_traffic_percent: value.observed_traffic_percent,
    plan_digest: value.plan_digest,
    previous_candidate_ref: value.previous_candidate_ref,
    receipt_ref: value.receipt_ref,
    schema_version: value.schema_version,
    started_at: value.started_at,
    status: value.status,
    target_ref: value.target_ref,
  };
  if (digestAgentGymJson(body) !== value.receipt_digest) invalid();
  return Object.freeze({ ...value, failure_codes: Object.freeze([...value.failure_codes]) });
}

function validateInput(value: {
  readonly completed_at: string;
  readonly executor_ref: string;
  readonly failure_codes: readonly string[];
  readonly observed_active_candidate_ref: string;
  readonly observed_traffic_percent: number;
  readonly previous_candidate_ref: string;
  readonly receipt_ref: string;
  readonly started_at: string;
  readonly status: AgentGymActivationStatus;
}): void {
  for (const ref of [value.executor_ref, value.observed_active_candidate_ref,
    value.previous_candidate_ref, value.receipt_ref]) reference(ref);
  timestamp(value.started_at);
  timestamp(value.completed_at);
  if (!Number.isSafeInteger(value.observed_traffic_percent)
    || value.observed_traffic_percent < 0 || value.observed_traffic_percent > 100
    || !Array.isArray(value.failure_codes) || value.failure_codes.length > 64
    || new Set(value.failure_codes).size !== value.failure_codes.length) invalid();
  for (const code of value.failure_codes) text(code);
}
function digest(value: string): void {
  if (!/^sha256:[0-9a-f]{64}$/u.test(value)) invalid();
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
function invalid(): never {
  throw new AgentGymContractError("Agent gym activation receipt is invalid.");
}
