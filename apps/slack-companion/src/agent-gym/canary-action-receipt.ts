import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import {
  validateAgentGymCanaryActionPlan,
  type AgentGymCanaryActionPlanV1,
} from "./canary-action-plan.js";

export type AgentGymCanaryActionStatus = "applied" | "indeterminate" | "rejected";

export interface AgentGymCanaryActionReceiptV1 {
  readonly action: AgentGymCanaryActionPlanV1["action"];
  readonly action_ref: string;
  readonly candidate_ref: string;
  readonly completed_at: string;
  readonly executor_ref: string;
  readonly failure_codes: readonly string[];
  readonly observed_active_candidate_ref: string | null;
  readonly observed_candidate_traffic_percent: number | null;
  readonly plan_digest: string;
  readonly receipt_digest: string;
  readonly receipt_ref: string;
  readonly schema_version: "agent-gym-canary-action-receipt/v1";
  readonly started_at: string;
  readonly status: AgentGymCanaryActionStatus;
  readonly target_ref: string;
}

/** Records an observed canary action result without claiming unknown state. */
export function recordAgentGymCanaryAction(
  planValue: AgentGymCanaryActionPlanV1,
  input: Omit<AgentGymCanaryActionReceiptV1,
    "action" | "action_ref" | "candidate_ref" | "plan_digest" | "receipt_digest"
    | "schema_version" | "target_ref">,
): AgentGymCanaryActionReceiptV1 {
  const plan = validateAgentGymCanaryActionPlan(planValue);
  validateInput(input);
  if (Date.parse(input.started_at) < Date.parse(plan.planned_at)
    || Date.parse(input.started_at) >= Date.parse(plan.expires_at)
    || Date.parse(input.completed_at) < Date.parse(input.started_at)) invalid();
  validateObservedOutcome(plan, input);
  const body = {
    action: plan.action,
    action_ref: plan.action_ref,
    candidate_ref: plan.candidate_ref,
    completed_at: input.completed_at,
    executor_ref: input.executor_ref,
    failure_codes: [...input.failure_codes],
    observed_active_candidate_ref: input.observed_active_candidate_ref,
    observed_candidate_traffic_percent: input.observed_candidate_traffic_percent,
    plan_digest: plan.plan_digest,
    receipt_ref: input.receipt_ref,
    schema_version: "agent-gym-canary-action-receipt/v1" as const,
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

export function validateAgentGymCanaryActionReceipt(
  value: AgentGymCanaryActionReceiptV1,
): AgentGymCanaryActionReceiptV1 {
  if (value.schema_version !== "agent-gym-canary-action-receipt/v1") invalid();
  validateInput(value);
  for (const ref of [value.action_ref, value.candidate_ref, value.target_ref]) reference(ref);
  digest(value.plan_digest);
  digest(value.receipt_digest);
  if (Date.parse(value.completed_at) < Date.parse(value.started_at)) invalid();
  if (value.status === "applied") {
    if (value.failure_codes.length !== 0 || value.observed_active_candidate_ref === null
      || value.observed_candidate_traffic_percent === null) invalid();
    if (value.action !== "rollback_candidate"
      && value.observed_active_candidate_ref !== value.candidate_ref) invalid();
    if (value.action === "rollback_candidate"
      && (value.observed_active_candidate_ref === value.candidate_ref
        || value.observed_candidate_traffic_percent !== 0)) invalid();
  } else if (value.status === "rejected") {
    if (value.failure_codes.length === 0 || value.observed_active_candidate_ref !== value.candidate_ref
      || value.observed_candidate_traffic_percent === null) invalid();
  } else if (value.status === "indeterminate") {
    if (value.failure_codes.length === 0 || value.observed_active_candidate_ref !== null
      || value.observed_candidate_traffic_percent !== null) invalid();
  } else invalid();
  const body = {
    action: value.action,
    action_ref: value.action_ref,
    candidate_ref: value.candidate_ref,
    completed_at: value.completed_at,
    executor_ref: value.executor_ref,
    failure_codes: value.failure_codes,
    observed_active_candidate_ref: value.observed_active_candidate_ref,
    observed_candidate_traffic_percent: value.observed_candidate_traffic_percent,
    plan_digest: value.plan_digest,
    receipt_ref: value.receipt_ref,
    schema_version: value.schema_version,
    started_at: value.started_at,
    status: value.status,
    target_ref: value.target_ref,
  };
  if (digestAgentGymJson(body) !== value.receipt_digest) invalid();
  return Object.freeze({ ...value, failure_codes: Object.freeze([...value.failure_codes]) });
}

function validateObservedOutcome(
  plan: AgentGymCanaryActionPlanV1,
  input: Pick<AgentGymCanaryActionReceiptV1,
    "failure_codes" | "observed_active_candidate_ref" | "observed_candidate_traffic_percent" | "status">,
): void {
  if (input.status === "applied") {
    const expectedActive = plan.action === "rollback_candidate"
      ? plan.rollback_candidate_ref
      : plan.candidate_ref;
    if (input.failure_codes.length !== 0 || input.observed_active_candidate_ref !== expectedActive
      || input.observed_candidate_traffic_percent !== plan.to_traffic_percent) invalid();
  } else if (input.status === "rejected") {
    if (input.failure_codes.length === 0 || input.observed_active_candidate_ref !== plan.candidate_ref
      || input.observed_candidate_traffic_percent !== plan.from_traffic_percent) invalid();
  } else if (input.status === "indeterminate") {
    if (input.failure_codes.length === 0 || input.observed_active_candidate_ref !== null
      || input.observed_candidate_traffic_percent !== null) invalid();
  } else invalid();
}
function validateInput(value: {
  readonly completed_at: string;
  readonly executor_ref: string;
  readonly failure_codes: readonly string[];
  readonly observed_active_candidate_ref: string | null;
  readonly observed_candidate_traffic_percent: number | null;
  readonly receipt_ref: string;
  readonly started_at: string;
  readonly status: AgentGymCanaryActionStatus;
}): void {
  reference(value.executor_ref);
  reference(value.receipt_ref);
  if (value.observed_active_candidate_ref !== null) reference(value.observed_active_candidate_ref);
  timestamp(value.started_at);
  timestamp(value.completed_at);
  if (value.observed_candidate_traffic_percent !== null) percent(value.observed_candidate_traffic_percent);
  if (!Array.isArray(value.failure_codes) || value.failure_codes.length > 64
    || new Set(value.failure_codes).size !== value.failure_codes.length) invalid();
  for (const code of value.failure_codes) text(code);
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
function invalid(): never { throw new AgentGymContractError("Agent gym canary action receipt is invalid."); }
