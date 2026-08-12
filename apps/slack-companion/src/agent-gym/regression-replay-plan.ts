import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import { validateAgentGymRegressionReplayRequest, type AgentGymRegressionReplayRequestV1 } from "./regression-replay-request.js";

export interface AgentGymRegressionReplayPlanV1 {
  readonly baseline_invocation_ref: string;
  readonly case_digest: string;
  readonly case_ref: string;
  readonly challenger_invocation_ref: string;
  readonly maximum_model_calls: number;
  readonly plan_digest: string;
  readonly plan_ref: string;
  readonly planned_at: string;
  readonly replay_request_digest: string;
  readonly schema_version: "agent-gym-regression-replay-plan/v1";
}

/** Seals the two provider-neutral invocations that may execute a regression replay. */
export function planAgentGymRegressionReplay(
  requestValue: AgentGymRegressionReplayRequestV1,
  input: Pick<AgentGymRegressionReplayPlanV1,
    "baseline_invocation_ref" | "challenger_invocation_ref" | "plan_ref" | "planned_at">,
): AgentGymRegressionReplayPlanV1 {
  const request = validateAgentGymRegressionReplayRequest(requestValue);
  for (const ref of [input.baseline_invocation_ref, input.challenger_invocation_ref, input.plan_ref]) reference(ref);
  timestamp(input.planned_at);
  if (input.baseline_invocation_ref === input.challenger_invocation_ref
    || Date.parse(input.planned_at) < Date.parse(request.planned_at)) invalid();
  const body = {
    baseline_invocation_ref: input.baseline_invocation_ref,
    case_digest: request.case_digest,
    case_ref: request.case_ref,
    challenger_invocation_ref: input.challenger_invocation_ref,
    maximum_model_calls: request.maximum_model_calls,
    plan_ref: input.plan_ref,
    planned_at: input.planned_at,
    replay_request_digest: request.request_digest,
    schema_version: "agent-gym-regression-replay-plan/v1" as const,
  };
  return Object.freeze({ ...body, plan_digest: digestAgentGymJson(body) });
}

export function validateAgentGymRegressionReplayPlan(value: AgentGymRegressionReplayPlanV1): AgentGymRegressionReplayPlanV1 {
  if (value.schema_version !== "agent-gym-regression-replay-plan/v1") invalid();
  for (const ref of [value.baseline_invocation_ref, value.case_ref, value.challenger_invocation_ref, value.plan_ref]) reference(ref);
  for (const item of [value.case_digest, value.plan_digest, value.replay_request_digest]) digest(item);
  timestamp(value.planned_at);
  if (value.baseline_invocation_ref === value.challenger_invocation_ref
    || !Number.isSafeInteger(value.maximum_model_calls) || value.maximum_model_calls < 2 || value.maximum_model_calls > 10_000) invalid();
  const { plan_digest: _digest, ...body } = value;
  if (digestAgentGymJson(body) !== value.plan_digest) invalid();
  return Object.freeze({ ...value });
}

function reference(value: string): void { if (typeof value !== "string" || value.length > 240 || !/^[a-z][a-z0-9+.-]*:\/\/\S+$/u.test(value)) invalid(); }
function timestamp(value: string): void { if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) || !Number.isFinite(Date.parse(value))) invalid(); }
function digest(value: string): void { if (!/^sha256:[0-9a-f]{64}$/u.test(value)) invalid(); }
function invalid(): never { throw new AgentGymContractError("Agent gym regression replay plan is invalid."); }
