import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import type { AgentGymEvaluatorAdmissionDecisionV1 } from "./evaluator-admission.js";
import { validateAgentGymRegressionReplayPlan, type AgentGymRegressionReplayPlanV1 } from "./regression-replay-plan.js";

export interface AgentGymRegressionCampaignCaseV1 {
  readonly case_digest: string;
  readonly case_ref: string;
  readonly maximum_model_calls: number;
  readonly replay_plan_digest: string;
  readonly replay_plan_ref: string;
}

export interface AgentGymRegressionCampaignPlanV1 {
  readonly baseline_candidate_ref: string;
  readonly campaign_digest: string;
  readonly campaign_ref: string;
  readonly cases: readonly AgentGymRegressionCampaignCaseV1[];
  readonly challenger_candidate_ref: string;
  readonly evaluator_admission_digest: string;
  readonly evaluator_digests: readonly string[];
  readonly maximum_invalid_cases: number;
  readonly maximum_model_calls: number;
  readonly planned_at: string;
  readonly rubric_digest: string;
  readonly schema_version: "agent-gym-regression-campaign-plan/v1";
}

/** Seals ordered replay work and shared evaluator identity before a campaign runs. */
export function planAgentGymRegressionCampaign(
  planValues: readonly AgentGymRegressionReplayPlanV1[],
  admission: AgentGymEvaluatorAdmissionDecisionV1,
  input: Pick<AgentGymRegressionCampaignPlanV1,
    "baseline_candidate_ref" | "campaign_ref" | "challenger_candidate_ref"
    | "maximum_invalid_cases" | "planned_at">,
): AgentGymRegressionCampaignPlanV1 {
  const plans = validatePlans(planValues);
  validateAdmission(admission);
  for (const ref of [input.baseline_candidate_ref, input.campaign_ref,
    input.challenger_candidate_ref]) reference(ref);
  timestamp(input.planned_at);
  if (!admission.admitted || input.baseline_candidate_ref === input.challenger_candidate_ref
    || Date.parse(input.planned_at) < Math.max(...plans.map((plan) => Date.parse(plan.planned_at)))
    || !Number.isSafeInteger(input.maximum_invalid_cases) || input.maximum_invalid_cases < 0
    || input.maximum_invalid_cases >= plans.length) invalid();
  const cases = plans.map((plan) => Object.freeze({
    case_digest: plan.case_digest, case_ref: plan.case_ref,
    maximum_model_calls: plan.maximum_model_calls, replay_plan_digest: plan.plan_digest,
    replay_plan_ref: plan.plan_ref,
  }));
  const maximumModelCalls = sum(cases.map((entry) => entry.maximum_model_calls));
  const body = {
    baseline_candidate_ref: input.baseline_candidate_ref, campaign_ref: input.campaign_ref,
    cases: cases.map((entry) => ({ ...entry })), challenger_candidate_ref: input.challenger_candidate_ref,
    evaluator_admission_digest: admission.decision_digest,
    evaluator_digests: [...admission.evaluator_digests], maximum_invalid_cases: input.maximum_invalid_cases,
    maximum_model_calls: maximumModelCalls, planned_at: input.planned_at,
    rubric_digest: admission.rubric_digest, schema_version: "agent-gym-regression-campaign-plan/v1" as const,
  };
  return Object.freeze({ ...body, cases: Object.freeze(cases),
    evaluator_digests: Object.freeze(body.evaluator_digests), campaign_digest: digestAgentGymJson(body) });
}

export function validateAgentGymRegressionCampaignPlan(
  value: AgentGymRegressionCampaignPlanV1,
): AgentGymRegressionCampaignPlanV1 {
  if (value.schema_version !== "agent-gym-regression-campaign-plan/v1") invalid();
  for (const ref of [value.baseline_candidate_ref, value.campaign_ref,
    value.challenger_candidate_ref]) reference(ref);
  for (const item of [value.campaign_digest, value.evaluator_admission_digest,
    value.rubric_digest]) digest(item);
  timestamp(value.planned_at);
  if (value.baseline_candidate_ref === value.challenger_candidate_ref
    || !Array.isArray(value.cases) || value.cases.length < 1 || value.cases.length > 10_000
    || !Array.isArray(value.evaluator_digests) || value.evaluator_digests.length < 1
    || value.evaluator_digests.length > 2
    || new Set(value.evaluator_digests).size !== value.evaluator_digests.length
    || !Number.isSafeInteger(value.maximum_invalid_cases) || value.maximum_invalid_cases < 0
    || value.maximum_invalid_cases >= value.cases.length) invalid();
  value.evaluator_digests.forEach(digest);
  const cases = value.cases.map(validateCase);
  if (new Set(cases.map((entry) => entry.case_ref)).size !== cases.length
    || new Set(cases.map((entry) => entry.replay_plan_digest)).size !== cases.length
    || cases.some((entry, index) => index > 0 && cases[index - 1]!.case_ref >= entry.case_ref)
    || sum(cases.map((entry) => entry.maximum_model_calls)) !== value.maximum_model_calls) invalid();
  const { campaign_digest: _digest, ...rest } = value;
  const body = { ...rest, cases: cases.map((entry) => ({ ...entry })),
    evaluator_digests: [...value.evaluator_digests] };
  if (digestAgentGymJson(body) !== value.campaign_digest) invalid();
  return Object.freeze({ ...value, cases: Object.freeze(cases),
    evaluator_digests: Object.freeze([...value.evaluator_digests]) });
}

function validatePlans(values: readonly AgentGymRegressionReplayPlanV1[]) {
  if (!Array.isArray(values) || values.length < 1 || values.length > 10_000) invalid();
  const plans = values.map(validateAgentGymRegressionReplayPlan)
    .sort((left, right) => left.case_ref.localeCompare(right.case_ref));
  if (new Set(plans.map((plan) => plan.case_ref)).size !== plans.length
    || new Set(plans.map((plan) => plan.plan_digest)).size !== plans.length) invalid();
  return plans;
}
function validateAdmission(value: AgentGymEvaluatorAdmissionDecisionV1): void {
  if (value.schema_version !== "agent-gym-evaluator-admission-decision/v1") invalid();
  timestamp(value.decided_at); reference(value.policy_ref); digest(value.decision_digest); digest(value.rubric_digest);
  value.evaluator_digests.forEach(digest);
  const body = { admitted: value.admitted, blocker_codes: value.blocker_codes,
    calibration_digests: value.calibration_digests, decided_at: value.decided_at,
    evaluator_digests: value.evaluator_digests, policy_ref: value.policy_ref,
    rubric_digest: value.rubric_digest, schema_version: value.schema_version };
  if (digestAgentGymJson(body) !== value.decision_digest
    || value.admitted !== (value.blocker_codes.length === 0)) invalid();
}
function validateCase(value: AgentGymRegressionCampaignCaseV1) {
  reference(value.case_ref); reference(value.replay_plan_ref);
  digest(value.case_digest); digest(value.replay_plan_digest);
  if (!Number.isSafeInteger(value.maximum_model_calls) || value.maximum_model_calls < 2
    || value.maximum_model_calls > 10_000) invalid();
  return Object.freeze({ ...value });
}
function sum(values: readonly number[]): number {
  const value = values.reduce((total, current) => total + current, 0);
  if (!Number.isSafeInteger(value) || value < 2 || value > 1_000_000) invalid();
  return value;
}
function reference(value: string): void {
  if (typeof value !== "string" || value.length > 240
    || !/^[a-z][a-z0-9+.-]*:\/\/\S+$/u.test(value)) invalid();
}
function timestamp(value: string): void {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)
    || !Number.isFinite(Date.parse(value))) invalid();
}
function digest(value: string): void { if (!/^sha256:[0-9a-f]{64}$/u.test(value)) invalid(); }
function invalid(): never { throw new AgentGymContractError("Agent gym regression campaign plan is invalid."); }
