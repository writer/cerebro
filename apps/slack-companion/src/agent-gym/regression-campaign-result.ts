import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import type { AgentGymRegressionCampaignExecutionV1 } from "./regression-campaign-execution.js";
import { validateAgentGymRegressionCampaignPlan, type AgentGymRegressionCampaignPlanV1 } from "./regression-campaign-plan.js";
import { validateAgentGymRegressionCampaignCaseOutput } from "./regression-campaign-port.js";
import type { AgentGymJson } from "./fixture-case.js";

export interface AgentGymRegressionCampaignCompletedResultCaseV1 {
  readonly case_digest: string;
  readonly case_ref: string;
  readonly outcome: "equivalent" | "improved" | "regressed";
  readonly status: "completed";
  readonly trial_digest: string;
}

export interface AgentGymRegressionCampaignInvalidResultCaseV1 {
  readonly blocker_code: string;
  readonly case_digest: string;
  readonly case_ref: string;
  readonly status: "invalid";
}

export type AgentGymRegressionCampaignResultCaseV1 =
  | AgentGymRegressionCampaignCompletedResultCaseV1
  | AgentGymRegressionCampaignInvalidResultCaseV1;

export interface AgentGymRegressionCampaignResultV1 {
  readonly campaign_digest: string;
  readonly cases: readonly AgentGymRegressionCampaignResultCaseV1[];
  readonly completed_at: string;
  readonly completed_case_count: number;
  readonly equivalent_case_count: number;
  readonly improved_case_count: number;
  readonly invalid_case_count: number;
  readonly regressed_case_count: number;
  readonly result_digest: string;
  readonly result_ref: string;
  readonly schema_version: "agent-gym-regression-campaign-result/v1";
  readonly status: "blocked" | "complete";
}

/** Seals complete campaign evidence and fails closed above the invalid-case budget. */
export function recordAgentGymRegressionCampaignResult(
  campaignValue: AgentGymRegressionCampaignPlanV1,
  execution: AgentGymRegressionCampaignExecutionV1,
  input: Pick<AgentGymRegressionCampaignResultV1, "completed_at" | "result_ref">,
): AgentGymRegressionCampaignResultV1 {
  const campaign = validateAgentGymRegressionCampaignPlan(campaignValue);
  reference(input.result_ref); timestamp(input.completed_at);
  if (execution.schema_version !== "agent-gym-regression-campaign-execution/v1"
    || execution.campaign_digest !== campaign.campaign_digest
    || execution.outputs.length !== campaign.cases.length) invalid();
  const outputs = execution.outputs.map((output, index) =>
    validateAgentGymRegressionCampaignCaseOutput(campaign, campaign.cases[index]!, output));
  if (outputs.some((output, index) => output.case_ref !== campaign.cases[index]!.case_ref)
    || outputs.some((output) => output.status === "completed"
      && Date.parse(input.completed_at) < Date.parse(output.trial.completed_at))) invalid();
  const cases = outputs.map((output): AgentGymRegressionCampaignResultCaseV1 => output.status === "completed"
    ? Object.freeze({ case_digest: output.case_digest, case_ref: output.case_ref,
      outcome: output.trial.outcome, status: output.status, trial_digest: output.trial.trial_digest })
    : Object.freeze({ blocker_code: output.blocker_code, case_digest: output.case_digest,
      case_ref: output.case_ref, status: output.status }));
  const counts = count(cases);
  if (counts.completed_case_count !== execution.completed_case_count
    || counts.invalid_case_count !== execution.invalid_case_count) invalid();
  const body = { campaign_digest: campaign.campaign_digest, cases: cases.map(caseBody),
    completed_at: input.completed_at, ...counts, result_ref: input.result_ref,
    schema_version: "agent-gym-regression-campaign-result/v1" as const,
    status: counts.invalid_case_count > campaign.maximum_invalid_cases ? "blocked" as const : "complete" as const };
  return Object.freeze({ ...body, cases: Object.freeze(cases), result_digest: digestAgentGymJson(body) });
}

export function validateAgentGymRegressionCampaignResult(
  value: AgentGymRegressionCampaignResultV1,
): AgentGymRegressionCampaignResultV1 {
  if (value.schema_version !== "agent-gym-regression-campaign-result/v1") invalid();
  reference(value.result_ref); timestamp(value.completed_at);
  digest(value.campaign_digest); digest(value.result_digest);
  if (!Array.isArray(value.cases) || value.cases.length < 1 || value.cases.length > 10_000
    || !["blocked", "complete"].includes(value.status)) invalid();
  const cases = value.cases.map(validateCase);
  if (new Set(cases.map((entry) => entry.case_ref)).size !== cases.length
    || cases.some((entry, index) => index > 0 && cases[index - 1]!.case_ref >= entry.case_ref)) invalid();
  const counts = count(cases);
  for (const key of Object.keys(counts) as (keyof typeof counts)[]) {
    if (value[key] !== counts[key]) invalid();
  }
  const { result_digest: _digest, ...rest } = value;
  const body = { ...rest, cases: cases.map(caseBody) };
  if (digestAgentGymJson(body) !== value.result_digest) invalid();
  return Object.freeze({ ...value, cases: Object.freeze(cases) });
}

function validateCase(value: AgentGymRegressionCampaignResultCaseV1) {
  reference(value.case_ref); digest(value.case_digest);
  if (value.status === "completed") {
    if (!["equivalent", "improved", "regressed"].includes(value.outcome)) invalid();
    digest(value.trial_digest);
  } else if (value.status === "invalid") {
    if (!/^[a-z][a-z0-9_.-]{0,79}$/u.test(value.blocker_code)) invalid();
  } else invalid();
  return Object.freeze({ ...value });
}
function caseBody(value: AgentGymRegressionCampaignResultCaseV1): AgentGymJson {
  return value.status === "completed"
    ? { case_digest: value.case_digest, case_ref: value.case_ref, outcome: value.outcome,
      status: value.status, trial_digest: value.trial_digest }
    : { blocker_code: value.blocker_code, case_digest: value.case_digest,
      case_ref: value.case_ref, status: value.status };
}
function count(cases: readonly AgentGymRegressionCampaignResultCaseV1[]) {
  return {
    completed_case_count: cases.filter((entry) => entry.status === "completed").length,
    equivalent_case_count: cases.filter((entry) => entry.status === "completed"
      && entry.outcome === "equivalent").length,
    improved_case_count: cases.filter((entry) => entry.status === "completed"
      && entry.outcome === "improved").length,
    invalid_case_count: cases.filter((entry) => entry.status === "invalid").length,
    regressed_case_count: cases.filter((entry) => entry.status === "completed"
      && entry.outcome === "regressed").length,
  };
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
function invalid(): never { throw new AgentGymContractError("Agent gym regression campaign result is invalid."); }
