import { AgentGymContractError } from "./contract-error.js";
import { validateAgentGymRegressionCampaignPlan, type AgentGymRegressionCampaignCaseV1,
  type AgentGymRegressionCampaignPlanV1 } from "./regression-campaign-plan.js";
import { validateAgentGymRegressionReplayTrial, type AgentGymRegressionReplayTrialV1 } from "./regression-replay-trial.js";

export interface AgentGymRegressionCampaignCompletedCaseV1 {
  readonly case_digest: string;
  readonly case_ref: string;
  readonly schema_version: "agent-gym-regression-campaign-case-output/v1";
  readonly status: "completed";
  readonly trial: AgentGymRegressionReplayTrialV1;
}

export interface AgentGymRegressionCampaignInvalidCaseV1 {
  readonly blocker_code: string;
  readonly case_digest: string;
  readonly case_ref: string;
  readonly schema_version: "agent-gym-regression-campaign-case-output/v1";
  readonly status: "invalid";
}

export type AgentGymRegressionCampaignCaseOutputV1 =
  | AgentGymRegressionCampaignCompletedCaseV1
  | AgentGymRegressionCampaignInvalidCaseV1;

export interface AgentGymRegressionCampaignTrialPort {
  run(
    campaign: AgentGymRegressionCampaignPlanV1,
    replay: AgentGymRegressionCampaignCaseV1,
  ): Promise<AgentGymRegressionCampaignCaseOutputV1>;
}

/** Validates one case output against its exact campaign and replay identities. */
export function validateAgentGymRegressionCampaignCaseOutput(
  campaignValue: AgentGymRegressionCampaignPlanV1,
  replayValue: AgentGymRegressionCampaignCaseV1,
  value: AgentGymRegressionCampaignCaseOutputV1,
): AgentGymRegressionCampaignCaseOutputV1 {
  const campaign = validateAgentGymRegressionCampaignPlan(campaignValue);
  const replay = campaign.cases.find((entry) => entry.case_ref === replayValue.case_ref);
  if (replay === undefined || replay.case_digest !== replayValue.case_digest
    || replay.replay_plan_digest !== replayValue.replay_plan_digest
    || value.schema_version !== "agent-gym-regression-campaign-case-output/v1"
    || value.case_ref !== replay.case_ref || value.case_digest !== replay.case_digest) invalid();
  if (value.status === "invalid") {
    blocker(value.blocker_code);
    return Object.freeze({ ...value });
  }
  if (value.status !== "completed") invalid();
  const trial = validateAgentGymRegressionReplayTrial(value.trial);
  if (trial.case_ref !== replay.case_ref || trial.case_digest !== replay.case_digest
    || trial.plan_digest !== replay.replay_plan_digest
    || trial.baseline_candidate_ref !== campaign.baseline_candidate_ref
    || trial.challenger_candidate_ref !== campaign.challenger_candidate_ref
    || trial.evaluator_admission_digest !== campaign.evaluator_admission_digest
    || trial.rubric_digest !== campaign.rubric_digest
    || trial.evaluator_digests.length !== campaign.evaluator_digests.length
    || trial.evaluator_digests.some((digest, index) => digest !== campaign.evaluator_digests[index])) invalid();
  return Object.freeze({ ...value, trial });
}

/** Records a stable, text-free invalid result when a provider or evaluator case fails. */
export function invalidAgentGymRegressionCampaignCase(
  replay: AgentGymRegressionCampaignCaseV1,
  blockerCode: string,
): AgentGymRegressionCampaignInvalidCaseV1 {
  blocker(blockerCode);
  return Object.freeze({ blocker_code: blockerCode, case_digest: replay.case_digest,
    case_ref: replay.case_ref, schema_version: "agent-gym-regression-campaign-case-output/v1",
    status: "invalid" });
}

function blocker(value: string): void {
  if (typeof value !== "string" || !/^[a-z][a-z0-9_.-]{0,79}$/u.test(value)) invalid();
}
function invalid(): never {
  throw new AgentGymContractError("Agent gym regression campaign case output is invalid.");
}
