import { AgentGymContractError } from "./contract-error.js";
import { validateAgentGymRegressionCampaignPlan, type AgentGymRegressionCampaignPlanV1 } from "./regression-campaign-plan.js";
import { invalidAgentGymRegressionCampaignCase, validateAgentGymRegressionCampaignCaseOutput,
  type AgentGymRegressionCampaignCaseOutputV1,
  type AgentGymRegressionCampaignTrialPort } from "./regression-campaign-port.js";

export interface AgentGymRegressionCampaignExecutionV1 {
  readonly campaign_digest: string;
  readonly completed_case_count: number;
  readonly invalid_case_count: number;
  readonly outputs: readonly AgentGymRegressionCampaignCaseOutputV1[];
  readonly schema_version: "agent-gym-regression-campaign-execution/v1";
}

/** Runs every campaign case in stable order and records thrown work as invalid. */
export async function executeAgentGymRegressionCampaign(
  campaignValue: AgentGymRegressionCampaignPlanV1,
  port: AgentGymRegressionCampaignTrialPort,
): Promise<AgentGymRegressionCampaignExecutionV1> {
  const campaign = validateAgentGymRegressionCampaignPlan(campaignValue);
  if (port === null || typeof port !== "object" || typeof port.run !== "function") invalid();
  const outputs: AgentGymRegressionCampaignCaseOutputV1[] = [];
  for (const replay of campaign.cases) {
    try {
      outputs.push(validateAgentGymRegressionCampaignCaseOutput(
        campaign, replay, await port.run(campaign, replay),
      ));
    } catch {
      outputs.push(invalidAgentGymRegressionCampaignCase(replay, "case_execution_failed"));
    }
  }
  return Object.freeze({ campaign_digest: campaign.campaign_digest,
    completed_case_count: outputs.filter((output) => output.status === "completed").length,
    invalid_case_count: outputs.filter((output) => output.status === "invalid").length,
    outputs: Object.freeze(outputs), schema_version: "agent-gym-regression-campaign-execution/v1" });
}

function invalid(): never {
  throw new AgentGymContractError("Agent gym regression campaign execution is invalid.");
}
