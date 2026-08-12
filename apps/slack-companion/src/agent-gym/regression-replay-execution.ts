import { AgentGymContractError } from "./contract-error.js";
import { runAgentGymModelBatch, type AgentGymModelBatchResultV1 } from "./model-batch.js";
import type { AgentGymModelBudgetV1 } from "./model-budget.js";
import { agentGymModelRequestDigest, validateAgentGymModelRequest, type AgentGymModelInvocationRequestV1, type AgentGymModelPort } from "./model-runtime.js";
import { validateAgentGymRegressionReplayParity, type AgentGymRegressionReplayParityV1 } from "./regression-replay-parity.js";
import { validateAgentGymRegressionReplayPlan, type AgentGymRegressionReplayPlanV1 } from "./regression-replay-plan.js";
import { validateAgentGymRegressionReplayRequestPair, type AgentGymRegressionReplayRequestPairV1 } from "./regression-replay-request-pair.js";

export interface AgentGymRegressionReplayExecutionV1 {
  readonly batch: AgentGymModelBatchResultV1;
  readonly pair_digest: string;
  readonly parity_report_digest: string;
  readonly plan_digest: string;
  readonly schema_version: "agent-gym-regression-replay-execution/v1";
}

/** Executes one fair paired replay through the provider-neutral model port. */
export async function executeAgentGymRegressionReplay(
  planValue: AgentGymRegressionReplayPlanV1,
  pairValue: AgentGymRegressionReplayRequestPairV1,
  parityValue: AgentGymRegressionReplayParityV1,
  baselineValue: AgentGymModelInvocationRequestV1,
  challengerValue: AgentGymModelInvocationRequestV1,
  budget: AgentGymModelBudgetV1,
  model: AgentGymModelPort,
  evaluatedAt: string,
  batchRef: string,
): Promise<AgentGymRegressionReplayExecutionV1> {
  const plan = validateAgentGymRegressionReplayPlan(planValue);
  const pair = validateAgentGymRegressionReplayRequestPair(pairValue);
  const parity = validateAgentGymRegressionReplayParity(parityValue);
  const baseline = validateAgentGymModelRequest(baselineValue);
  const challenger = validateAgentGymModelRequest(challengerValue);
  if (!parity.passed || pair.plan_digest !== plan.plan_digest || parity.pair_digest !== pair.pair_digest
    || agentGymModelRequestDigest(baseline) !== pair.baseline_request_digest
    || agentGymModelRequestDigest(challenger) !== pair.challenger_request_digest) invalid();
  const batch = await runAgentGymModelBatch(batchRef, [baseline, challenger], budget, model, evaluatedAt);
  return Object.freeze({
    batch, pair_digest: pair.pair_digest, parity_report_digest: parity.report_digest,
    plan_digest: plan.plan_digest, schema_version: "agent-gym-regression-replay-execution/v1",
  });
}

function invalid(): never { throw new AgentGymContractError("Agent gym regression replay execution is invalid."); }
