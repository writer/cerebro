import type { SharedRateLimitCoordinator } from "../a2a/rate-limit.js";
import type { AppConfig } from "../config/index.js";
import type { CerebroDistributedWorkService } from "./distributed-work.js";
import type { FlueSecurityAssistantResearchAugmentation, FlueSecurityAssistantResearchPlanInput } from "./flue-security-assistant.js";
import type { SecurityResearchState } from "./research-state.js";
import type { SecurityAssistantInput } from "./security-assistant-types.js";

export async function prepareDistributedResearch(input: {
  question: SecurityAssistantInput;
  plan: FlueSecurityAssistantResearchPlanInput;
  researchState: SecurityResearchState;
  distributedWork?: Pick<CerebroDistributedWorkService, "coordinate">;
}): Promise<FlueSecurityAssistantResearchAugmentation | undefined> {
  input.researchState.seedStagedPlan(input.plan);
  const distributed = await input.distributedWork?.coordinate(input.question, input.plan);
  if (!distributed) return undefined;
  return {
    distributed_work: distributed.receipts.map((receipt) => ({
      packet_id: receipt.packet_id,
      status: receipt.status,
      findings: receipt.findings,
      recommendations: receipt.recommendations,
      blockers: receipt.blockers,
      source_results: receipt.tool_observations.map((observation) => importObservation(input.researchState, observation)),
    })),
  };
}

export function withAssistantWorkflowPermit<T>(
  config: AppConfig,
  rateLimits: Pick<SharedRateLimitCoordinator, "withPermit"> | undefined,
  run: () => Promise<T>,
): Promise<T> {
  if (!rateLimits) return run();
  return rateLimits.withPermit("model:opus-workflow", {
    maxConcurrent: config.a2a.modelMaxConcurrent,
    leaseMs: Math.max(config.a2a.rateLeaseMs, config.triage.timeoutMs + 30_000),
    waitMs: Math.max(config.a2a.rateWaitMs, config.triage.timeoutMs),
  }, run);
}

function importObservation(
  researchState: SecurityResearchState,
  observation: { tool_name: string; status: "completed" | "failed"; details: Record<string, unknown> },
): { tool_name: string; status: "completed" | "failed"; evidence_receipt?: string } {
  if (observation.status === "failed") {
    researchState.recordToolFailure(observation.tool_name);
    return { tool_name: observation.tool_name, status: "failed" };
  }
  const imported = researchState.recordToolResult(observation.tool_name, { details: observation.details });
  return {
    tool_name: observation.tool_name,
    status: imported?.evidenceReceipt ? "completed" : "failed",
    evidence_receipt: imported?.evidenceReceipt,
  };
}
