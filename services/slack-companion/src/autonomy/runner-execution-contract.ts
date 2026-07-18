import type { SecurityToolDeps } from "../agent/tools/types.js";
import type { AutonomyCapabilityDefinition } from "./capabilities.js";
import { autonomyExecutionContractFromControlPlane, evaluateAutonomyExecutionContract, localAutonomyExecutionContract, type AutonomyExecutionContractDecision } from "./execution-contract.js";
import type { AutonomyGoalService } from "./goal-service.js";
import type { AutonomyCapabilityId, AutonomyPlanStep, AutonomousGoalRecord } from "./goals.js";
import { updateStep } from "./runner-plan.js";
import type { AutonomyRunnerAdvanceResult } from "./runner-types.js";
import { unique } from "./runner-utils.js";

export async function ensureGoalExecutionContract(input: {
  goal: AutonomousGoalRecord;
  capabilityId: AutonomyCapabilityId;
  goals: AutonomyGoalService;
  now: () => Date;
  toolDeps?: SecurityToolDeps;
}): Promise<AutonomousGoalRecord> {
  if (input.goal.executionContract?.capabilityId === input.capabilityId) return input.goal;
  const selectedAt = input.now().toISOString();
  const controlPlane = await input.toolDeps?.cerebro.getAgentControlPlane().catch(() => undefined);
  const executionContract = controlPlane
    ? autonomyExecutionContractFromControlPlane(input.capabilityId, controlPlane, selectedAt)
    : localAutonomyExecutionContract(input.capabilityId, selectedAt);
  const updated = await input.goals.update(input.goal.id, { executionContract });
  return input.goals.appendLog(updated.id, {
    kind: "decision_made",
    summary: `Execution contract set: ${executionContract.profileId} allows ${executionContract.maxActionStage}.`,
    details: `Source: ${executionContract.source}; version: ${executionContract.version}; requested stage: ${executionContract.requestedActionStage}; required verifiers: ${executionContract.requiredVerifierIds.join(", ") || "none"}.`,
  });
}

export async function blockOnExecutionContract(input: {
  goal: AutonomousGoalRecord;
  capability: AutonomyCapabilityDefinition;
  step: AutonomyPlanStep;
  decision: AutonomyExecutionContractDecision;
  goals: AutonomyGoalService;
}): Promise<AutonomyRunnerAdvanceResult> {
  const summary = input.decision.reason ?? `Execution contract does not allow ${input.capability.id}.`;
  const updated = await input.goals.update(input.goal.id, {
    currentPlan: updateStep(input.goal.currentPlan, input.step.id, "failed", summary),
    activeStepId: null,
    status: "blocked",
    blockers: unique([...input.goal.blockers, summary]),
    nextWakeAt: null,
  });
  await input.goals.appendLog(updated.id, {
    kind: "blocker_found",
    summary,
    details: `Capability: ${input.capability.name}; requested stage: ${input.decision.requestedActionStage}.`,
  });
  return { goalId: updated.id, status: "advanced", summary };
}

export function executionContractDecision(goal: AutonomousGoalRecord, capabilityId: AutonomyCapabilityId): AutonomyExecutionContractDecision {
  if (!goal.executionContract) {
    return {
      allowed: false,
      requestedActionStage: "observe",
      reason: "Execution contract is missing.",
    };
  }
  return evaluateAutonomyExecutionContract(goal.executionContract, capabilityId);
}
