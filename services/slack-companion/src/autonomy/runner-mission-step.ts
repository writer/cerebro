import type { AutonomyCapabilityDefinition } from "./capabilities.js";
import { missionBlockerPrefix, type AutonomyGoalService } from "./goal-service.js";
import type { AutonomyPlanStep, AutonomousGoalRecord } from "./goals.js";
import { approvedApprovalForStep, pendingApprovalForStep, updateStep } from "./runner-plan.js";
import type { AutonomyRunnerAdvanceResult } from "./runner-types.js";
import { unique } from "./runner-utils.js";

export async function advanceUnboundMissionStep(input: {
  goal: AutonomousGoalRecord;
  capability: AutonomyCapabilityDefinition;
  step: AutonomyPlanStep;
  goals: AutonomyGoalService;
  now: () => Date;
}): Promise<AutonomyRunnerAdvanceResult> {
  const missionStep = input.step.mission;
  const mission = input.goal.mission;
  if (!missionStep || !mission) throw new Error("Compiled mission metadata is required.");
  if (missionStep.kind === "decide" && missionStep.approvalRequired) {
    const approved = approvedApprovalForStep(input.goal, input.step.id);
    if (approved) {
      const updated = await input.goals.recordMissionDecision({
        goalId: input.goal.id,
        stepId: input.step.id,
        summary: `Reviewed approval completed for ${input.step.title}.`,
        evidenceRefs: [approved.id],
        approvalId: approved.id,
      });
      return { goalId: updated.id, status: "advanced", summary: `Approved ${input.step.title}. The next mission step is ready.` };
    }
    const pending = pendingApprovalForStep(input.goal, input.step.id);
    if (pending) {
      await input.goals.update(input.goal.id, {
        currentPlan: updateStep(input.goal.currentPlan, input.step.id, "waiting", "Waiting for reviewed approval."),
        activeStepId: null,
        status: "approval_needed",
        nextWakeAt: null,
      });
      return { goalId: input.goal.id, status: "advanced", summary: `Approval is pending for ${input.step.title}.` };
    }
    const approvalGoal = await input.goals.requestApproval(input.goal.id, {
      stepId: input.step.id,
      toolId: `mission.${mission.packId}.decision`,
      toolName: "Security mission approval",
      actionSummary: input.step.title,
      reason: `Mission ${mission.packId}@${mission.packVersion} requires reviewed approval at the ${missionStep.actionStage} boundary.`,
      risk: `Capability: ${input.capability.id}; owner: ${mission.owner}; rollback: ${missionStep.rollback ?? "No action executes in this decision step."}`,
      requestSummary: input.goal.objective,
    });
    await input.goals.update(approvalGoal.id, {
      currentPlan: updateStep(approvalGoal.currentPlan, input.step.id, "waiting", "Waiting for reviewed approval."),
      activeStepId: null,
    });
    return { goalId: approvalGoal.id, status: "advanced", summary: `Approval requested for ${input.step.title}.` };
  }

  const boundInputIds = new Set(mission.bindings.map((binding) => binding.id));
  const missingInputIds = missionStep.requiredInputIds.filter((id) => !boundInputIds.has(id));
  const reason = missionStep.bindingState === "operator_decision"
    ? `Record an evidence-backed decision with operator_agent_run_step_decide for ${input.step.title}.`
    : missingInputIds.length > 0
      ? `Bind required mission input${missingInputIds.length === 1 ? "" : "s"}: ${missingInputIds.join(", ")}.`
      : `Bind one registered tool that matches the mission selector for ${input.step.title}.`;
  const blocker = `${missionBlockerPrefix(input.step.id)} ${reason}`;
  const updated = await input.goals.update(input.goal.id, {
    currentPlan: updateStep(input.goal.currentPlan, input.step.id, "waiting", reason),
    activeStepId: null,
    status: "waiting",
    blockers: unique([...input.goal.blockers.filter((item) => !item.startsWith(missionBlockerPrefix(input.step.id))), blocker]),
    nextWakeAt: null,
  });
  await input.goals.appendLog(updated.id, {
    kind: "blocker_found",
    summary: `Mission step needs operator input: ${input.step.title}.`,
    details: reason,
  });
  return { goalId: updated.id, status: "advanced", summary: reason };
}
