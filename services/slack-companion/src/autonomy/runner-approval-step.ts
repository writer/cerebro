import { trimForSlack } from "../slack/format.js";
import type { AutonomyCapabilityDefinition } from "./capabilities.js";
import type { AutonomyGoalService } from "./goal-service.js";
import type { AutonomyPlanStep, AutonomousGoalRecord } from "./goals.js";
import { approvedApprovalForStep, pendingApprovalForStep, updateStep } from "./runner-plan.js";
import type { AutonomyRunnerAdvanceResult } from "./runner-types.js";

export async function advanceApprovalOnlyStep(input: {
  goal: AutonomousGoalRecord;
  capability: AutonomyCapabilityDefinition;
  step: AutonomyPlanStep;
  goals: AutonomyGoalService;
  startedAt: string;
  now: () => Date;
}): Promise<AutonomyRunnerAdvanceResult> {
  const approved = approvedApprovalForStep(input.goal, input.step.id);
  if (approved) {
    await input.goals.appendToolRun(input.goal.id, {
      toolId: "autonomy.approved_execution",
      toolName: input.capability.name,
      status: "completed",
      reason: `Approved by ${approved.decidedBy?.displayName ?? approved.decidedBy?.slackUserId ?? "operator"}.`,
      requestSummary: approved.requestSummary ?? `${input.capability.name}: ${input.goal.objective}`,
      responseSummary: "Approval checkpointed. Add an exact registered tool to the plan step before execution.",
      startedAt: input.startedAt,
      completedAt: input.now().toISOString(),
    });
    const updated = await input.goals.update(input.goal.id, {
      currentPlan: updateStep(input.goal.currentPlan, input.step.id, "waiting", "Approved; exact execution tool is still required."),
      activeStepId: input.step.id,
      status: "waiting",
      nextWakeAt: null,
    });
    await input.goals.appendLog(updated.id, {
      kind: "decision_made",
      summary: `Approved ${input.step.title}; exact execution tool is required.`,
      details: `Capability: ${input.capability.name}; approval: ${approved.id}.`,
    });
    return {
      goalId: updated.id,
      status: "advanced",
      summary: `${input.capability.name} is approved and waiting for an exact executable tool step.`,
    };
  }

  const pending = pendingApprovalForStep(input.goal, input.step.id);
  if (pending) {
    await input.goals.update(input.goal.id, {
      status: "approval_needed",
      nextWakeAt: null,
      currentPlan: updateStep(input.goal.currentPlan, input.step.id, "waiting", "Waiting for approval."),
      activeStepId: input.step.id,
    });
    return { goalId: input.goal.id, status: "advanced", summary: `Approval is already pending for ${input.capability.name}.` };
  }

  await input.goals.appendToolRun(input.goal.id, {
    toolId: "autonomy.approval_request",
    toolName: "Approval request",
    status: "approval_requested",
    reason: input.capability.purpose,
    requestSummary: `${input.capability.name}: ${input.goal.objective}`,
    responseSummary: "Waiting for operator approval.",
    startedAt: input.startedAt,
    completedAt: input.now().toISOString(),
  });
  const approvalGoal = await input.goals.requestApproval(input.goal.id, {
    stepId: input.step.id,
    toolId: "autonomy.execute",
    toolName: input.capability.name,
    actionSummary: `Advance ${input.capability.name}`,
    reason: `Capability ${input.capability.id} has ${input.capability.blastRadius} blast radius and requires approval before execution.`,
    risk: `Blast radius: ${input.capability.blastRadius}; owner: ${input.capability.owner}; escalation: ${input.capability.escalationPath}.`,
    requestSummary: trimForSlack(input.goal.objective, 500),
  });
  await input.goals.update(approvalGoal.id, {
    currentPlan: updateStep(approvalGoal.currentPlan, input.step.id, "waiting", "Waiting for approval."),
    activeStepId: input.step.id,
  });
  return { goalId: input.goal.id, status: "advanced", summary: `Approval requested for ${input.capability.name}.` };
}
