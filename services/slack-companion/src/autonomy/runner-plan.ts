import type { AutonomyPlanStep, AutonomousGoalRecord } from "./goals.js";

export function nextReadyStep(plan: AutonomyPlanStep[]): AutonomyPlanStep | undefined {
  const completed = new Set(plan.filter((step) => step.status === "completed" || step.status === "skipped").map((step) => step.id));
  return plan.find((step) => step.status === "pending" && step.dependsOn.every((dependency) => completed.has(dependency)));
}

export function nextApprovedWaitingStep(goal: AutonomousGoalRecord): AutonomyPlanStep | undefined {
  return goal.currentPlan.find((step) => step.status === "waiting" && Boolean(approvedApprovalForStep(goal, step.id)));
}

export function approvedApprovalForStep(goal: AutonomousGoalRecord, stepId: string) {
  return goal.approvals.find((approval) => approval.stepId === stepId && approval.status === "approved");
}

export function pendingApprovalForStep(goal: AutonomousGoalRecord, stepId: string) {
  return goal.approvals.find((approval) => approval.stepId === stepId && approval.status === "pending");
}

export function updateStep(
  plan: AutonomyPlanStep[],
  stepId: string,
  status: AutonomyPlanStep["status"],
  summary?: string,
): AutonomyPlanStep[] {
  return plan.map((step) => step.id === stepId ? { ...step, status, summary } : step);
}
