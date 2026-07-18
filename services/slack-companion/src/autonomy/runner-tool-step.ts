import type { AutonomyCapabilityDefinition } from "./capabilities.js";
import { completionReceipt, verifyAgentRunStep } from "./acceptance-verifier.js";
import { createAgentArtifact, type AgentAcceptanceCriterion } from "./agent-run.js";
import type { AutonomyGoalService } from "./goal-service.js";
import type { AutonomyPlanStep, AutonomousGoalRecord } from "./goals.js";
import { recordMetric } from "../telemetry.js";
import { approvedApprovalForStep, pendingApprovalForStep, updateStep } from "./runner-plan.js";
import type { AutonomyRunnerAdvanceResult } from "./runner-types.js";
import { AutonomyToolDispatcher } from "./tool-dispatcher.js";

type ToolStepInput = {
  goal: AutonomousGoalRecord;
  capability: AutonomyCapabilityDefinition;
  step: AutonomyPlanStep;
  goals: AutonomyGoalService;
  now: () => Date;
};

export async function advanceExecutableToolStep(input: ToolStepInput & {
  dispatcher: AutonomyToolDispatcher;
}): Promise<AutonomyRunnerAdvanceResult> {
  const approved = Boolean(approvedApprovalForStep(input.goal, input.step.id));
  const policy = input.dispatcher.policy(input.goal, input.step, approved);
  if (policy.decision === "approval_required") return requestApproval(input, policy.reason);
  if (policy.decision === "block") return blockStep(input, policy.reason);

  const execution = await input.dispatcher.dispatch(input.step);
  recordMetric("cerebro_slack_companion_agent_run_tool_total", {
    tool: execution.toolName,
    phase: "execute",
    status: execution.ok ? "completed" : "failed",
  }, 1);
  await input.goals.appendToolRun(input.goal.id, {
    toolId: input.step.execution!.toolName,
    toolName: input.step.execution!.toolName,
    status: execution.ok ? "completed" : "failed",
    reason: policy.reason,
    requestSummary: input.step.title,
    responseSummary: execution.summary,
    error: execution.error,
    startedAt: input.now().toISOString(),
    completedAt: input.now().toISOString(),
  });
  const attemptedStep = withAttempt(input.step);
  if (!execution.ok) return retryOrBlock(input, attemptedStep, execution.summary);

  let verification;
  if (attemptedStep.execution?.verificationToolName) {
    const verificationPolicy = input.dispatcher.verificationPolicy(attemptedStep.execution.verificationToolName);
    if (verificationPolicy.decision !== "allow") return blockStep({ ...input, step: attemptedStep }, verificationPolicy.reason);
    verification = await input.dispatcher.dispatch(attemptedStep, true, execution.details);
    recordMetric("cerebro_slack_companion_agent_run_tool_total", {
      tool: verification.toolName,
      phase: "verify",
      status: verification.ok ? "completed" : "failed",
    }, 1);
    await input.goals.appendToolRun(input.goal.id, {
      toolId: attemptedStep.execution.verificationToolName,
      toolName: attemptedStep.execution.verificationToolName,
      status: verification.ok ? "completed" : "failed",
      reason: "Independent acceptance verification.",
      requestSummary: `Verify ${input.step.title}.`,
      responseSummary: verification.summary,
      error: verification.error,
      startedAt: input.now().toISOString(),
      completedAt: input.now().toISOString(),
    });
  }

  let goal = await input.goals.get(input.goal.id) ?? input.goal;
  const checked = verifyAgentRunStep({ goal, step: attemptedStep, execution, verification, now: input.now() });
  const criteria = mergeCriteria(goal.acceptanceCriteria, checked.criteria);
  await input.goals.updateAcceptanceCriteria(goal.id, criteria);
  for (const artifact of artifactsFromRefs(checked.evidenceRefs, input.step.title, input.now())) {
    await input.goals.appendArtifact(goal.id, artifact);
  }
  if (!checked.passed) return retryOrBlock({ ...input, goal: await input.goals.get(goal.id) ?? goal }, attemptedStep, checked.summary);

  goal = await input.goals.get(goal.id) ?? goal;
  const updatedPlan = updateStep(goal.currentPlan, attemptedStep.id, "completed", checked.summary)
    .map((step) => step.id === attemptedStep.id ? { ...step, execution: attemptedStep.execution } : step);
  const remaining = updatedPlan.some((step) => step.status === "pending" || step.status === "active" || step.status === "waiting");
  const updated = await input.goals.update(goal.id, {
    currentPlan: updatedPlan,
    activeStepId: null,
    status: remaining ? "active" : "waiting",
    nextWakeAt: remaining ? input.now().toISOString() : null,
    approvals: goal.approvals.map((approval) => approval.stepId === attemptedStep.id && approval.status === "approved"
      ? { ...approval, status: "executed" as const, resultSummary: checked.summary }
      : approval),
  });
  await input.goals.appendLog(updated.id, {
    kind: "step_completed",
    summary: checked.summary,
    details: checked.evidenceRefs.length > 0 ? `Evidence: ${checked.evidenceRefs.join(", ")}` : undefined,
  });
  if (remaining) {
    return { goalId: updated.id, status: "advanced", summary: `${checked.summary} The next step is ready.` };
  }
  const completedGoal = await input.goals.get(updated.id) ?? updated;
  const receipt = completionReceipt({
    goal: completedGoal,
    summary: `Completed ${completedGoal.objective}`,
    verifier: attemptedStep.execution?.verificationToolName ?? "host_acceptance_verifier",
    now: input.now(),
  });
  const final = await input.goals.recordCompletionReceipt(completedGoal.id, receipt);
  recordMetric("cerebro_slack_companion_agent_run_completion_total", {
    status: receipt.status,
    verifier: receipt.verifier,
  }, 1);
  return { goalId: final.id, status: "advanced", summary: receipt.summary };
}

export async function blockUnavailableExecutableToolStep(input: {
  goal: AutonomousGoalRecord;
  capability: AutonomyCapabilityDefinition;
  step: AutonomyPlanStep;
  goals: AutonomyGoalService;
  now: () => Date;
}): Promise<AutonomyRunnerAdvanceResult> {
  return blockStep(input, "The autonomy tool dispatcher is unavailable.");
}

async function requestApproval(input: Parameters<typeof advanceExecutableToolStep>[0], reason: string): Promise<AutonomyRunnerAdvanceResult> {
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
  const execution = input.step.execution!;
  await input.goals.update(input.goal.id, {
    currentPlan: updateStep(input.goal.currentPlan, input.step.id, "waiting", "Waiting for reviewed approval."),
    activeStepId: null,
  });
  const goal = await input.goals.requestApproval(input.goal.id, {
    stepId: input.step.id,
    toolId: execution.toolName,
    toolName: execution.toolName,
    actionSummary: input.step.title,
    reason,
    risk: `Capability: ${input.capability.id}; blast radius: ${input.capability.blastRadius}.`,
    requestSummary: input.goal.objective,
  });
  return { goalId: goal.id, status: "advanced", summary: `Approval requested for ${input.step.title}.` };
}

async function retryOrBlock(
  input: Parameters<typeof advanceExecutableToolStep>[0],
  step: AutonomyPlanStep,
  reason: string,
): Promise<AutonomyRunnerAdvanceResult> {
  const attempts = step.execution?.attempts ?? 1;
  const maxAttempts = step.execution?.maxAttempts ?? 1;
  if (attempts < maxAttempts) {
    const retryAt = new Date(input.now().getTime() + 30_000).toISOString();
    const plan = updateStep(input.goal.currentPlan, step.id, "pending", `Attempt ${attempts} failed. Retry scheduled.`)
      .map((item) => item.id === step.id ? { ...item, execution: step.execution } : item);
    await input.goals.update(input.goal.id, { currentPlan: plan, activeStepId: null, status: "active", nextWakeAt: retryAt });
    await input.goals.appendLog(input.goal.id, { kind: "blocker_found", summary: `Retry scheduled for ${input.step.title}.`, details: reason });
    return { goalId: input.goal.id, status: "advanced", summary: `Attempt ${attempts} failed. Retry ${attempts + 1} is scheduled.` };
  }
  return blockStep({ ...input, step }, reason);
}

async function blockStep(input: ToolStepInput, reason: string): Promise<AutonomyRunnerAdvanceResult> {
  const plan = updateStep(input.goal.currentPlan, input.step.id, "failed", reason)
    .map((step) => step.id === input.step.id ? { ...step, execution: input.step.execution } : step);
  await input.goals.update(input.goal.id, {
    currentPlan: plan,
    activeStepId: null,
    status: "blocked",
    blockers: [...input.goal.blockers, reason].slice(-40),
    nextWakeAt: null,
  });
  await input.goals.appendLog(input.goal.id, { kind: "blocker_found", summary: `Blocked ${input.step.title}.`, details: reason });
  return { goalId: input.goal.id, status: "advanced", summary: `Blocked ${input.step.title}: ${reason}` };
}

function withAttempt(step: AutonomyPlanStep): AutonomyPlanStep {
  return step.execution ? { ...step, execution: { ...step.execution, attempts: Math.min(3, step.execution.attempts + 1) } } : step;
}

function mergeCriteria(current: AgentAcceptanceCriterion[], updates: AgentAcceptanceCriterion[]): AgentAcceptanceCriterion[] {
  const byId = new Map(current.map((criterion) => [criterion.id, criterion]));
  for (const criterion of updates) byId.set(criterion.id, criterion);
  return [...byId.values()].slice(-80);
}

function artifactsFromRefs(refs: string[], title: string, now: Date) {
  return refs.filter((ref) => /^https?:\/\//.test(ref) || /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_./-]+$/.test(ref)).slice(0, 8).map((ref) => {
    const url = /^https?:\/\//.test(ref) ? ref : undefined;
    const path = url ? undefined : ref;
    const kind = url?.includes("/pull/") ? "pull_request" as const : path ? "file" as const : "other" as const;
    return createAgentArtifact({ kind, title, status: "ready", url, path, sourceRefs: [ref] }, now);
  });
}
