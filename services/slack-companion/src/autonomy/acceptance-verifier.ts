import type { AgentAcceptanceCriterion, AgentCompletionReceipt } from "./agent-run.js";
import type { AutonomyPlanStep, AutonomousGoalRecord } from "./goals.js";
import type { AutonomyToolDispatchResult } from "./tool-dispatcher.js";

export interface StepVerificationResult {
  passed: boolean;
  criteria: AgentAcceptanceCriterion[];
  passedIds: string[];
  failedIds: string[];
  evidenceRefs: string[];
  summary: string;
}

export function verifyAgentRunStep(input: {
  goal: AutonomousGoalRecord;
  step: AutonomyPlanStep;
  execution: AutonomyToolDispatchResult;
  verification?: AutonomyToolDispatchResult;
  now?: Date;
}): StepVerificationResult {
  const now = (input.now ?? new Date()).toISOString();
  const selected = input.goal.acceptanceCriteria.filter((criterion) => input.step.acceptanceCriteriaIds?.includes(criterion.id));
  const approvalRefs = selected.some((criterion) => criterion.kind === "manual")
    ? input.goal.approvals
      .filter((approval) => approval.stepId === input.step.id && (approval.status === "approved" || approval.status === "executed"))
      .map((approval) => approval.id)
    : [];
  const evidenceRefs = unique([...input.execution.evidenceRefs, ...(input.verification?.evidenceRefs ?? []), ...approvalRefs]);
  const source = input.verification?.details ?? input.execution.details;
  const criteria = selected.map((criterion): AgentAcceptanceCriterion => {
    const result = evaluateCriterion(criterion, source, input.goal, input.step.id, input.execution.ok && (input.verification?.ok ?? true));
    return {
      ...criterion,
      status: result.passed ? "passed" : "failed",
      checkedAt: now,
      result: result.summary,
      evidenceRefs: unique([...criterion.evidenceRefs, ...evidenceRefs]),
    };
  });
  const implicitPassed = input.execution.ok && (input.verification?.ok ?? true);
  const passedIds = criteria.filter((criterion) => criterion.status === "passed").map((criterion) => criterion.id);
  const failedIds = criteria.filter((criterion) => criterion.status === "failed").map((criterion) => criterion.id);
  const passed = selected.length === 0 ? implicitPassed : failedIds.length === 0;
  return {
    passed,
    criteria,
    passedIds,
    failedIds,
    evidenceRefs,
    summary: passed
      ? `Verified ${input.step.title}.`
      : `Verification failed for ${input.step.title}: ${failedIds.join(", ") || input.verification?.error || input.execution.error || "tool result did not satisfy the acceptance check"}.`,
  };
}

export function completionReceipt(input: {
  goal: AutonomousGoalRecord;
  summary: string;
  verifier: string;
  now?: Date;
}): AgentCompletionReceipt {
  const passed = input.goal.acceptanceCriteria.filter((criterion) => criterion.status === "passed");
  const failed = input.goal.acceptanceCriteria.filter((criterion) => criterion.status === "failed");
  const pending = input.goal.acceptanceCriteria.filter((criterion) => criterion.status === "pending");
  return {
    status: failed.length > 0 || pending.length > 0 ? "partial" : "complete",
    summary: input.summary,
    verifiedAt: (input.now ?? new Date()).toISOString(),
    verifier: input.verifier,
    criteriaPassed: passed.map((criterion) => criterion.id),
    criteriaFailed: [...failed, ...pending].map((criterion) => criterion.id),
    evidenceRefs: unique(passed.flatMap((criterion) => criterion.evidenceRefs)),
  };
}

function evaluateCriterion(
  criterion: AgentAcceptanceCriterion,
  source: unknown,
  goal: AutonomousGoalRecord,
  inputStepId: string,
  toolSucceeded: boolean,
): { passed: boolean; summary: string } {
  if (criterion.kind === "tool_success") return { passed: toolSucceeded, summary: toolSucceeded ? "Tool completed successfully." : "Tool did not complete successfully." };
  if (criterion.kind === "field_present") {
    const value = fieldValue(source, criterion.field);
    const passed = value !== undefined && value !== null && value !== "";
    return { passed, summary: passed ? `Field ${criterion.field} is present.` : `Field ${criterion.field ?? "unknown"} is missing.` };
  }
  if (criterion.kind === "field_equals") {
    const value = fieldValue(source, criterion.field);
    const passed = value === criterion.expected;
    return { passed, summary: passed ? `Field ${criterion.field} matched.` : `Field ${criterion.field ?? "unknown"} did not match the expected value.` };
  }
  if (criterion.kind === "resource_ref") {
    const expected = String(criterion.expected ?? "");
    const passed = goal.resourceRefs.some((resource) => resource.uri === expected || resource.id === expected);
    return { passed, summary: passed ? `Resource ${expected} is attached.` : `Resource ${expected} is not attached.` };
  }
  if (criterion.kind === "artifact") {
    const expected = String(criterion.expected ?? "");
    const passed = goal.artifacts.some((artifact) => artifact.id === expected || artifact.url === expected || artifact.path === expected || artifact.kind === expected);
    return { passed, summary: passed ? `Artifact ${expected} is attached.` : `Artifact ${expected} is not attached.` };
  }
  if (criterion.kind === "manual") {
    const approval = goal.approvals.find((candidate) => candidate.stepId === inputStepId && (candidate.status === "approved" || candidate.status === "executed"));
    return approval
      ? { passed: true, summary: `Reviewed approval ${approval.id} is attached.` }
      : { passed: false, summary: "Reviewed approval is still required." };
  }
  return { passed: false, summary: "Manual acceptance is still required." };
}

function fieldValue(value: unknown, field: string | undefined): unknown {
  if (!field) return undefined;
  return field.split(".").reduce<unknown>((current, segment) => {
    if (Array.isArray(current)) {
      const index = Number(segment);
      return Number.isInteger(index) && index >= 0 ? current[index] : undefined;
    }
    if (!current || typeof current !== "object") return undefined;
    return (current as Record<string, unknown>)[segment];
  }, value);
}

function unique(values: string[]): string[] {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))].slice(0, 40);
}
