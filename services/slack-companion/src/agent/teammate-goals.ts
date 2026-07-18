import type { AutonomyGoalStatus, AutonomousGoalRecord } from "../autonomy/goals.js";
import type { SecurityAssistantAnswer, SecurityAssistantInput } from "./security-assistant-types.js";
import type { AssistantTeammateState, TeammateCommitment, TeammateCommitmentStatus } from "./teammate-state.js";

interface GoalReader {
  get(goalId: string): Promise<AutonomousGoalRecord | undefined>;
}

export interface TeammateGoalReconciliation {
  linked: number;
  completed: number;
  missing: number;
  unbacked: number;
  scopeMismatch: number;
}

export async function reconcileTeammateGoals(input: {
  answer: SecurityAssistantAnswer;
  question: SecurityAssistantInput;
  goals?: GoalReader;
  createdGoalIds?: string[];
}): Promise<{ answer: SecurityAssistantAnswer; reconciliation: TeammateGoalReconciliation }> {
  const reconciliation: TeammateGoalReconciliation = { linked: 0, completed: 0, missing: 0, unbacked: 0, scopeMismatch: 0 };
  const teammate = input.answer.teammate;
  if (!teammate?.commitments.length) return { answer: input.answer, reconciliation };
  const unfinishedWithoutGoal = teammate.commitments.filter((commitment) => commitment.status !== "completed" && commitment.status !== "cancelled" && !commitment.goalId);
  const hostCreatedGoalId = unfinishedWithoutGoal.length === 1 && input.createdGoalIds?.length === 1 ? input.createdGoalIds[0] : undefined;
  const commitments: TeammateCommitment[] = [];
  for (const rawCommitment of teammate.commitments) {
    const commitment = !rawCommitment.goalId && rawCommitment === unfinishedWithoutGoal[0] && hostCreatedGoalId
      ? { ...rawCommitment, goalId: hostCreatedGoalId }
      : rawCommitment;
    if (commitment.status === "completed" || commitment.status === "cancelled") {
      commitments.push(commitment);
      if (commitment.status === "completed") reconciliation.completed += 1;
      continue;
    }
    if (!commitment.goalId) {
      reconciliation.unbacked += 1;
      commitments.push(unbackedCommitment(commitment, "No follow-up run is scheduled for this unfinished work."));
      continue;
    }
    const goal = await input.goals?.get(commitment.goalId).catch(() => undefined);
    if (!goal) {
      reconciliation.missing += 1;
      commitments.push(unbackedCommitment(commitment, "The recorded follow-up run could not be verified."));
      continue;
    }
    const expectedThread = input.question.threadTs ?? input.question.ts;
    if ((goal.channelId && goal.channelId !== input.question.channelId) || (goal.threadTs && goal.threadTs !== expectedThread)) {
      reconciliation.scopeMismatch += 1;
      commitments.push(unbackedCommitment(commitment, "The recorded follow-up run belongs to a different Slack conversation."));
      continue;
    }
    reconciliation.linked += 1;
    if (goal.status === "completed") reconciliation.completed += 1;
    commitments.push(commitmentFromGoal(commitment, goal));
  }
  const goalBackedWork = teammate.commitments.some((commitment) => commitment.status !== "completed" && commitment.status !== "cancelled");
  const invalidGoalLink = reconciliation.unbacked + reconciliation.missing + reconciliation.scopeMismatch > 0;
  const fallbackMessages = goalBackedWork ? verifiedGoalFallbackMessages(input.answer, commitments) : input.answer.messages;
  return {
    answer: {
      ...input.answer,
      answer: invalidGoalLink ? fallbackMessages[0] ?? input.answer.answer : input.answer.answer,
      messages: fallbackMessages,
      presentationReady: goalBackedWork ? false : input.answer.presentationReady,
      teammate: { ...teammate, commitments },
    },
    reconciliation,
  };
}

export async function verifiedTeammateGoalPromptBlock(input: {
  state: AssistantTeammateState | undefined;
  goals?: GoalReader;
  channelId: string;
  threadTs: string;
}): Promise<string> {
  const goalIds = [...new Set((input.state?.commitments ?? []).map((item) => item.goalId).filter((value): value is string => Boolean(value)))].slice(0, 8);
  if (!input.goals || goalIds.length === 0) return "";
  const checked = await Promise.all(goalIds.map(async (goalId) => {
    const goal = await input.goals?.get(goalId).catch(() => undefined);
    if (!goal) return { goal_id: goalId, state: "missing" };
    const scopeMatches = (!goal.channelId || goal.channelId === input.channelId) && (!goal.threadTs || goal.threadTs === input.threadTs);
    if (!scopeMatches) return { goal_id: goalId, state: "scope_mismatch" };
    return {
      goal_id: goal.id,
      state: goal.status,
      objective: goal.objective,
      active_step: activeStep(goal)?.title,
      next_wake_at: goal.nextWakeAt,
      blockers: goal.blockers.slice(0, 4),
      acceptance_criteria: goal.acceptanceCriteria.slice(0, 12).map((criterion) => ({
        id: criterion.id,
        description: criterion.description,
        status: criterion.status,
      })),
      artifacts: goalArtifacts(goal),
      completion: goal.completionReceipt ? {
        status: goal.completionReceipt.status,
        summary: goal.completionReceipt.summary,
        verified_at: goal.completionReceipt.verifiedAt,
        verifier: goal.completionReceipt.verifier,
      } : undefined,
      checked_at: goal.updatedAt,
    };
  }));
  return [
    "Verified teammate goal state:",
    "This state came from the autonomy goal store. Use it instead of a stale promise from an earlier turn.",
    JSON.stringify(checked, null, 2),
  ].join("\n");
}

function commitmentFromGoal(commitment: TeammateCommitment, goal: AutonomousGoalRecord): TeammateCommitment {
  const status = commitmentStatus(goal.status);
  const criterionPassed = goal.acceptanceCriteria.filter((criterion) => criterion.status === "passed").length;
  const verification = goal.completionReceipt
    ? `${goal.completionReceipt.verifier} checked ${goal.completionReceipt.criteriaPassed.length} passed and ${goal.completionReceipt.criteriaFailed.length} failed acceptance criteria at ${goal.completionReceipt.verifiedAt}.`
    : `Goal ${goal.id} was checked at ${goal.updatedAt}; ${criterionPassed} of ${goal.acceptanceCriteria.length} acceptance criteria passed.`;
  const blocker = status === "blocked"
    ? goal.blockers[0] ?? pendingApproval(goal) ?? commitment.blocker
    : undefined;
  const nextAction = status === "completed" || status === "cancelled"
    ? undefined
    : activeStep(goal)?.title ?? nextStateAction(goal) ?? commitment.nextAction;
  return {
    ...commitment,
    status,
    goalId: goal.id,
    goalStatus: goal.status,
    acceptanceCriteria: goal.acceptanceCriteria.map((criterion) => `${criterion.description} [${criterion.status}]`),
    nextWakeAt: goal.nextWakeAt,
    nextAction,
    blocker,
    verification,
    artifactRefs: [...new Set([`goal:${goal.id}`, ...commitment.artifactRefs, ...goalArtifacts(goal)])].slice(0, 24),
  };
}

function unbackedCommitment(commitment: TeammateCommitment, blocker: string): TeammateCommitment {
  return {
    ...commitment,
    status: "blocked",
    blocker,
    nextAction: undefined,
    goalStatus: undefined,
    nextWakeAt: undefined,
    verification: blocker,
  };
}

function commitmentStatus(status: AutonomyGoalStatus): TeammateCommitmentStatus {
  if (status === "completed") return "completed";
  if (status === "cancelled") return "cancelled";
  if (status === "blocked" || status === "paused" || status === "approval_needed") return "blocked";
  return "in_progress";
}

function activeStep(goal: AutonomousGoalRecord) {
  return goal.currentPlan.find((step) => step.id === goal.activeStepId)
    ?? goal.currentPlan.find((step) => step.status === "active")
    ?? goal.currentPlan.find((step) => step.status === "pending");
}

function nextStateAction(goal: AutonomousGoalRecord): string | undefined {
  if (goal.status === "approval_needed") return "Wait for the recorded approval decision.";
  if (goal.status === "waiting" && goal.nextWakeAt) return `Resume the goal at ${goal.nextWakeAt}.`;
  if (goal.status === "paused") return "Resume the paused goal after its blocker is resolved.";
  return undefined;
}

function pendingApproval(goal: AutonomousGoalRecord): string | undefined {
  const approval = goal.approvals.find((item) => item.status === "pending");
  return approval ? `${approval.actionSummary}: ${approval.reason}` : undefined;
}

function goalArtifacts(goal: AutonomousGoalRecord): string[] {
  return [...new Set([
    ...goal.artifactUrls,
    ...goal.artifacts.flatMap((artifact) => [artifact.url, artifact.path, artifact.id].filter((value): value is string => Boolean(value))),
    ...(goal.completionReceipt?.evidenceRefs ?? []),
  ])].slice(0, 24);
}

function verifiedGoalFallbackMessages(answer: SecurityAssistantAnswer, commitments: TeammateCommitment[]): string[] {
  const completedNow = answer.actionsTaken.length > 0
    ? `Completed now: ${answer.actionsTaken.slice(0, 4).join("; ")}`
    : answer.keyPoints[0] ?? answer.evidence[0];
  const states = commitments.flatMap((commitment) => {
    if (commitment.status === "completed") {
      return [`Goal ${commitment.goalId ?? commitment.id} completed.${commitment.verification ? ` ${commitment.verification}` : ""}`];
    }
    if (!commitment.goalStatus) {
      return [`Remaining: ${commitment.summary} ${commitment.blocker ?? "No follow-up run is scheduled."}`];
    }
    if (commitment.status === "blocked") {
      return [`Goal ${commitment.goalId} is ${commitment.goalStatus}: ${commitment.blocker ?? "work cannot continue"}`];
    }
    return [
      `Goal ${commitment.goalId} is ${commitment.goalStatus}.${commitment.nextAction ? ` Next: ${commitment.nextAction}` : ""}${commitment.nextWakeAt ? ` Next wake: ${commitment.nextWakeAt}.` : ""}`,
    ];
  });
  return [completedNow, ...states]
    .filter((value): value is string => Boolean(value?.trim()))
    .map((value) => value.replace(/\s+/g, " ").trim().slice(0, 3_000))
    .slice(0, 6);
}
