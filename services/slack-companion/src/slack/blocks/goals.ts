import type { AutonomousGoalRecord } from "../../autonomy/goals.js";
import { encodeAction } from "../action-codec.js";
import { trimForSlack } from "../format.js";
import { actionIds } from "./action-ids.js";
import { actions, button, context, escapeMrkdwn, header, listSection, section, type SlackBlock } from "./primitives.js";

export function goalCreatedBlocks(goal: AutonomousGoalRecord): SlackBlock[] {
  return [
    header("Agent run created"),
    section(`*${escapeMrkdwn(goal.id)}* · ${escapeMrkdwn(goal.status)} · ${escapeMrkdwn(goal.capabilityId)}\n${escapeMrkdwn(trimForSlack(goal.objective, 900))}`),
    context([
      goal.channelId ? `Channel: ${goal.channelId}` : "Channel: not set",
      `Executable steps: ${goal.currentPlan.filter((step) => Boolean(step.execution)).length}`,
      `Acceptance checks: ${goal.acceptanceCriteria.length}`,
      goal.mission ? `Mission: ${goal.mission.packId}@${goal.mission.packVersion}` : "Mission: generic",
      goal.mission ? `Mission state: ${goal.mission.status}` : "Mission state: not compiled",
      `Created: ${goal.createdAt}`,
    ]),
    ...missionBlocks(goal),
    ...listSection("Plan", goal.currentPlan.map(planLabel)),
  ];
}

export function goalsBlocks(goals: AutonomousGoalRecord[]): SlackBlock[] {
  if (goals.length === 0) {
    return [header("Agent runs"), section("No agent runs matched the request.")];
  }
  return [
    header("Agent runs"),
    ...goals.slice(0, 10).flatMap((goal) => [
      section(`*${escapeMrkdwn(goal.id)}* · ${escapeMrkdwn(goal.status)}\n${escapeMrkdwn(trimForSlack(goal.objective, 500))}`),
      context([
        `Capability: ${goal.capabilityId}`,
        goal.mission ? `Mission: ${goal.mission.packId}@${goal.mission.packVersion} · ${goal.mission.status}` : "Mission: generic",
        `Updated: ${goal.updatedAt}`,
        goal.nextWakeAt ? `Next wake: ${goal.nextWakeAt}` : "Next wake: not set",
        goal.artifacts.length ? `Artifacts: ${goal.artifacts.length}` : "Artifacts: none",
      ]),
    ]),
  ];
}

export function goalBlocks(goal: AutonomousGoalRecord): SlackBlock[] {
  return [
    header("Agent run"),
    section(`*${escapeMrkdwn(goal.id)}* · ${escapeMrkdwn(goal.status)} · ${escapeMrkdwn(goal.capabilityId)}\n${escapeMrkdwn(trimForSlack(goal.objective, 900))}`),
    context([
      `Created: ${goal.createdAt}`,
      `Updated: ${goal.updatedAt}`,
      goal.channelId ? `Channel: ${goal.channelId}` : "Channel: not set",
      goal.nextWakeAt ? `Next wake: ${goal.nextWakeAt}` : "Next wake: not set",
    ]),
    ...missionBlocks(goal),
    ...listSection("Plan", goal.currentPlan.map(planLabel)),
    ...listSection("Resources", goal.resourceRefs.map((resource) => `${resource.uri}${resource.label ? ` — ${resource.label}` : ""}`)),
    ...listSection("Acceptance checks", goal.acceptanceCriteria.map((criterion) => `${criterion.description}: ${criterion.status}${criterion.result ? ` — ${criterion.result}` : ""}`)),
    ...approvalBlocks(goal),
    ...listSection("Tool runs", goal.toolRuns.slice(-6).map((run) => `${run.toolName ?? run.toolId}: ${run.status}${run.responseSummary ? ` - ${run.responseSummary}` : ""}`)),
    ...listSection("Blockers", goal.blockers),
    ...listSection("Artifacts", goal.artifacts.map((artifact) => `${artifact.title}: ${artifact.status}${artifact.url ? ` — ${artifact.url}` : artifact.path ? ` — ${artifact.path}` : ""}`)),
    ...(goal.completionReceipt ? [section(`*Completion receipt*\n${escapeMrkdwn(goal.completionReceipt.status)} · ${escapeMrkdwn(goal.completionReceipt.verifier)} · ${escapeMrkdwn(goal.completionReceipt.verifiedAt)}\n${escapeMrkdwn(trimForSlack(goal.completionReceipt.summary, 700))}`)] : []),
    ...listSection("Corrections", goal.corrections.slice(-4).map((correction) => `${correction.previousClaim} → ${correction.replacement}`)),
    ...listSection("Work log", goal.workLog.slice(-6).map((entry) => `${entry.createdAt}: ${entry.summary}`)),
  ];
}

function missionBlocks(goal: AutonomousGoalRecord): SlackBlock[] {
  if (!goal.mission) return [];
  const pendingApprovals = goal.approvals.filter((approval) => approval.status === "pending").length;
  const currentStep = goal.currentPlan.find((step) => step.id === goal.activeStepId)
    ?? goal.currentPlan.find((step) => step.status === "waiting" || step.status === "active" || step.status === "pending");
  return [section([
    "*Security mission*",
    `${escapeMrkdwn(goal.mission.packId)} · ${escapeMrkdwn(goal.mission.packVersion)} · ${escapeMrkdwn(goal.mission.status)}`,
    `Owner: ${escapeMrkdwn(goal.mission.owner)}`,
    `Current step: ${escapeMrkdwn(currentStep?.title ?? "No remaining step")}`,
    `Pending approvals: ${pendingApprovals}`,
    `Missing inputs: ${escapeMrkdwn(goal.mission.missingInputIds.join(", ") || "none")}`,
    `Plan receipt: ${escapeMrkdwn(goal.mission.planDigest)}`,
  ].join("\n"))];
}

function planLabel(step: AutonomousGoalRecord["currentPlan"][number]): string {
  const tool = step.execution?.toolName
    ?? (step.mission?.bindingState === "operator_decision" ? "operator decision" : step.mission?.bindingState);
  const stage = step.mission?.actionStage ? ` · ${step.mission.actionStage}` : "";
  return `${step.title}: ${step.status}${stage}${tool ? ` — ${tool}` : ""}`;
}

function approvalBlocks(goal: AutonomousGoalRecord): SlackBlock[] {
  const pending = goal.approvals.filter((approval) => approval.status === "pending").slice(0, 3);
  if (pending.length === 0) return [];
  return pending.flatMap((approval) => [
    section(`*Approval needed*\n${escapeMrkdwn(approval.actionSummary)}\n${escapeMrkdwn(trimForSlack(approval.risk, 500))}`),
    actions([
      button("Approve", actionIds.autonomyApprove, encodeAction({ kind: "autonomy_approval_approve", goalId: goal.id, approvalId: approval.id }), "primary"),
      button("Reject", actionIds.autonomyReject, encodeAction({ kind: "autonomy_approval_reject", goalId: goal.id, approvalId: approval.id }), "danger"),
    ]),
  ]);
}
