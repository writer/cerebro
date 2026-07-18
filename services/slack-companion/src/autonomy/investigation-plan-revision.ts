import { trimForSlack } from "../slack/format.js";
import type { AutonomyPlanStep } from "./goals.js";

export interface InvestigationPlanRevision {
  title: string;
  summary: string;
}

export function reviseInvestigationPlan(
  plan: AutonomyPlanStep[],
  completedStepId: string,
  revision: InvestigationPlanRevision,
): AutonomyPlanStep[] {
  const completedIndex = plan.findIndex((step) => step.id === completedStepId);
  const nextIndex = plan.findIndex((step, index) => (
    step.status === "pending"
    && (completedIndex < 0 || index > completedIndex)
    && step.dependsOn.includes(completedStepId)
  ));
  if (nextIndex >= 0) {
    return plan.map((step, index) => index === nextIndex
      ? { ...step, title: revision.title, summary: revision.summary }
      : step);
  }
  return [
    ...plan,
    {
      id: uniqueStepId(plan, "recheck-evidence"),
      title: revision.title,
      status: "pending",
      dependsOn: [completedStepId],
      summary: revision.summary,
    },
  ];
}

export function investigationPlanRevision(packet: Record<string, unknown>): InvestigationPlanRevision | undefined {
  const verification = claimVerificationState(packet);
  if (!verification) return undefined;
  const gaps = stringArray(packet.gaps);
  const blockerCodes = verification.blockerCodes;
  if (verification.error) {
    return {
      title: "Retry claim verification before recommendation",
      summary: `Claim verification failed: ${verification.error}. Re-run verification or collect the missing verifier context before recommending action.`,
    };
  }
  if (verification.verdict === "contradicted" || blockerCodes.includes("counterevidence_present")) {
    return {
      title: "Resolve counterevidence before recommendation",
      summary: `Claim ${verification.verdict} allows ${verification.allowedNextStage}; counterevidence blocks recommendation until the conflict is resolved.`,
    };
  }
  if (gaps.length > 0 || verification.verdict !== "supported" || !stageAtLeast(verification.allowedNextStage, "recommend")) {
    const gapSummary = gaps.length ? ` Missing evidence: ${trimForSlack(gaps.slice(0, 3).join("; "), 500)}.` : "";
    return {
      title: "Collect missing evidence before recommendation",
      summary: `Claim ${verification.verdict} allows ${verification.allowedNextStage}; collect evidence before recommending action.${gapSummary}`,
    };
  }
  return {
    title: "Write recommendation from verified evidence",
    summary: `Claim ${verification.verdict} allows ${verification.allowedNextStage}; prepare a recommendation with cited evidence and no execution step.`,
  };
}

export function claimVerificationText(packet: Record<string, unknown>): string {
  const verification = claimVerificationState(packet);
  return verification ? ` Claim ${verification.verdict} allows ${verification.allowedNextStage}.` : "";
}

function claimVerificationState(packet: Record<string, unknown>): {
  verdict: string;
  allowedNextStage: string;
  blockerCodes: string[];
  error?: string;
} | undefined {
  const verification = objectValue(packet.claim_verification);
  if (!verification) return undefined;
  const error = stringValue(verification.error);
  if (error) {
    return { verdict: "unknown", allowedNextStage: "observe", blockerCodes: [], error };
  }
  return {
    verdict: stringValue(verification.verdict) ?? "unknown",
    allowedNextStage: stringValue(verification.allowed_next_stage) ?? "observe",
    blockerCodes: Array.isArray(verification.blockers)
      ? verification.blockers.map((blocker) => stringValue(objectValue(blocker)?.code)).filter((code): code is string => Boolean(code))
      : [],
  };
}

function stageAtLeast(stage: string, minimum: string): boolean {
  return actionStageRank(stage) >= actionStageRank(minimum);
}

function actionStageRank(stage: string): number {
  switch (stage) {
    case "observe":
      return 0;
    case "explain":
      return 1;
    case "recommend":
      return 2;
    case "dry_run":
      return 3;
    case "approve":
      return 4;
    case "execute":
      return 5;
    case "verify":
      return 6;
    case "close_loop":
      return 7;
    default:
      return -1;
  }
}

function uniqueStepId(plan: AutonomyPlanStep[], base: string): string {
  const ids = new Set(plan.map((step) => step.id));
  if (!ids.has(base)) return base;
  let index = 2;
  while (ids.has(`${base}-${index}`)) index += 1;
  return `${base}-${index}`;
}

function objectValue(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.map(stringValue).filter((item): item is string => Boolean(item)) : [];
}
