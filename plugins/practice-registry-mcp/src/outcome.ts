import type { PracticeDecision, PracticeOutcome } from "./schema.js";

const passDecisions = new Set<string>(["allowed", "follow_guidance"]);

export function isPassingDecision(decision: PracticeDecision | string): boolean {
  return passDecisions.has(decision);
}

export function isActionableDecision(decision: PracticeDecision | string): boolean {
  return !isPassingDecision(decision);
}

export function outcomeForDecision(decision: PracticeDecision): PracticeOutcome {
  const passed = isPassingDecision(decision);
  return {
    passed,
    action_required: !passed,
    rerun_required: !passed,
  };
}
