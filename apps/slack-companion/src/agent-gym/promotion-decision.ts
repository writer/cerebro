import { AgentGymContractError } from "./index.js";

export type AgentGymPromotionDisposition = "blocked" | "inconclusive" | "promote";

export interface AgentGymPromotionDecisionV1 {
  readonly baseline_candidate_ref: string;
  readonly candidate_ref: string;
  readonly comparison_ref: string;
  readonly decided_at: string;
  readonly decision_ref: string;
  readonly disposition: AgentGymPromotionDisposition;
  readonly held_out_passed: boolean;
  readonly reason_codes: readonly string[];
  readonly schema_version: "agent-gym-promotion-decision/v1";
  readonly safety_blocker_codes: readonly string[];
}

/** Requires positive held-out evidence and no safety blocker for promotion. */
export function validateAgentGymPromotionDecision(
  decision: AgentGymPromotionDecisionV1,
): AgentGymPromotionDecisionV1 {
  if (decision.schema_version !== "agent-gym-promotion-decision/v1") invalid();
  for (const ref of [decision.decision_ref, decision.baseline_candidate_ref,
    decision.candidate_ref, decision.comparison_ref]) reference(ref);
  if (decision.baseline_candidate_ref === decision.candidate_ref) invalid();
  timestamp(decision.decided_at);
  if (!["blocked", "inconclusive", "promote"].includes(decision.disposition)) invalid();
  strings(decision.reason_codes, 64);
  strings(decision.safety_blocker_codes, 64);
  if (decision.reason_codes.length === 0) invalid();
  if (decision.disposition === "promote"
    && (!decision.held_out_passed || decision.safety_blocker_codes.length > 0)) invalid();
  if (decision.safety_blocker_codes.length > 0 && decision.disposition !== "blocked") invalid();
  return Object.freeze({
    ...decision,
    reason_codes: Object.freeze([...decision.reason_codes]),
    safety_blocker_codes: Object.freeze([...decision.safety_blocker_codes]),
  });
}

function bounded(value: string, maximum: number): void {
  if (typeof value !== "string" || !value.trim() || value.length > maximum
    || /[\u0000-\u001f\u007f]/u.test(value)) invalid();
}
function reference(value: string): void { bounded(value, 240); if (!value.includes("://")) invalid(); }
function strings(values: readonly string[], maximum: number): void {
  if (!Array.isArray(values) || values.length > maximum || new Set(values).size !== values.length) invalid();
  for (const value of values) bounded(value, 160);
}
function timestamp(value: string): void {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)
    || !Number.isFinite(Date.parse(value))) invalid();
}
function invalid(): never { throw new AgentGymContractError("Agent gym promotion decision is invalid."); }
