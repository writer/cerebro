import { AgentGymContractError } from "./index.js";

export interface AgentGymRunSummaryV1 {
  readonly artifact_refs: readonly string[];
  readonly blocker_codes: readonly string[];
  readonly candidate_ref: string;
  readonly completed_at: string;
  readonly failed_case_count: number;
  readonly passed_case_count: number;
  readonly run_ref: string;
  readonly schema_version: "agent-gym-run-summary/v1";
  readonly status: "blocked" | "failed" | "passed";
  readonly total_case_count: number;
}

/** Validates the small summary consumed by CI and draft-PR automation. */
export function validateAgentGymRunSummary(summary: AgentGymRunSummaryV1): AgentGymRunSummaryV1 {
  if (summary.schema_version !== "agent-gym-run-summary/v1") invalid();
  for (const ref of [summary.run_ref, summary.candidate_ref]) reference(ref);
  timestamp(summary.completed_at);
  integer(summary.total_case_count, 1_000_000, false);
  integer(summary.failed_case_count, summary.total_case_count);
  integer(summary.passed_case_count, summary.total_case_count);
  if (summary.failed_case_count + summary.passed_case_count !== summary.total_case_count) invalid();
  if (!["blocked", "failed", "passed"].includes(summary.status)) invalid();
  strings(summary.blocker_codes, 64, false);
  references(summary.artifact_refs, 128);
  if ((summary.status === "passed") !== (summary.failed_case_count === 0)) invalid();
  if ((summary.status === "blocked") !== (summary.blocker_codes.length > 0)) invalid();
  return Object.freeze({
    ...summary,
    artifact_refs: Object.freeze([...summary.artifact_refs]),
    blocker_codes: Object.freeze([...summary.blocker_codes]),
  });
}

function bounded(value: string, maximum: number): void {
  if (typeof value !== "string" || !value.trim() || value.length > maximum
    || /[\u0000-\u001f\u007f]/u.test(value)) invalid();
}
function integer(value: number, maximum: number, allowZero = true): void {
  if (!Number.isSafeInteger(value) || value < (allowZero ? 0 : 1) || value > maximum) invalid();
}
function reference(value: string): void { bounded(value, 240); if (!value.includes("://")) invalid(); }
function references(values: readonly string[], maximum: number): void {
  strings(values, maximum, false);
  for (const value of values) reference(value);
}
function strings(values: readonly string[], maximum: number, requireOne: boolean): void {
  if (!Array.isArray(values) || values.length > maximum || (requireOne && values.length === 0)
    || new Set(values).size !== values.length) invalid();
  for (const value of values) bounded(value, 240);
}
function timestamp(value: string): void {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)
    || !Number.isFinite(Date.parse(value))) invalid();
}
function invalid(): never { throw new AgentGymContractError("Agent gym run summary is invalid."); }
