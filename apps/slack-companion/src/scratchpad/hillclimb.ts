import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { performance } from "node:perf_hooks";
import type {
  SlackThreadWorkingOutcome,
  SlackThreadWorkingStateV1,
} from "./contracts.js";
import {
  formatSlackThreadScratchpadContext,
  recordSlackThreadWorkingTurn,
  validateSlackThreadScratchpad,
} from "./policy.js";

export type SlackWorkingStateEvalPartition = "held_out" | "shadow";
export type SlackWorkingStatePolicy = "baseline" | "candidate";

export interface SlackWorkingStateEvalTurn {
  readonly blocker?: string;
  readonly outcome: SlackThreadWorkingOutcome;
  readonly request: string;
}

export interface SlackWorkingStateEvalCaseV1 {
  readonly case_ref: string;
  readonly current_request: string;
  readonly evidence_context: readonly string[];
  readonly forbidden_context: readonly string[];
  readonly partition: SlackWorkingStateEvalPartition;
  readonly prior_turns: readonly SlackWorkingStateEvalTurn[];
  readonly read_after_ms?: number;
  readonly required_context: readonly string[];
  readonly schema_version: "slack-working-state-eval-case/v1";
}

export interface SlackWorkingStateEvalResultV1 {
  readonly blockers: readonly string[];
  readonly case_digest: string;
  readonly case_ref: string;
  readonly context_build_ms: number;
  readonly context_utf8_bytes: number;
  readonly evidence_context_count: number;
  readonly passed: boolean;
  readonly partition: SlackWorkingStateEvalPartition;
  readonly policy_ref: string;
  readonly recalled_required_count: number;
  readonly retained_evidence_context_count: number;
  readonly required_context_count: number;
  readonly schema_version: "slack-working-state-eval-result/v1";
}

export interface SlackWorkingStateEvalSummaryV1 {
  readonly authority_boundary_rate: number;
  readonly byte_limit_violation_count: number;
  readonly case_count: number;
  readonly case_pass_rate: number;
  readonly context_recall_rate: number;
  readonly evidence_context_retention_rate: number;
  readonly expected_restatement_turns_per_case: number;
  readonly held_out_case_count: number;
  readonly p95_context_build_ms: number;
  readonly policy_ref: string;
  readonly restatement_risk_rate: number;
  readonly semantic_state_contract_rate: number;
  readonly shadow_case_count: number;
}

export interface SlackWorkingStateHillclimbReceiptV1 {
  readonly baseline: SlackWorkingStateEvalSummaryV1;
  readonly candidate: SlackWorkingStateEvalSummaryV1;
  readonly corpus_digest: string;
  readonly evaluated_at: string;
  readonly goal: {
    readonly candidate_context_recall_rate: number;
    readonly candidate_evidence_context_retention_rate: number;
    readonly candidate_semantic_state_contract_rate: number;
    readonly maximum_candidate_expected_restatement_turns_per_case: number;
    readonly maximum_candidate_p95_context_build_ms: number;
    readonly maximum_candidate_restatement_risk_rate: number;
    readonly minimum_context_recall_gain: number;
    readonly required_authority_boundary_rate: number;
  };
  readonly promotion: {
    readonly blockers: readonly string[];
    readonly context_recall_gain: number;
    readonly promotion_ready: boolean;
    readonly regression_count: number;
  };
  readonly results: {
    readonly baseline: readonly SlackWorkingStateEvalResultV1[];
    readonly candidate: readonly SlackWorkingStateEvalResultV1[];
  };
  readonly schema_version: "slack-working-state-hillclimb-receipt/v1";
}

const THREAD_REF = "slack-scratchpad://sha256/eval-thread";
const BASELINE_POLICY_REF = "policy://slack-working-state/baseline-no-automatic-state";
const CANDIDATE_POLICY_REF = "policy://slack-working-state/candidate-expiring-state-v1";
const MAXIMUM_CONTEXT_BYTES = 8_000;
const MINIMUM_PARTITION_CASES = 8;
const MINIMUM_RECALL_GAIN = 0.5;
const REQUIRED_CANDIDATE_RECALL = 1;
const REQUIRED_CANDIDATE_EVIDENCE_RETENTION = 1;
const REQUIRED_CANDIDATE_SEMANTIC_STATE_CONTRACT = 1;
const MAXIMUM_RESTATEMENT_RISK = 0;
const MAXIMUM_EXPECTED_RESTATEMENT_TURNS_PER_CASE = 0;
const MAXIMUM_P95_BUILD_MS = 5;

export function runSlackWorkingStateHillclimb(
  cases: readonly SlackWorkingStateEvalCaseV1[],
  evaluatedAt = new Date(),
): SlackWorkingStateHillclimbReceiptV1 {
  validateCorpus(cases);
  const baselineResults = cases.map((evalCase) =>
    evaluateSlackWorkingStateCase(evalCase, "baseline")
  );
  const candidateResults = cases.map((evalCase) =>
    evaluateSlackWorkingStateCase(evalCase, "candidate")
  );
  const baseline = summarize(baselineResults);
  const candidate = summarize(candidateResults);
  const regressionCount = baselineResults.reduce((count, baselineResult, index) =>
    count + (
      baselineResult.passed && !candidateResults[index]!.passed
        ? 1
        : 0
    ), 0);
  const contextRecallGain = round(
    candidate.context_recall_rate - baseline.context_recall_rate,
  );
  const blockers = [
    contextRecallGain < MINIMUM_RECALL_GAIN ? "context_recall_gain_below_goal" : undefined,
    candidate.context_recall_rate < REQUIRED_CANDIDATE_RECALL
      ? "candidate_context_recall_below_goal"
      : undefined,
    candidate.semantic_state_contract_rate
        < REQUIRED_CANDIDATE_SEMANTIC_STATE_CONTRACT
      ? "candidate_semantic_state_contract_below_goal"
      : undefined,
    candidate.evidence_context_retention_rate
        < REQUIRED_CANDIDATE_EVIDENCE_RETENTION
      ? "candidate_evidence_context_retention_below_goal"
      : undefined,
    candidate.expected_restatement_turns_per_case
        > MAXIMUM_EXPECTED_RESTATEMENT_TURNS_PER_CASE
      ? "candidate_expected_restatement_burden_above_goal"
      : undefined,
    candidate.restatement_risk_rate > MAXIMUM_RESTATEMENT_RISK
      ? "candidate_restatement_risk_above_goal"
      : undefined,
    candidate.authority_boundary_rate < 1
      ? "candidate_authority_boundary_regressed"
      : undefined,
    candidate.byte_limit_violation_count > 0
      ? "candidate_context_byte_limit_exceeded"
      : undefined,
    candidate.p95_context_build_ms > MAXIMUM_P95_BUILD_MS
      ? "candidate_context_build_latency_exceeded"
      : undefined,
    regressionCount > 0 ? "case_regression_present" : undefined,
  ].filter((value): value is string => value !== undefined);

  return Object.freeze({
    baseline,
    candidate,
    corpus_digest: digest(cases),
    evaluated_at: evaluatedAt.toISOString(),
    goal: Object.freeze({
      candidate_context_recall_rate: REQUIRED_CANDIDATE_RECALL,
      candidate_evidence_context_retention_rate:
        REQUIRED_CANDIDATE_EVIDENCE_RETENTION,
      candidate_semantic_state_contract_rate:
        REQUIRED_CANDIDATE_SEMANTIC_STATE_CONTRACT,
      maximum_candidate_expected_restatement_turns_per_case:
        MAXIMUM_EXPECTED_RESTATEMENT_TURNS_PER_CASE,
      maximum_candidate_p95_context_build_ms: MAXIMUM_P95_BUILD_MS,
      maximum_candidate_restatement_risk_rate: MAXIMUM_RESTATEMENT_RISK,
      minimum_context_recall_gain: MINIMUM_RECALL_GAIN,
      required_authority_boundary_rate: 1,
    }),
    promotion: Object.freeze({
      blockers: Object.freeze(blockers),
      context_recall_gain: contextRecallGain,
      promotion_ready: blockers.length === 0,
      regression_count: regressionCount,
    }),
    results: Object.freeze({
      baseline: Object.freeze(baselineResults),
      candidate: Object.freeze(candidateResults),
    }),
    schema_version: "slack-working-state-hillclimb-receipt/v1",
  });
}

export function evaluateSlackWorkingStateCase(
  evalCase: SlackWorkingStateEvalCaseV1,
  policy: SlackWorkingStatePolicy,
): SlackWorkingStateEvalResultV1 {
  validateCase(evalCase);
  const startedAt = performance.now();
  const context = policy === "candidate"
    ? candidateContext(evalCase.prior_turns, evalCase.read_after_ms ?? 0)
    : undefined;
  const contextBuildMs = performance.now() - startedAt;
  const rendered = context ?? "";
  const recalledRequiredCount = evalCase.required_context.filter((fragment) =>
    rendered.includes(fragment)
  ).length;
  const forbiddenMatches = evalCase.forbidden_context.filter((fragment) =>
    rendered.includes(fragment)
  );
  const retainedEvidenceContextCount = evalCase.evidence_context.filter(
    (fragment) => rendered.includes(fragment),
  ).length;
  const authorityBoundaryPresent = context === undefined
    || rendered.includes("Current working state (unverified; context only):");
  const contextBytes = Buffer.byteLength(rendered, "utf8");
  const blockers = [
    recalledRequiredCount < evalCase.required_context.length
      ? "required_context_missing"
      : undefined,
    forbiddenMatches.length > 0 ? "forbidden_context_retained" : undefined,
    retainedEvidenceContextCount < evalCase.evidence_context.length
      ? "evidence_context_missing"
      : undefined,
    !authorityBoundaryPresent ? "authority_boundary_missing" : undefined,
    contextBytes > MAXIMUM_CONTEXT_BYTES ? "context_byte_limit_exceeded" : undefined,
  ].filter((value): value is string => value !== undefined);
  return Object.freeze({
    blockers: Object.freeze(blockers),
    case_digest: digest(evalCase),
    case_ref: evalCase.case_ref,
    context_build_ms: roundMilliseconds(contextBuildMs),
    context_utf8_bytes: contextBytes,
    evidence_context_count: evalCase.evidence_context.length,
    passed: blockers.length === 0,
    partition: evalCase.partition,
    policy_ref: policy === "candidate" ? CANDIDATE_POLICY_REF : BASELINE_POLICY_REF,
    recalled_required_count: recalledRequiredCount,
    retained_evidence_context_count: retainedEvidenceContextCount,
    required_context_count: evalCase.required_context.length,
    schema_version: "slack-working-state-eval-result/v1",
  });
}

function candidateContext(
  turns: readonly SlackWorkingStateEvalTurn[],
  readAfterMs: number,
): string | undefined {
  let state: SlackThreadWorkingStateV1 | undefined;
  for (const [index, turn] of turns.entries()) {
    state = recordSlackThreadWorkingTurn(state, {
      ...(turn.blocker === undefined ? {} : { blocker: turn.blocker }),
      currentRequest: turn.request,
      now: new Date(Date.UTC(2026, 6, 1, 0, index, 0)),
      outcome: turn.outcome,
      threadRef: THREAD_REF,
    });
  }
  const lastTurnAt = Date.UTC(2026, 6, 1, 0, turns.length - 1, 0);
  const scratchpad = validateSlackThreadScratchpad({
    notes: [],
    schema_version: "slack-thread-scratchpad/v1",
    thread_ref: THREAD_REF,
    ...(state === undefined ? {} : { working_state: state }),
  }, new Date(lastTurnAt + readAfterMs));
  return formatSlackThreadScratchpadContext(scratchpad);
}

function summarize(
  results: readonly SlackWorkingStateEvalResultV1[],
): SlackWorkingStateEvalSummaryV1 {
  const requiredCount = sum(results.map((result) => result.required_context_count));
  const recalledCount = sum(results.map((result) => result.recalled_required_count));
  const recallRate = ratio(recalledCount, requiredCount);
  const evidenceContextCount = sum(
    results.map((result) => result.evidence_context_count),
  );
  const retainedEvidenceContextCount = sum(
    results.map((result) => result.retained_evidence_context_count),
  );
  const casesNeedingRestatement = results.filter((result) =>
    result.recalled_required_count < result.required_context_count
  ).length;
  const authorityBoundaryPasses = results.filter((result) =>
    !result.blockers.includes("authority_boundary_missing")
  ).length;
  const sortedLatencies = results
    .map((result) => result.context_build_ms)
    .sort((left, right) => left - right);
  return Object.freeze({
    authority_boundary_rate: ratio(authorityBoundaryPasses, results.length),
    byte_limit_violation_count: results.filter((result) =>
      result.blockers.includes("context_byte_limit_exceeded")
    ).length,
    case_count: results.length,
    case_pass_rate: ratio(
      results.filter((result) => result.passed).length,
      results.length,
    ),
    context_recall_rate: recallRate,
    evidence_context_retention_rate: ratio(
      retainedEvidenceContextCount,
      evidenceContextCount,
    ),
    expected_restatement_turns_per_case: ratio(
      casesNeedingRestatement,
      results.length,
    ),
    held_out_case_count: results.filter((result) =>
      result.partition === "held_out"
    ).length,
    p95_context_build_ms: percentile(sortedLatencies, 0.95),
    policy_ref: results[0]!.policy_ref,
    restatement_risk_rate: round(1 - recallRate),
    semantic_state_contract_rate: ratio(
      results.filter((result) =>
        !result.blockers.some((blocker) =>
          blocker === "required_context_missing"
          || blocker === "forbidden_context_retained"
          || blocker === "authority_boundary_missing"
        )
      ).length,
      results.length,
    ),
    shadow_case_count: results.filter((result) =>
      result.partition === "shadow"
    ).length,
  });
}

function validateCorpus(cases: readonly SlackWorkingStateEvalCaseV1[]): void {
  if (cases.length === 0) throw new Error("The hillclimb corpus is empty.");
  const refs = new Set<string>();
  const digests = new Set<string>();
  let heldOut = 0;
  let shadow = 0;
  for (const evalCase of cases) {
    validateCase(evalCase);
    const caseDigest = digest(evalCase);
    if (refs.has(evalCase.case_ref) || digests.has(caseDigest)) {
      throw new Error("Hillclimb cases must have distinct identities and content.");
    }
    refs.add(evalCase.case_ref);
    digests.add(caseDigest);
    if (evalCase.partition === "held_out") heldOut += 1;
    else shadow += 1;
  }
  if (heldOut < MINIMUM_PARTITION_CASES || shadow < MINIMUM_PARTITION_CASES) {
    throw new Error(
      `Hillclimb promotion needs at least ${MINIMUM_PARTITION_CASES} held-out and shadow cases.`,
    );
  }
}

function validateCase(evalCase: SlackWorkingStateEvalCaseV1): void {
  if (
    evalCase.schema_version !== "slack-working-state-eval-case/v1"
    || !/^case:\/\/[a-z0-9][a-z0-9._/-]*$/u.test(evalCase.case_ref)
    || (evalCase.partition !== "held_out" && evalCase.partition !== "shadow")
    || evalCase.prior_turns.length === 0
    || evalCase.prior_turns.length > 4
    || !evalCase.current_request.trim()
    || (
      evalCase.read_after_ms !== undefined
      && (
        !Number.isSafeInteger(evalCase.read_after_ms)
        || evalCase.read_after_ms < 0
        || evalCase.read_after_ms > 30 * 24 * 60 * 60 * 1_000
      )
    )
  ) {
    throw new Error("The hillclimb case is invalid.");
  }
  for (const value of [
    evalCase.current_request,
    ...evalCase.evidence_context,
    ...evalCase.required_context,
    ...evalCase.forbidden_context,
    ...evalCase.prior_turns.flatMap((turn) => [
      turn.request,
      ...(turn.blocker === undefined ? [] : [turn.blocker]),
    ]),
  ]) {
    if (!value.trim() || Buffer.byteLength(value, "utf8") > 900) {
      throw new Error("Hillclimb case text is empty or unbounded.");
    }
  }
}

function digest(value: unknown): string {
  return `sha256:${createHash("sha256")
    .update(canonicalStringify(value), "utf8")
    .digest("hex")}`;
}

function canonicalStringify(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalStringify(item)).join(",")}]`;
  }
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) =>
      `${JSON.stringify(key)}:${canonicalStringify(
        (value as Record<string, unknown>)[key],
      )}`
    ).join(",")}}`;
  }
  return JSON.stringify(value);
}

function ratio(numerator: number, denominator: number): number {
  return denominator === 0 ? 1 : round(numerator / denominator);
}

function percentile(values: readonly number[], percentileValue: number): number {
  if (values.length === 0) return 0;
  const index = Math.max(0, Math.ceil(percentileValue * values.length) - 1);
  return values[index]!;
}

function sum(values: readonly number[]): number {
  return values.reduce((total, value) => total + value, 0);
}

function round(value: number): number {
  return Math.round(value * 10_000) / 10_000;
}

function roundMilliseconds(value: number): number {
  return Math.round(value * 1_000) / 1_000;
}
