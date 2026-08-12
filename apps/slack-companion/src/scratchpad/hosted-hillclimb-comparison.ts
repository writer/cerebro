import type { HostedHillclimbReceipt } from "./hosted-hillclimb.js";

export interface HostedHillclimbComparisonV1 {
  readonly blocker_change: {
    readonly added: readonly string[];
    readonly resolved: readonly string[];
  };
  readonly candidate_delta: {
    readonly authority_boundary_rate: number;
    readonly context_recall_rate: number;
    readonly evidence_context_retention_rate: number;
    readonly expected_restatement_turns_per_case: number;
    readonly p95_inference_latency_ms: number;
    readonly semantic_state_contract_rate: number;
  };
  readonly current_evaluated_at: string;
  readonly previous_evaluated_at: string;
  readonly promotion_stable: boolean;
  readonly regression_count_delta: number;
  readonly schema_version: "slack-working-state-hosted-hillclimb-comparison/v1";
}

/** Compares repeat measurements only when corpus and model identities are unchanged. */
export function compareHostedSlackWorkingStateHillclimbs(
  previous: HostedHillclimbReceipt,
  current: HostedHillclimbReceipt,
): HostedHillclimbComparisonV1 {
  if (previous.schema_version !== "slack-working-state-hosted-hillclimb-receipt/v1"
    || current.schema_version !== "slack-working-state-hosted-hillclimb-receipt/v1") {
    throw new Error("Hosted hillclimb comparison requires v1 receipts.");
  }
  if (previous.corpus_digest !== current.corpus_digest) {
    throw new Error("Hosted hillclimb comparison requires the same corpus digest.");
  }
  if (previous.generator.model_id !== current.generator.model_id
    || previous.judge.model_id !== current.judge.model_id) {
    throw new Error("Hosted hillclimb comparison requires the same generator and judge models.");
  }
  const previousTime = Date.parse(previous.evaluated_at);
  const currentTime = Date.parse(current.evaluated_at);
  if (!Number.isFinite(previousTime) || !Number.isFinite(currentTime)
    || currentTime <= previousTime) {
    throw new Error("Hosted hillclimb comparison requires increasing evaluation times.");
  }
  const previousBlockers = new Set(previous.promotion.blockers);
  const currentBlockers = new Set(current.promotion.blockers);
  return Object.freeze({
    blocker_change: Object.freeze({
      added: Object.freeze([...currentBlockers].filter((value) => !previousBlockers.has(value)).sort()),
      resolved: Object.freeze([...previousBlockers].filter((value) => !currentBlockers.has(value)).sort()),
    }),
    candidate_delta: Object.freeze({
      authority_boundary_rate: delta(
        previous.candidate.authority_boundary_rate,
        current.candidate.authority_boundary_rate,
      ),
      context_recall_rate: delta(
        previous.candidate.context_recall_rate,
        current.candidate.context_recall_rate,
      ),
      evidence_context_retention_rate: delta(
        previous.candidate.evidence_context_retention_rate,
        current.candidate.evidence_context_retention_rate,
      ),
      expected_restatement_turns_per_case: delta(
        previous.candidate.expected_restatement_turns_per_case,
        current.candidate.expected_restatement_turns_per_case,
      ),
      p95_inference_latency_ms: delta(
        previous.candidate.p95_inference_latency_ms,
        current.candidate.p95_inference_latency_ms,
      ),
      semantic_state_contract_rate: delta(
        previous.candidate.semantic_state_contract_rate,
        current.candidate.semantic_state_contract_rate,
      ),
    }),
    current_evaluated_at: current.evaluated_at,
    previous_evaluated_at: previous.evaluated_at,
    promotion_stable:
      previous.promotion.promotion_ready === current.promotion.promotion_ready,
    regression_count_delta:
      current.promotion.regression_count - previous.promotion.regression_count,
    schema_version: "slack-working-state-hosted-hillclimb-comparison/v1",
  });
}

function delta(previous: number, current: number): number {
  if (!Number.isFinite(previous) || !Number.isFinite(current)) {
    throw new Error("Hosted hillclimb comparison metrics must be finite.");
  }
  return Math.round((current - previous) * 10_000) / 10_000;
}
