import { digestAgentGymJson } from "../agent-gym/canonical-json.js";
import type { AgentGymJson } from "../agent-gym/fixture-case.js";
import type { HostedHillclimbRepeatWindowV1 } from "./hosted-hillclimb-repeat-window.js";

export interface HostedHillclimbRepeatVerdictV1 {
  readonly blockers: readonly string[];
  readonly comparison_count: number;
  readonly corpus_digest: string;
  readonly decision: "hold" | "stable";
  readonly evaluated_at: string;
  readonly generator_model_id: string;
  readonly judge_model_id: string;
  readonly judge_repair_increase_count: number;
  readonly promotion_flip_count: number;
  readonly regression_increase_count: number;
  readonly schema_version: "slack-working-state-hosted-hillclimb-repeat-verdict/v1";
  readonly verdict_digest: string;
  readonly window_digest: string;
}

/** Projects a bounded content-free decision from one sealed repeat window. */
export function decideHostedHillclimbRepeatVerdict(
  window: HostedHillclimbRepeatWindowV1,
): HostedHillclimbRepeatVerdictV1 {
  if (window.schema_version !== "slack-working-state-hosted-hillclimb-repeat-window/v1") {
    throw new Error("Hosted hillclimb repeat verdict requires a v1 window.");
  }
  const body = {
    blockers: Object.freeze([...window.stability.blockers]),
    comparison_count: window.comparison_count,
    corpus_digest: window.corpus_digest,
    decision: window.stability.stable ? "stable" : "hold",
    evaluated_at: window.last_evaluated_at,
    generator_model_id: window.generator_model_id,
    judge_model_id: window.judge_model_id,
    judge_repair_increase_count: window.judge_repair_increase_count,
    promotion_flip_count: window.promotion_flip_count,
    regression_increase_count: window.regression_increase_count,
    schema_version: "slack-working-state-hosted-hillclimb-repeat-verdict/v1",
    window_digest: digestAgentGymJson(window as unknown as AgentGymJson),
  } as const;
  return Object.freeze({
    ...body,
    verdict_digest: digestAgentGymJson(body),
  });
}

/** Verifies the self-contained repeat verdict identity and decision coherence. */
export function validateHostedHillclimbRepeatVerdict(
  value: HostedHillclimbRepeatVerdictV1,
): HostedHillclimbRepeatVerdictV1 {
  if (value.schema_version !== "slack-working-state-hosted-hillclimb-repeat-verdict/v1"
    || !/^sha256:[0-9a-f]{64}$/u.test(value.window_digest)
    || !/^sha256:[0-9a-f]{64}$/u.test(value.verdict_digest)
    || (value.decision === "stable" && value.blockers.length !== 0)
    || (value.decision === "hold" && value.blockers.length === 0)) {
    throw new Error("Hosted hillclimb repeat verdict is invalid.");
  }
  const body = {
    blockers: value.blockers,
    comparison_count: value.comparison_count,
    corpus_digest: value.corpus_digest,
    decision: value.decision,
    evaluated_at: value.evaluated_at,
    generator_model_id: value.generator_model_id,
    judge_model_id: value.judge_model_id,
    judge_repair_increase_count: value.judge_repair_increase_count,
    promotion_flip_count: value.promotion_flip_count,
    regression_increase_count: value.regression_increase_count,
    schema_version: value.schema_version,
    window_digest: value.window_digest,
  } as const;
  if (digestAgentGymJson(body) !== value.verdict_digest) {
    throw new Error("Hosted hillclimb repeat verdict is invalid.");
  }
  return Object.freeze({ ...value, blockers: Object.freeze([...value.blockers]) });
}
