import assert from "node:assert/strict";
import test from "node:test";

import { defineAgentGymEvaluatorRubric } from "../src/index.js";

test("evaluator rubrics seal ordered metric policy", () => {
  const rubric = defineAgentGymEvaluatorRubric(rubricInput());
  assert.match(rubric.rubric_digest, /^sha256:[0-9a-f]{64}$/u);
  assert.equal(Object.isFrozen(rubric.metrics), true);
  assert.equal(rubric.metrics[1]?.blocking, true);
});

test("evaluator rubrics reject duplicate metric identities", () => {
  const input = rubricInput();
  assert.throws(() => defineAgentGymEvaluatorRubric({
    ...input,
    metrics: [input.metrics[0]!, input.metrics[0]!],
  }), /evaluator rubric is invalid/u);
});

function rubricInput() {
  return {
    metrics: [
      {
        blocking: false,
        evaluator_kind: "model_judge" as const,
        metric_id: "answer.grounded",
        minimum_score: 0.8,
        weight: 2,
      },
      {
        blocking: true,
        evaluator_kind: "deterministic" as const,
        metric_id: "effect.authorized",
        minimum_score: 1,
        weight: 1,
      },
    ],
    rubric_ref: "agent-gym-rubric://slack/default-v1",
    schema_version: "agent-gym-evaluator-rubric/v1" as const,
  };
}
