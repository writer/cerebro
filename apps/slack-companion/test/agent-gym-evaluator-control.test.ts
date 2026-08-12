import assert from "node:assert/strict";
import test from "node:test";

import {
  defineAgentGymEvaluatorManifest,
  defineAgentGymEvaluatorRubric,
} from "../src/index.js";

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

test("model judge manifests bind exact model inference configuration", () => {
  const manifest = defineAgentGymEvaluatorManifest(modelJudgeManifestInput());
  assert.match(manifest.evaluator_digest, /^sha256:[0-9a-f]{64}$/u);
  assert.equal(manifest.model?.model_ref, "model://judge/primary");
});

test("deterministic evaluator manifests reject model configuration", () => {
  assert.throws(() => defineAgentGymEvaluatorManifest({
    ...modelJudgeManifestInput(),
    evaluator_kind: "deterministic",
  }), /evaluator manifest is invalid/u);
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

function modelJudgeManifestInput() {
  return {
    evaluator_kind: "model_judge" as const,
    evaluator_ref: "agent-gym-evaluator://grounding/v1",
    implementation_digest: digest("a"),
    model: {
      inference_config_digest: digest("b"),
      model_ref: "model://judge/primary",
    },
    output_schema_digest: digest("c"),
    rubric_digest: defineAgentGymEvaluatorRubric(rubricInput()).rubric_digest,
    schema_version: "agent-gym-evaluator-manifest/v1" as const,
  };
}

function digest(character: string): string {
  return `sha256:${character.repeat(64)}`;
}
