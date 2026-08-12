import assert from "node:assert/strict";
import test from "node:test";

import {
  calibrateAgentGymEvaluator,
  defineAgentGymEvaluatorManifest,
  defineAgentGymEvaluatorRubric,
  recordAgentGymCaseEvaluation,
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

test("case evaluations bind ordered metrics to exact evaluator versions", () => {
  const rubric = defineAgentGymEvaluatorRubric(rubricInput());
  const modelJudge = defineAgentGymEvaluatorManifest(modelJudgeManifestInput());
  const deterministic = defineAgentGymEvaluatorManifest(deterministicManifestInput());
  const evaluation = recordAgentGymCaseEvaluation(rubric, [modelJudge, deterministic], {
    ...caseEvaluationInput(),
    metrics: [
      { evaluator_digest: modelJudge.evaluator_digest, metric_id: "answer.grounded", reason_codes: [], score: 0.9 },
      { evaluator_digest: deterministic.evaluator_digest, metric_id: "effect.authorized", reason_codes: [], score: 1 },
    ],
  });
  assert.equal(evaluation.valid, true);
  assert.equal(evaluation.weighted_score, 2.8 / 3);
  assert.deepEqual(evaluation.blocker_codes, []);
});

test("invalid evaluator output cannot carry candidate scores", () => {
  const rubric = defineAgentGymEvaluatorRubric(rubricInput());
  assert.throws(() => recordAgentGymCaseEvaluation(rubric, [
    defineAgentGymEvaluatorManifest(modelJudgeManifestInput()),
    defineAgentGymEvaluatorManifest(deterministicManifestInput()),
  ], {
    ...caseEvaluationInput(),
    invalid_reason_codes: ["judge.output_schema_mismatch"],
    metrics: [{ evaluator_digest: digest("d"), metric_id: "answer.grounded", reason_codes: [], score: 1 }],
    valid: false,
  }), /case evaluation is invalid/u);
});

test("model judge calibration measures a sealed labeled dataset", () => {
  const evaluator = defineAgentGymEvaluatorManifest(modelJudgeManifestInput());
  const calibration = calibrateAgentGymEvaluator(evaluator, calibrationPolicy(), {
    calibrated_at: "2026-08-12T10:47:00.000Z",
    calibration_dataset_digest: digest("f"),
    samples: [
      { expected_score: 0.9, observed_score: 0.85, sample_ref: "agent-gym-calibration-sample://one" },
      { expected_score: 0.5, observed_score: 0.55, sample_ref: "agent-gym-calibration-sample://two" },
    ],
  });
  assert.equal(calibration.passed, true);
  assert.ok(calibration.mean_absolute_error < 0.1);
  assert.match(calibration.calibration_digest, /^sha256:[0-9a-f]{64}$/u);
});

test("model judge calibration fails closed on too few labeled samples", () => {
  const calibration = calibrateAgentGymEvaluator(
    defineAgentGymEvaluatorManifest(modelJudgeManifestInput()),
    calibrationPolicy(),
    {
      calibrated_at: "2026-08-12T10:47:00.000Z",
      calibration_dataset_digest: digest("f"),
      samples: [{ expected_score: 1, observed_score: 1, sample_ref: "agent-gym-calibration-sample://one" }],
    },
  );
  assert.equal(calibration.passed, false);
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

function deterministicManifestInput() {
  return {
    evaluator_kind: "deterministic" as const,
    evaluator_ref: "agent-gym-evaluator://effect-authority/v1",
    implementation_digest: digest("d"),
    output_schema_digest: digest("e"),
    rubric_digest: defineAgentGymEvaluatorRubric(rubricInput()).rubric_digest,
    schema_version: "agent-gym-evaluator-manifest/v1" as const,
  };
}

function caseEvaluationInput() {
  return {
    candidate_ref: "agent-gym-candidate://slack/challenger",
    case_ref: "agent-gym-case://slack/held-out-one",
    evaluated_at: "2026-08-12T10:45:00.000Z",
    evaluation_ref: "agent-gym-evaluation://nightly/held-out-one",
    invalid_reason_codes: [],
    metrics: [],
    replay_ref: "agent-gym-replay://nightly/held-out-one",
    schema_version: "agent-gym-case-evaluation/v1" as const,
    valid: true,
  };
}

function calibrationPolicy() {
  return {
    maximum_mean_absolute_error: 0.1,
    maximum_sample_absolute_error: 0.2,
    minimum_sample_count: 2,
    policy_ref: "agent-gym-calibration-policy://model-judge/default-v1",
    schema_version: "agent-gym-calibration-policy/v1" as const,
  };
}

function digest(character: string): string {
  return `sha256:${character.repeat(64)}`;
}
