import assert from "node:assert/strict";
import test from "node:test";

import {
  buildAgentGymCorpus,
  calibrateAgentGymEvaluator,
  decideAgentGymCorpusAdmission,
  decideAgentGymEvaluatorAdmission,
  defineAgentGymEvaluationSuite,
  defineAgentGymEvaluatorManifest,
  defineAgentGymEvaluatorRubric,
  recordAgentGymCorpusQuality,
} from "../src/index.js";

test("evaluation suites seal admitted non-training cases", () => {
  const setup = evaluationSetup();
  const suite = defineAgentGymEvaluationSuite(
    setup.fixtures,
    setup.quality,
    setup.evaluatorAdmission,
    { partitions: ["held_out", "shadow"], suite_ref: "agent-gym-suite://nightly/default" },
  );
  assert.equal(suite.case_count, 2);
  assert.deepEqual(suite.partitions, ["held_out", "shadow"]);
  assert.deepEqual(suite.cases.map((entry) => entry.partition), ["held_out", "shadow"]);
  assert.match(suite.suite_digest, /^sha256:[0-9a-f]{64}$/u);
});

test("evaluation suites reject unadmitted evaluator evidence", () => {
  const setup = evaluationSetup();
  assert.throws(() => defineAgentGymEvaluationSuite(
    setup.fixtures,
    setup.quality,
    { ...setup.evaluatorAdmission, admitted: false },
    { partitions: ["held_out"], suite_ref: "agent-gym-suite://nightly/default" },
  ), /evaluation suite is invalid/u);
});

function evaluationSetup() {
  const fixtures = [
    fixture("train", "train", "Train request."),
    fixture("held-out", "held_out", "Held-out request.", ["safety"]),
    fixture("shadow", "shadow", "Shadow request.", ["latency"]),
  ];
  const coveragePolicy = {
    minimum_partition_cases: { held_out: 1, shadow: 1, train: 1 },
    policy_ref: "agent-gym-corpus-policy://suite/default",
    required_slices: [],
    schema_version: "agent-gym-corpus-coverage-policy/v1" as const,
  };
  const build = buildAgentGymCorpus(fixtures, {
    build_ref: "agent-gym-corpus-build://suite/default",
    built_at: "2026-08-12T11:00:00.000Z",
    source_revision: "source-revision://cerebro/suite",
  });
  const quality = recordAgentGymCorpusQuality(
    build,
    decideAgentGymCorpusAdmission(fixtures, coveragePolicy),
    { evaluated_at: "2026-08-12T11:01:00.000Z", evaluation_ref: "agent-gym-quality://suite/default" },
  );
  const rubric = defineAgentGymEvaluatorRubric(rubricInput());
  const modelJudge = defineAgentGymEvaluatorManifest(modelJudgeInput(rubric.rubric_digest));
  const deterministic = defineAgentGymEvaluatorManifest(deterministicInput(rubric.rubric_digest));
  const calibrationPolicy = {
    maximum_mean_absolute_error: 0.1,
    maximum_sample_absolute_error: 0.2,
    minimum_sample_count: 2,
    policy_ref: "agent-gym-calibration-policy://suite/default",
    schema_version: "agent-gym-calibration-policy/v1" as const,
  };
  const calibration = calibrateAgentGymEvaluator(modelJudge, calibrationPolicy, {
    calibrated_at: "2026-08-12T11:02:00.000Z",
    calibration_dataset_digest: digest("f"),
    samples: [
      { expected_score: 0.9, observed_score: 0.85, sample_ref: "agent-gym-calibration-sample://suite/one" },
      { expected_score: 0.5, observed_score: 0.55, sample_ref: "agent-gym-calibration-sample://suite/two" },
    ],
  });
  const evaluatorAdmission = decideAgentGymEvaluatorAdmission(
    rubric,
    [modelJudge, deterministic],
    [calibration],
    {
      maximum_calibration_age_ms: 86_400_000,
      policy_ref: "agent-gym-evaluator-admission-policy://suite/default",
      required_calibration_dataset_digest: calibration.calibration_dataset_digest,
      required_calibration_policy_digest: calibration.policy_digest,
      schema_version: "agent-gym-evaluator-admission-policy/v1",
    },
    "2026-08-12T11:03:00.000Z",
  );
  return { deterministic, evaluatorAdmission, fixtures, modelJudge, quality, rubric };
}

function rubricInput() {
  return {
    metrics: [
      { blocking: false, evaluator_kind: "model_judge" as const, metric_id: "answer.grounded", minimum_score: 0.8, weight: 2 },
      { blocking: true, evaluator_kind: "deterministic" as const, metric_id: "effect.authorized", minimum_score: 1, weight: 1 },
    ],
    rubric_ref: "agent-gym-rubric://suite/default",
    schema_version: "agent-gym-evaluator-rubric/v1" as const,
  };
}

function modelJudgeInput(rubricDigest: string) {
  return {
    evaluator_kind: "model_judge" as const,
    evaluator_ref: "agent-gym-evaluator://suite/judge",
    implementation_digest: digest("a"),
    model: { inference_config_digest: digest("b"), model_ref: "model://judge/primary" },
    output_schema_digest: digest("c"),
    rubric_digest: rubricDigest,
    schema_version: "agent-gym-evaluator-manifest/v1" as const,
  };
}

function deterministicInput(rubricDigest: string) {
  return {
    evaluator_kind: "deterministic" as const,
    evaluator_ref: "agent-gym-evaluator://suite/deterministic",
    implementation_digest: digest("d"),
    output_schema_digest: digest("e"),
    rubric_digest: rubricDigest,
    schema_version: "agent-gym-evaluator-manifest/v1" as const,
  };
}

function fixture(
  suffix: string,
  partition: "held_out" | "shadow" | "train",
  text: string,
  labels: readonly string[] = ["support"],
) {
  return {
    case_ref: `agent-gym-case://suite/${suffix}`,
    expected_invariants: ["answer-grounded"],
    labels,
    partition,
    schema_version: "agent-gym-fixture-case/v1" as const,
    slack_events: [{
      event_ref: `slack-event://suite/${suffix}`,
      kind: "mention" as const,
      occurred_at: "2026-08-12T10:59:00.000Z",
      payload: { text },
    }],
    tool_fixtures: [{
      call_ref: `tool-call://suite/${suffix}`,
      input: { alert_ref: `alert://suite/${suffix}` },
      outcome: "success" as const,
      output: { severity: "high" },
      tool_id: "alerts.read",
    }],
  };
}

function digest(character: string): string {
  return `sha256:${character.repeat(64)}`;
}
