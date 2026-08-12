import assert from "node:assert/strict";
import test from "node:test";

import {
  buildAgentGymCorpus,
  calibrateAgentGymEvaluator,
  completeAgentGymEvaluationRun,
  decideAgentGymCorpusAdmission,
  decideAgentGymEvaluatorAdmission,
  decideAgentGymEvaluationReadiness,
  defineAgentGymEvaluationSuite,
  defineAgentGymEvaluatorManifest,
  defineAgentGymEvaluatorRubric,
  planAgentGymEvaluationRun,
  pairAgentGymEvaluationRuns,
  recordAgentGymCaseEvaluation,
  recordAgentGymCorpusQuality,
  summarizeAgentGymEvaluationSlices,
  validateAgentGymEvaluationRunPlan,
  validateAgentGymEvaluationRunResult,
  validateAgentGymEvaluationReadinessDecision,
  validateAgentGymEvaluationSliceReport,
  validateAgentGymPairedEvaluation,
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

test("evaluation run plans bind every suite case to one candidate", () => {
  const suite = evaluationSuite();
  const plan = planAgentGymEvaluationRun(suite, runPlanInput());
  assert.equal(plan.case_count, suite.case_count);
  assert.equal(plan.cases[0]?.ordinal, 0);
  assert.match(plan.plan_digest, /^sha256:[0-9a-f]{64}$/u);
  assert.deepEqual(validateAgentGymEvaluationRunPlan(plan), plan);
});

test("evaluation run plans reject tampered case identities", () => {
  const plan = planAgentGymEvaluationRun(evaluationSuite(), runPlanInput());
  assert.throws(() => validateAgentGymEvaluationRunPlan({
    ...plan,
    cases: [{ ...plan.cases[0]!, case_digest: digest("a") }, ...plan.cases.slice(1)],
  }), /evaluation run plan is invalid/u);
});

test("evaluation run results require one exact evaluation per planned case", () => {
  const setup = evaluationSetup();
  const suite = suiteFrom(setup);
  const plan = planAgentGymEvaluationRun(suite, runPlanInput());
  const result = completeAgentGymEvaluationRun(
    suite,
    plan,
    caseEvaluations(setup, suite),
    { completed_at: "2026-08-12T11:06:00.000Z", started_at: "2026-08-12T11:05:00.000Z" },
  );
  assert.equal(result.valid_case_count, 2);
  assert.equal(result.invalid_case_count, 0);
  assert.equal(result.blocker_case_count, 0);
  assert.deepEqual(validateAgentGymEvaluationRunResult(result), result);
});

test("evaluation run results reject missing case evidence", () => {
  const setup = evaluationSetup();
  const suite = suiteFrom(setup);
  assert.throws(() => completeAgentGymEvaluationRun(
    suite,
    planAgentGymEvaluationRun(suite, runPlanInput()),
    caseEvaluations(setup, suite).slice(1),
    { completed_at: "2026-08-12T11:06:00.000Z", started_at: "2026-08-12T11:05:00.000Z" },
  ), /evaluation run result is invalid/u);
});

test("evaluation slices retain partition and label evidence", () => {
  const setup = evaluationSetup();
  const suite = suiteFrom(setup);
  const result = completedRun(setup, suite);
  const report = summarizeAgentGymEvaluationSlices(suite, result);
  assert.equal(report.slices.find((entry) => entry.slice_id === "overall:all")?.case_count, 2);
  assert.equal(report.slices.find((entry) => entry.slice_id === "label:safety")?.case_count, 1);
  assert.equal(report.slices.find((entry) => entry.slice_id === "partition:shadow")?.valid_case_count, 1);
  assert.deepEqual(validateAgentGymEvaluationSliceReport(report), report);
});

test("evaluation readiness admits complete valid comparison evidence", () => {
  const setup = evaluationSetup();
  const suite = suiteFrom(setup);
  const result = completedRun(setup, suite);
  const report = summarizeAgentGymEvaluationSlices(suite, result);
  const decision = decideAgentGymEvaluationReadiness(
    suite,
    result,
    report,
    readinessPolicy(),
    "2026-08-12T11:07:00.000Z",
  );
  assert.equal(decision.ready, true);
  assert.deepEqual(decision.blocker_codes, []);
  assert.match(decision.decision_digest, /^sha256:[0-9a-f]{64}$/u);
  assert.deepEqual(validateAgentGymEvaluationReadinessDecision(decision), decision);
});

test("evaluation readiness preserves invalid judge output as a blocker", () => {
  const setup = evaluationSetup();
  const suite = suiteFrom(setup);
  const plan = planAgentGymEvaluationRun(suite, runPlanInput());
  const evaluations = caseEvaluations(setup, suite);
  const invalid = recordAgentGymCaseEvaluation(
    setup.rubric,
    [setup.modelJudge, setup.deterministic],
    {
      candidate_ref: runPlanInput().candidate_ref,
      case_ref: suite.cases[0]!.case_ref,
      evaluated_at: "2026-08-12T11:05:30.000Z",
      evaluation_ref: "agent-gym-evaluation://nightly/invalid-case",
      invalid_reason_codes: ["judge.output_schema_mismatch"],
      metrics: [],
      replay_ref: "agent-gym-replay://nightly/invalid-case",
      schema_version: "agent-gym-case-evaluation/v1",
      valid: false,
    },
  );
  const result = completeAgentGymEvaluationRun(
    suite,
    plan,
    [invalid, ...evaluations.slice(1)],
    { completed_at: "2026-08-12T11:06:00.000Z", started_at: "2026-08-12T11:05:00.000Z" },
  );
  const decision = decideAgentGymEvaluationReadiness(
    suite,
    result,
    summarizeAgentGymEvaluationSlices(suite, result),
    readinessPolicy(),
    "2026-08-12T11:07:00.000Z",
  );
  assert.equal(decision.ready, false);
  assert.deepEqual(decision.blocker_codes, [
    "evaluation.case_count_below_minimum",
    "evaluation.invalid_cases",
    "evaluation.required_slice_underfilled",
  ]);
});

test("paired evaluations require ready runs over the same case set", () => {
  const setup = evaluationSetup();
  const suite = suiteFrom(setup);
  const baseline = completedRunFor(setup, suite, "baseline", 0.8);
  const candidate = completedRunFor(setup, suite, "challenger", 0.9);
  const paired = pairAgentGymEvaluationRuns(
    suite,
    baseline.result,
    baseline.readiness,
    candidate.result,
    candidate.readiness,
    { pair_ref: "agent-gym-pair://nightly/one", paired_at: "2026-08-12T11:08:00.000Z" },
  );
  assert.equal(paired.case_count, 2);
  assert.notEqual(paired.baseline_candidate_ref, paired.candidate_ref);
  assert.deepEqual(validateAgentGymPairedEvaluation(paired), paired);
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

function evaluationSuite() {
  const setup = evaluationSetup();
  return suiteFrom(setup);
}

function suiteFrom(setup: ReturnType<typeof evaluationSetup>) {
  return defineAgentGymEvaluationSuite(
    setup.fixtures,
    setup.quality,
    setup.evaluatorAdmission,
    { partitions: ["held_out", "shadow"], suite_ref: "agent-gym-suite://nightly/default" },
  );
}

function caseEvaluations(
  setup: ReturnType<typeof evaluationSetup>,
  suite: ReturnType<typeof defineAgentGymEvaluationSuite>,
) {
  return suite.cases.map((entry, index) => recordAgentGymCaseEvaluation(
    setup.rubric,
    [setup.modelJudge, setup.deterministic],
    {
      candidate_ref: runPlanInput().candidate_ref,
      case_ref: entry.case_ref,
      evaluated_at: "2026-08-12T11:05:30.000Z",
      evaluation_ref: `agent-gym-evaluation://nightly/case-${index}`,
      invalid_reason_codes: [],
      metrics: [
        { evaluator_digest: setup.modelJudge.evaluator_digest, metric_id: "answer.grounded", reason_codes: [], score: 0.9 },
        { evaluator_digest: setup.deterministic.evaluator_digest, metric_id: "effect.authorized", reason_codes: [], score: 1 },
      ],
      replay_ref: `agent-gym-replay://nightly/case-${index}`,
      schema_version: "agent-gym-case-evaluation/v1",
      valid: true,
    },
  ));
}

function completedRun(
  setup: ReturnType<typeof evaluationSetup>,
  suite: ReturnType<typeof defineAgentGymEvaluationSuite>,
) {
  return completeAgentGymEvaluationRun(
    suite,
    planAgentGymEvaluationRun(suite, runPlanInput()),
    caseEvaluations(setup, suite),
    { completed_at: "2026-08-12T11:06:00.000Z", started_at: "2026-08-12T11:05:00.000Z" },
  );
}

function readinessPolicy() {
  return {
    minimum_case_count: 2,
    policy_ref: "agent-gym-evaluation-readiness-policy://default/v1",
    required_slices: [
      { minimum_valid_case_count: 1, slice_id: "partition:held_out" },
      { minimum_valid_case_count: 1, slice_id: "partition:shadow" },
    ],
    schema_version: "agent-gym-evaluation-readiness-policy/v1" as const,
  };
}

function completedRunFor(
  setup: ReturnType<typeof evaluationSetup>,
  suite: ReturnType<typeof defineAgentGymEvaluationSuite>,
  candidate: string,
  score: number,
) {
  const runInput = {
    ...runPlanInput(),
    candidate_ref: `agent-gym-candidate://slack/${candidate}`,
    run_ref: `agent-gym-evaluation-run://nightly/${candidate}`,
  };
  const plan = planAgentGymEvaluationRun(suite, runInput);
  const evaluations = suite.cases.map((entry, index) => recordAgentGymCaseEvaluation(
    setup.rubric,
    [setup.modelJudge, setup.deterministic],
    {
      candidate_ref: runInput.candidate_ref,
      case_ref: entry.case_ref,
      evaluated_at: "2026-08-12T11:05:30.000Z",
      evaluation_ref: `agent-gym-evaluation://nightly/${candidate}/case-${index}`,
      invalid_reason_codes: [],
      metrics: [
        { evaluator_digest: setup.modelJudge.evaluator_digest, metric_id: "answer.grounded", reason_codes: [], score },
        { evaluator_digest: setup.deterministic.evaluator_digest, metric_id: "effect.authorized", reason_codes: [], score: 1 },
      ],
      replay_ref: `agent-gym-replay://nightly/${candidate}/case-${index}`,
      schema_version: "agent-gym-case-evaluation/v1",
      valid: true,
    },
  ));
  const result = completeAgentGymEvaluationRun(
    suite,
    plan,
    evaluations,
    { completed_at: "2026-08-12T11:06:00.000Z", started_at: "2026-08-12T11:05:00.000Z" },
  );
  const report = summarizeAgentGymEvaluationSlices(suite, result);
  const readiness = decideAgentGymEvaluationReadiness(
    suite,
    result,
    report,
    readinessPolicy(),
    "2026-08-12T11:07:00.000Z",
  );
  return { readiness, report, result };
}

function runPlanInput() {
  return {
    candidate_ref: "agent-gym-candidate://slack/challenger",
    case_timeout_ms: 120_000,
    maximum_parallel_cases: 2,
    planned_at: "2026-08-12T11:04:00.000Z",
    run_ref: "agent-gym-evaluation-run://nightly/challenger",
  };
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
