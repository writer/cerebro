import assert from "node:assert/strict";
import test from "node:test";
import { defineAgentGymEvaluatorRubric } from "../src/agent-gym/evaluator-rubric.js";
import { defineAgentGymEvaluatorManifest } from "../src/agent-gym/evaluator-manifest.js";
import { decideAgentGymEvaluatorAdmission } from "../src/agent-gym/evaluator-admission.js";
import { bindAgentGymRegressionReplayEvaluators, validateAgentGymRegressionReplayEvaluatorBinding } from "../src/agent-gym/regression-replay-evaluator-binding.js";
import { validateAgentGymRegressionReplayEvaluatorInput, validateAgentGymRegressionReplayEvaluatorOutput } from "../src/agent-gym/regression-replay-evaluator-port.js";
import { buildAgentGymRegressionReplayEvaluatorInputs } from "../src/agent-gym/regression-replay-evaluator-inputs.js";
import { executeAgentGymRegressionReplayEvaluators } from "../src/agent-gym/regression-replay-evaluator-execution.js";
import { recordExecutedAgentGymRegressionReplayEvaluation } from "../src/agent-gym/regression-replay-runtime-evaluation.js";
import { bindAgentGymRegressionReplayRequests } from "../src/agent-gym/regression-replay-request-pair.js";
import { checkAgentGymRegressionReplayParity } from "../src/agent-gym/regression-replay-parity.js";
import { executeAgentGymRegressionReplay } from "../src/agent-gym/regression-replay-execution.js";
import { recordExecutedAgentGymRegressionReplay } from "../src/agent-gym/regression-replay-runtime-result.js";
import { agentGymModelRequestDigest } from "../src/agent-gym/model-runtime.js";
import { recordAgentGymRegressionReplayResult } from "../src/agent-gym/regression-replay-result.js";
import { digestAgentGymJson } from "../src/agent-gym/canonical-json.js";

const sha = (value: string): string => `sha256:${value.repeat(64).slice(0, 64)}`;
const rubric = defineAgentGymEvaluatorRubric({ metrics: [{ blocking: true, evaluator_kind: "deterministic", metric_id: "safety", minimum_score: 1, weight: 1 }], rubric_ref: "agent-gym-rubric://regression/runtime", schema_version: "agent-gym-evaluator-rubric/v1" });
const evaluator = defineAgentGymEvaluatorManifest({ evaluator_kind: "deterministic", evaluator_ref: "agent-gym-evaluator://regression/safety", implementation_digest: sha("a"), output_schema_digest: sha("b"), rubric_digest: rubric.rubric_digest, schema_version: "agent-gym-evaluator-manifest/v1" });
const admission = decideAgentGymEvaluatorAdmission(rubric, [evaluator], [], { maximum_calibration_age_ms: 86_400_000, policy_ref: "agent-gym-evaluator-policy://regression/one", required_calibration_dataset_digest: sha("c"), required_calibration_policy_digest: sha("d"), schema_version: "agent-gym-evaluator-admission-policy/v1" }, "2026-08-12T14:00:00.000Z");

function replayPlan() {
  const planBody = { baseline_invocation_ref: "agent-gym-invocation://baseline/one", case_digest: sha("e"), case_ref: "agent-gym-case://regression/one", challenger_invocation_ref: "agent-gym-invocation://challenger/one", maximum_model_calls: 2, plan_ref: "agent-gym-replay-plan://regression/one", planned_at: "2026-08-12T13:00:00.000Z", replay_request_digest: sha("f"), schema_version: "agent-gym-regression-replay-plan/v1" as const };
  return { ...planBody, plan_digest: digestAgentGymJson(planBody) };
}

function result() {
  const plan = replayPlan();
  return recordAgentGymRegressionReplayResult(plan, { baseline: { candidate_ref: "agent-gym-candidate://baseline/one", invocation_receipt_digest: sha("1"), invocation_ref: plan.baseline_invocation_ref, latency_ms: 10, response_digest: sha("2"), total_tokens: 20 }, challenger: { candidate_ref: "agent-gym-candidate://challenger/one", invocation_receipt_digest: sha("3"), invocation_ref: plan.challenger_invocation_ref, latency_ms: 9, response_digest: sha("4"), total_tokens: 18 }, completed_at: "2026-08-12T13:30:00.000Z", result_ref: "agent-gym-replay-result://regression/one" });
}

function binding() {
  return bindAgentGymRegressionReplayEvaluators(result(), rubric, [evaluator], admission, { binding_ref: "agent-gym-evaluator-binding://regression/one", bound_at: "2026-08-12T14:01:00.000Z" });
}

async function runtimeBundle() {
  const plan = replayPlan();
  const request = (role: "baseline" | "challenger") => ({ candidate_ref: `agent-gym-candidate://${role}/one`,
    invocation_ref: `agent-gym-invocation://${role}/one`, max_output_tokens: 256,
    messages: [{ role: "user" as const, text: "Summarize the regression evidence." }], model_id: `model-${role}`,
    schema_version: "agent-gym-model-request/v1" as const, system_prompt: `You are the ${role} candidate.` });
  const baseline = request("baseline"); const challenger = request("challenger");
  const pair = bindAgentGymRegressionReplayRequests(plan, baseline, challenger, "agent-gym-request-pair://regression/evaluator");
  const parity = checkAgentGymRegressionReplayParity(pair, { checked_at: "2026-08-12T13:01:00.000Z", report_ref: "agent-gym-parity://regression/evaluator" });
  const execution = await executeAgentGymRegressionReplay(plan, pair, parity, baseline, challenger,
    { max_input_tokens: 1_000, max_invocations: 2, max_latency_ms: 1_000, max_output_tokens: 1_000,
      max_total_tokens: 2_000, schema_version: "agent-gym-model-budget/v1" }, { async invoke(modelRequest) {
      return { invocation_ref: modelRequest.invocation_ref, latency_ms: 10, model_id: modelRequest.model_id,
        output_text: `answer:${modelRequest.candidate_ref}`, request_digest: agentGymModelRequestDigest(modelRequest),
        response_source: "recorded" as const, schema_version: "agent-gym-model-response/v1" as const,
        stop_reason: "end_turn" as const, token_usage: { input_tokens: 10, output_tokens: 5, total_tokens: 15 } };
    } }, "2026-08-12T13:02:00.000Z", "agent-gym-model-batch://regression/evaluator");
  const replayResult = recordExecutedAgentGymRegressionReplay(plan, execution, { completed_at: "2026-08-12T13:03:00.000Z", result_ref: "agent-gym-replay-result://regression/evaluator" });
  const evaluatorBinding = bindAgentGymRegressionReplayEvaluators(replayResult, rubric, [evaluator], admission, { binding_ref: "agent-gym-evaluator-binding://regression/runtime", bound_at: "2026-08-12T14:01:00.000Z" });
  return { evaluatorBinding, execution, replayResult };
}

test("binds replay scoring to admitted exact evaluator evidence", () => {
  assert.equal(validateAgentGymRegressionReplayEvaluatorBinding(binding()).evaluator_admission_digest, admission.decision_digest);
});

test("validates bounded evaluator inputs and fail-closed outputs", () => {
  const bound = binding();
  const input = validateAgentGymRegressionReplayEvaluatorInput({ binding_digest: bound.binding_digest,
    candidate_ref: bound.baseline_candidate_ref, case_ref: "agent-gym-case://regression/one",
    evaluator_digests: bound.evaluator_digests, output_text: "A bounded candidate answer.", response_digest: sha("2"),
    rubric_digest: bound.rubric_digest, schema_version: "agent-gym-regression-replay-evaluator-input/v1" });
  assert.equal(input.output_text, "A bounded candidate answer.");
  assert.equal(validateAgentGymRegressionReplayEvaluatorOutput({ binding_digest: bound.binding_digest, blocker_codes: [],
    candidate_ref: bound.baseline_candidate_ref, evidence_digest: sha("5"), safety_passed: true,
    schema_version: "agent-gym-regression-replay-evaluator-output/v1", score: 0.8 }).score, 0.8);
  assert.throws(() => validateAgentGymRegressionReplayEvaluatorOutput({ binding_digest: bound.binding_digest,
    blocker_codes: ["unsafe"], candidate_ref: bound.baseline_candidate_ref, evidence_digest: sha("5"), safety_passed: true,
    schema_version: "agent-gym-regression-replay-evaluator-output/v1", score: 0.8 }));
});

test("projects exact transient model answers into paired evaluator inputs", async () => {
  const { evaluatorBinding, execution, replayResult } = await runtimeBundle();
  const inputs = buildAgentGymRegressionReplayEvaluatorInputs(evaluatorBinding, replayResult, execution);
  assert.deepEqual(inputs.map((input) => input.candidate_ref), [replayResult.baseline.candidate_ref, replayResult.challenger.candidate_ref]);
  assert.equal(inputs[0].output_text, `answer:${replayResult.baseline.candidate_ref}`);
});

test("executes baseline and challenger through one evaluator port", async () => {
  const { evaluatorBinding, execution, replayResult } = await runtimeBundle();
  const inputs = buildAgentGymRegressionReplayEvaluatorInputs(evaluatorBinding, replayResult, execution);
  const seen: string[] = [];
  const evaluated = await executeAgentGymRegressionReplayEvaluators(inputs, { async evaluate(input) {
    seen.push(input.candidate_ref);
    return { binding_digest: input.binding_digest, blocker_codes: [], candidate_ref: input.candidate_ref,
      evidence_digest: input.candidate_ref === replayResult.baseline.candidate_ref ? sha("6") : sha("7"),
      safety_passed: true, schema_version: "agent-gym-regression-replay-evaluator-output/v1", score: 0.9 };
  } });
  assert.deepEqual(seen, [replayResult.baseline.candidate_ref, replayResult.challenger.candidate_ref]);
  assert.deepEqual(evaluated.outputs.map((output) => output.score), [0.9, 0.9]);
});

test("rejects evaluator output bound to another candidate", async () => {
  const { evaluatorBinding, execution, replayResult } = await runtimeBundle();
  const inputs = buildAgentGymRegressionReplayEvaluatorInputs(evaluatorBinding, replayResult, execution);
  await assert.rejects(executeAgentGymRegressionReplayEvaluators(inputs, { async evaluate(input) {
    return { binding_digest: input.binding_digest, blocker_codes: [], candidate_ref: replayResult.baseline.candidate_ref,
      evidence_digest: sha("8"), safety_passed: true,
      schema_version: "agent-gym-regression-replay-evaluator-output/v1", score: 0.8 };
  } }), /evaluator execution is invalid/u);
});

test("records validated evaluator execution as durable paired evidence", async () => {
  const { evaluatorBinding, execution, replayResult } = await runtimeBundle();
  const inputs = buildAgentGymRegressionReplayEvaluatorInputs(evaluatorBinding, replayResult, execution);
  const evaluated = await executeAgentGymRegressionReplayEvaluators(inputs, { async evaluate(input) {
    const baseline = input.candidate_ref === replayResult.baseline.candidate_ref;
    return { binding_digest: input.binding_digest, blocker_codes: baseline ? ["safety_regression"] : [],
      candidate_ref: input.candidate_ref, evidence_digest: baseline ? sha("9") : sha("a"), safety_passed: !baseline,
      schema_version: "agent-gym-regression-replay-evaluator-output/v1", score: baseline ? 0.4 : 0.95 };
  } });
  const durable = recordExecutedAgentGymRegressionReplayEvaluation(replayResult, evaluatorBinding, evaluated, {
    evaluated_at: "2026-08-12T14:02:00.000Z", evaluation_ref: "agent-gym-replay-evaluation://regression/runtime",
  });
  assert.equal(durable.baseline.safety_passed, false);
  assert.equal(durable.challenger.score, 0.95);
  assert.equal(JSON.stringify(durable).includes("answer:"), false);
});

test("rejects evaluator execution for another binding", async () => {
  const { evaluatorBinding, execution, replayResult } = await runtimeBundle();
  const inputs = buildAgentGymRegressionReplayEvaluatorInputs(evaluatorBinding, replayResult, execution);
  const evaluated = await executeAgentGymRegressionReplayEvaluators(inputs, { async evaluate(input) {
    return { binding_digest: input.binding_digest, blocker_codes: [], candidate_ref: input.candidate_ref,
      evidence_digest: sha("b"), safety_passed: true,
      schema_version: "agent-gym-regression-replay-evaluator-output/v1", score: 0.8 };
  } });
  assert.throws(() => recordExecutedAgentGymRegressionReplayEvaluation(replayResult, evaluatorBinding,
    { ...evaluated, binding_digest: sha("c") }, { evaluated_at: "2026-08-12T14:02:00.000Z",
      evaluation_ref: "agent-gym-replay-evaluation://regression/invalid" }));
});

test("rejects evaluator evidence that was not admitted", () => {
  assert.throws(() => bindAgentGymRegressionReplayEvaluators(result(), rubric, [evaluator], { ...admission, admitted: false }, { binding_ref: "agent-gym-evaluator-binding://regression/invalid", bound_at: "2026-08-12T14:01:00.000Z" }));
});
