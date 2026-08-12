import assert from "node:assert/strict";
import test from "node:test";
import { digestAgentGymJson } from "../src/agent-gym/canonical-json.js";
import { compareAgentGymRegressionReplay } from "../src/agent-gym/regression-replay-comparison.js";
import { evaluateAgentGymRegressionReplay } from "../src/agent-gym/regression-replay-evaluation.js";
import { sealAgentGymRegressionReplayTrial, validateAgentGymRegressionReplayTrial } from "../src/agent-gym/regression-replay-trial.js";

const sha = (value: string): string => `sha256:${value.repeat(64).slice(0, 64)}`;

function trialChain() {
  const planBody = {
    baseline_invocation_ref: "agent-gym-invocation://baseline/campaign-one",
    case_digest: sha("a"), case_ref: "agent-gym-case://campaign/one",
    challenger_invocation_ref: "agent-gym-invocation://challenger/campaign-one",
    maximum_model_calls: 2, plan_ref: "agent-gym-replay-plan://campaign/one",
    planned_at: "2026-08-12T15:00:00.000Z", replay_request_digest: sha("b"),
    schema_version: "agent-gym-regression-replay-plan/v1" as const,
  };
  const plan = { ...planBody, plan_digest: digestAgentGymJson(planBody) };
  const candidate = (role: "baseline" | "challenger") => ({
    candidate_ref: `agent-gym-candidate://${role}/campaign`, invocation_receipt_digest: sha(role === "baseline" ? "c" : "d"),
    invocation_ref: `agent-gym-invocation://${role}/campaign-one`, latency_ms: role === "baseline" ? 20 : 15,
    response_digest: sha(role === "baseline" ? "e" : "f"), total_tokens: role === "baseline" ? 30 : 25,
  });
  const resultBody = { baseline: candidate("baseline"), case_digest: plan.case_digest, case_ref: plan.case_ref,
    challenger: candidate("challenger"), completed_at: "2026-08-12T15:01:00.000Z", plan_digest: plan.plan_digest,
    result_ref: "agent-gym-replay-result://campaign/one", schema_version: "agent-gym-regression-replay-result/v1" as const };
  const result = { ...resultBody, result_digest: digestAgentGymJson(resultBody) };
  const bindingBody = { baseline_candidate_ref: result.baseline.candidate_ref,
    binding_ref: "agent-gym-evaluator-binding://campaign/one", bound_at: "2026-08-12T15:02:00.000Z",
    challenger_candidate_ref: result.challenger.candidate_ref, evaluator_admission_digest: sha("1"),
    evaluator_digests: [sha("2")], replay_result_digest: result.result_digest, rubric_digest: sha("3"),
    schema_version: "agent-gym-regression-replay-evaluator-binding/v1" as const };
  const binding = { ...bindingBody, binding_digest: digestAgentGymJson(bindingBody) };
  const evaluation = evaluateAgentGymRegressionReplay(result, {
    baseline: { blocker_codes: [], candidate_ref: result.baseline.candidate_ref,
      evidence_digest: sha("4"), safety_passed: true, score: 0.7 },
    challenger: { blocker_codes: [], candidate_ref: result.challenger.candidate_ref,
      evidence_digest: sha("5"), safety_passed: true, score: 0.9 },
    evaluated_at: "2026-08-12T15:03:00.000Z", evaluation_ref: "agent-gym-replay-evaluation://campaign/one",
  });
  const comparison = compareAgentGymRegressionReplay(result, evaluation, {
    compared_at: "2026-08-12T15:04:00.000Z", comparison_ref: "agent-gym-replay-comparison://campaign/one",
  });
  return { binding, comparison, evaluation, plan, result };
}

test("seals one complete runtime chain without model output text", () => {
  const chain = trialChain();
  const trial = sealAgentGymRegressionReplayTrial(chain.plan, chain.result, chain.binding,
    chain.evaluation, chain.comparison, { completed_at: "2026-08-12T15:05:00.000Z",
      trial_ref: "agent-gym-regression-trial://campaign/one" });
  assert.equal(validateAgentGymRegressionReplayTrial(trial).outcome, "improved");
  assert.equal(trial.evaluator_binding_digest, chain.binding.binding_digest);
  assert.equal(JSON.stringify(trial).includes("output_text"), false);
});

test("rejects a runtime chain whose evaluator binding targets another result", () => {
  const chain = trialChain();
  assert.throws(() => sealAgentGymRegressionReplayTrial(chain.plan, chain.result,
    { ...chain.binding, replay_result_digest: sha("9") }, chain.evaluation, chain.comparison,
    { completed_at: "2026-08-12T15:05:00.000Z", trial_ref: "agent-gym-regression-trial://campaign/invalid" }));
});
