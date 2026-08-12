import assert from "node:assert/strict";
import test from "node:test";
import { bindAgentGymRegressionReplayRequests, validateAgentGymRegressionReplayRequestPair } from "../src/agent-gym/regression-replay-request-pair.js";
import { checkAgentGymRegressionReplayParity, validateAgentGymRegressionReplayParity } from "../src/agent-gym/regression-replay-parity.js";
import { executeAgentGymRegressionReplay } from "../src/agent-gym/regression-replay-execution.js";
import { agentGymModelRequestDigest } from "../src/agent-gym/model-runtime.js";
import type { AgentGymRegressionReplayPlanV1 } from "../src/agent-gym/regression-replay-plan.js";
import { digestAgentGymJson } from "../src/agent-gym/canonical-json.js";

const sha = (value: string): string => `sha256:${value.repeat(64).slice(0, 64)}`;

function plan(): AgentGymRegressionReplayPlanV1 {
  const body = {
    baseline_invocation_ref: "agent-gym-invocation://baseline/one", case_digest: sha("a"),
    case_ref: "agent-gym-case://regression/one", challenger_invocation_ref: "agent-gym-invocation://challenger/one",
    maximum_model_calls: 2, plan_ref: "agent-gym-replay-plan://regression/one",
    planned_at: "2026-08-12T13:01:00.000Z", replay_request_digest: sha("b"),
    schema_version: "agent-gym-regression-replay-plan/v1" as const,
  };
  return { ...body, plan_digest: digestAgentGymJson(body) };
}

function request(role: "baseline" | "challenger") {
  return {
    candidate_ref: `agent-gym-candidate://${role}/one`, invocation_ref: `agent-gym-invocation://${role}/one`,
    max_output_tokens: 256, messages: [{ role: "user" as const, text: "Summarize the regression evidence." }],
    model_id: role === "baseline" ? "model-baseline" : "model-challenger",
    schema_version: "agent-gym-model-request/v1" as const, system_prompt: `You are the ${role} candidate.`,
  };
}

function pairAndParity() {
  const baseline = request("baseline"); const challenger = request("challenger");
  const pair = bindAgentGymRegressionReplayRequests(plan(), baseline, challenger, "agent-gym-request-pair://regression/one");
  const parity = checkAgentGymRegressionReplayParity(pair, { checked_at: "2026-08-12T13:02:00.000Z", report_ref: "agent-gym-parity://regression/one" });
  return { baseline, challenger, pair, parity };
}

const budget = {
  max_input_tokens: 1_000, max_invocations: 2, max_latency_ms: 1_000, max_output_tokens: 1_000,
  max_total_tokens: 2_000, schema_version: "agent-gym-model-budget/v1" as const,
};

test("binds the exact two requests authorized by a replay plan", () => {
  const pair = bindAgentGymRegressionReplayRequests(plan(), request("baseline"), request("challenger"), "agent-gym-request-pair://regression/one");
  assert.equal(validateAgentGymRegressionReplayRequestPair(pair).plan_digest, plan().plan_digest);
  assert.notEqual(pair.baseline_request_digest, pair.challenger_request_digest);
});

test("rejects a request outside the replay plan", () => {
  assert.throws(() => bindAgentGymRegressionReplayRequests(plan(),
    { ...request("baseline"), invocation_ref: "agent-gym-invocation://baseline/other" }, request("challenger"),
    "agent-gym-request-pair://regression/invalid"));
});

test("requires both candidates to receive the same case and output allowance", () => {
  const pair = bindAgentGymRegressionReplayRequests(plan(), request("baseline"), request("challenger"), "agent-gym-request-pair://regression/one");
  const parity = checkAgentGymRegressionReplayParity(pair, { checked_at: "2026-08-12T13:02:00.000Z", report_ref: "agent-gym-parity://regression/one" });
  assert.equal(validateAgentGymRegressionReplayParity(parity).passed, true);
  const changed = bindAgentGymRegressionReplayRequests(plan(), request("baseline"), {
    ...request("challenger"), max_output_tokens: 512,
    messages: [{ role: "user" as const, text: "Use different evidence." }],
  }, "agent-gym-request-pair://regression/changed");
  assert.deepEqual(checkAgentGymRegressionReplayParity(changed, {
    checked_at: "2026-08-12T13:02:00.000Z", report_ref: "agent-gym-parity://regression/changed",
  }).blocker_codes, ["case_messages_differ", "max_output_tokens_differ"]);
});

test("executes the exact pair through one provider-neutral model port", async () => {
  const { baseline, challenger, pair, parity } = pairAndParity();
  const seen: string[] = [];
  const execution = await executeAgentGymRegressionReplay(plan(), pair, parity, baseline, challenger, budget, {
    async invoke(modelRequest) {
      seen.push(modelRequest.invocation_ref);
      return { invocation_ref: modelRequest.invocation_ref, latency_ms: 10, model_id: modelRequest.model_id,
        output_text: `answer:${modelRequest.candidate_ref}`, request_digest: agentGymModelRequestDigest(modelRequest),
        response_source: "recorded", schema_version: "agent-gym-model-response/v1", stop_reason: "end_turn",
        token_usage: { input_tokens: 10, output_tokens: 5, total_tokens: 15 } };
    },
  }, "2026-08-12T13:03:00.000Z", "agent-gym-model-batch://regression/one");
  assert.deepEqual(seen, [baseline.invocation_ref, challenger.invocation_ref]);
  assert.equal(execution.batch.ledger.invocation_count, 2);
  assert.equal(execution.aggregate_budget.allowed, true);
});

test("retains aggregate budget failure across otherwise allowed calls", async () => {
  const { baseline, challenger, pair, parity } = pairAndParity();
  const execution = await executeAgentGymRegressionReplay(plan(), pair, parity, baseline, challenger,
    { ...budget, max_total_tokens: 20 }, {
      async invoke(modelRequest) {
        return { invocation_ref: modelRequest.invocation_ref, latency_ms: 10, model_id: modelRequest.model_id,
          output_text: "bounded answer", request_digest: agentGymModelRequestDigest(modelRequest), response_source: "recorded",
          schema_version: "agent-gym-model-response/v1", stop_reason: "end_turn",
          token_usage: { input_tokens: 10, output_tokens: 5, total_tokens: 15 } };
      },
    }, "2026-08-12T13:03:00.000Z", "agent-gym-model-batch://regression/budget");
  assert.equal(execution.aggregate_budget.allowed, false);
  assert.deepEqual(execution.aggregate_budget.blockers, ["model_total_tokens_exceeded"]);
});
