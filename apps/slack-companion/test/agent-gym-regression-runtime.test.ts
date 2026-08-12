import assert from "node:assert/strict";
import test from "node:test";
import { bindAgentGymRegressionReplayRequests, validateAgentGymRegressionReplayRequestPair } from "../src/agent-gym/regression-replay-request-pair.js";
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
