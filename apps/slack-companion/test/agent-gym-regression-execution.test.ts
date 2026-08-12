import assert from "node:assert/strict";
import test from "node:test";
import { digestAgentGymJson } from "../src/agent-gym/canonical-json.js";
import { planAgentGymRegressionReplay, validateAgentGymRegressionReplayPlan } from "../src/agent-gym/regression-replay-plan.js";
import type { AgentGymRegressionReplayRequestV1 } from "../src/agent-gym/regression-replay-request.js";

const sha = (value: string): string => `sha256:${value.repeat(64).slice(0, 64)}`;

function request(): AgentGymRegressionReplayRequestV1 {
  const body = {
    augmentation_digest: sha("a"), baseline_candidate_ref: "agent-gym-candidate://baseline/one",
    case_digest: sha("b"), case_ref: "agent-gym-case://regression/one",
    challenger_candidate_ref: "agent-gym-candidate://challenger/one", fixture_receipt_digest: sha("c"),
    maximum_model_calls: 2, planned_at: "2026-08-12T13:00:00.000Z",
    request_ref: "agent-gym-replay-request://regression/one",
    schema_version: "agent-gym-regression-replay-request/v1" as const,
  };
  return { ...body, request_digest: digestAgentGymJson(body) };
}

test("seals an exact paired regression replay plan", () => {
  const plan = planAgentGymRegressionReplay(request(), {
    baseline_invocation_ref: "agent-gym-invocation://baseline/one",
    challenger_invocation_ref: "agent-gym-invocation://challenger/one",
    plan_ref: "agent-gym-replay-plan://regression/one", planned_at: "2026-08-12T13:01:00.000Z",
  });
  assert.equal(validateAgentGymRegressionReplayPlan(plan).replay_request_digest, request().request_digest);
  assert.throws(() => validateAgentGymRegressionReplayPlan({ ...plan, maximum_model_calls: 3 }));
});
