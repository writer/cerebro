import assert from "node:assert/strict";
import test from "node:test";

import {
  agentGymModelRequestDigest,
  validateAgentGymModelRequest,
} from "../src/index.js";

function request() {
  return {
    candidate_ref: "candidate://baseline",
    invocation_ref: "model-invocation://case-one/one",
    max_output_tokens: 512,
    messages: [{ role: "user" as const, text: "Summarize the current evidence." }],
    model_id: "recorded.model-v1",
    schema_version: "agent-gym-model-request/v1" as const,
    system_prompt: "Use only supplied evidence.",
  };
}

test("model requests freeze a provider-neutral conversation", () => {
  const validated = validateAgentGymModelRequest(request());
  assert.equal(Object.isFrozen(validated), true);
  assert.equal(Object.isFrozen(validated.messages), true);
  assert.match(agentGymModelRequestDigest(validated), /^sha256:[0-9a-f]{64}$/u);
});

test("model requests must end with a user turn", () => {
  assert.throws(() => validateAgentGymModelRequest({
    ...request(),
    messages: [
      { role: "user", text: "Summarize the current evidence." },
      { role: "assistant", text: "The evidence is incomplete." },
    ],
  }), /model request is invalid/u);
});
