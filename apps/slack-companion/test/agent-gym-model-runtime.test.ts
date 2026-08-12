import assert from "node:assert/strict";
import test from "node:test";

import {
  agentGymModelRequestDigest,
  RecordedAgentGymModel,
  validateAgentGymRecordedModelResponse,
  validateAgentGymModelRequest,
} from "../src/index.js";

function recordedResponse(modelRequest = request()) {
  return {
    invocation_ref: modelRequest.invocation_ref,
    latency_ms: 42,
    model_id: modelRequest.model_id,
    output_text: "The current evidence is incomplete.",
    request_digest: agentGymModelRequestDigest(modelRequest),
    schema_version: "agent-gym-recorded-model-response/v1" as const,
    stop_reason: "end_turn" as const,
    token_usage: { input_tokens: 18, output_tokens: 7, total_tokens: 25 },
  };
}

test("recorded model ports replay the exact bound response", async () => {
  const modelRequest = request();
  const model = new RecordedAgentGymModel([recordedResponse(modelRequest)]);
  const response = await model.invoke(modelRequest);
  assert.equal(response.response_source, "recorded");
  assert.equal(response.output_text, "The current evidence is incomplete.");
});

test("recorded model ports reject unrecorded requests", async () => {
  const model = new RecordedAgentGymModel([recordedResponse()]);
  await assert.rejects(model.invoke({
    ...request(),
    messages: [{ role: "user", text: "Summarize different evidence." }],
  }), /recorded model fixture is missing/u);
});

test("recorded model responses retain usage and request identity", () => {
  const modelRequest = request();
  const response = validateAgentGymRecordedModelResponse({
    invocation_ref: modelRequest.invocation_ref,
    latency_ms: 42,
    model_id: modelRequest.model_id,
    output_text: "The current evidence is incomplete.",
    provider_request_ref: "provider-request://recorded/one",
    request_digest: agentGymModelRequestDigest(modelRequest),
    schema_version: "agent-gym-recorded-model-response/v1",
    stop_reason: "end_turn",
    token_usage: { input_tokens: 18, output_tokens: 7, total_tokens: 25 },
  });
  assert.equal(Object.isFrozen(response.token_usage), true);
  assert.equal(response.token_usage.total_tokens, 25);
});

test("recorded model responses reject inconsistent token totals", () => {
  const modelRequest = request();
  assert.throws(() => validateAgentGymRecordedModelResponse({
    invocation_ref: modelRequest.invocation_ref,
    latency_ms: 42,
    model_id: modelRequest.model_id,
    output_text: "The current evidence is incomplete.",
    request_digest: agentGymModelRequestDigest(modelRequest),
    schema_version: "agent-gym-recorded-model-response/v1",
    stop_reason: "end_turn",
    token_usage: { input_tokens: 18, output_tokens: 7, total_tokens: 24 },
  }), /recorded model response is invalid/u);
});

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
