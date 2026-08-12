import assert from "node:assert/strict";
import test from "node:test";

import {
  agentGymModelRequestDigest,
  AgentGymModelInvocationError,
  createAgentGymModelInvocationLedger,
  decideAgentGymModelRetry,
  invokeAgentGymModelWithRetry,
  evaluateAgentGymModelBudget,
  invokeAgentGymModel,
  RecordedAgentGymModel,
  runAgentGymModelBatch,
  validateAgentGymRecordedModelResponse,
  validateAgentGymModelFailure,
  validateAgentGymModelRequest,
} from "../src/index.js";

test("model batches replay requests in declared order", async () => {
  const first = request();
  const second = {
    ...request(),
    invocation_ref: "model-invocation://case-two/one",
    messages: [{ role: "user" as const, text: "Summarize the second case." }],
  };
  const model = new RecordedAgentGymModel([
    recordedResponse(first),
    recordedResponse(second),
  ]);
  const batch = await runAgentGymModelBatch(
    "model-batch://one",
    [first, second],
    modelBudget(),
    model,
    "2026-08-12T09:45:00.000Z",
  );
  assert.deepEqual(batch.results.map((result) => result.receipt.invocation_ref), [
    first.invocation_ref,
    second.invocation_ref,
  ]);
  assert.equal(batch.ledger.invocation_count, 2);
});

test("model batches reject duplicate invocation identities", async () => {
  await assert.rejects(runAgentGymModelBatch(
    "model-batch://one",
    [request(), request()],
    modelBudget(),
    new RecordedAgentGymModel([recordedResponse()]),
    "2026-08-12T09:45:00.000Z",
  ), /model batch is invalid/u);
});

test("model invocation ledgers aggregate replay cost and blockers", async () => {
  const modelRequest = request();
  const result = await invokeAgentGymModel(
    modelRequest,
    modelBudget(),
    new RecordedAgentGymModel([recordedResponse(modelRequest)]),
    "2026-08-12T09:45:00.000Z",
  );
  const ledger = createAgentGymModelInvocationLedger([result.receipt]);
  assert.equal(ledger.invocation_count, 1);
  assert.equal(ledger.recorded_invocation_count, 1);
  assert.equal(ledger.blocked_invocation_count, 0);
  assert.equal(ledger.total_tokens, 25);
});

test("model invocation ledgers reject duplicate invocation identities", async () => {
  const modelRequest = request();
  const result = await invokeAgentGymModel(
    modelRequest,
    modelBudget(),
    new RecordedAgentGymModel([recordedResponse(modelRequest)]),
    "2026-08-12T09:45:00.000Z",
  );
  assert.throws(() => createAgentGymModelInvocationLedger([
    result.receipt, result.receipt,
  ]), /invocation ledger is invalid/u);
});

test("model retry execution advances virtual time without sleeping", async () => {
  let invocationCount = 0;
  const result = await invokeAgentGymModelWithRetry(request(), retryPolicy(), {
    async invoke() {
      invocationCount += 1;
      if (invocationCount < 3) throw new AgentGymModelInvocationError(retryableFailure());
      return modelResponse();
    },
  });
  assert.equal(result.virtual_elapsed_ms, 350);
  assert.deepEqual(result.attempts.map((attempt) => attempt.outcome), [
    "failure", "failure", "success",
  ]);
});

test("model retry execution propagates terminal failures", async () => {
  const failure = { ...retryableFailure(), retryable: false };
  await assert.rejects(invokeAgentGymModelWithRetry(request(), retryPolicy(), {
    async invoke() { throw new AgentGymModelInvocationError(failure); },
  }), (error: unknown) => error instanceof AgentGymModelInvocationError
    && error.failure.error_code === "provider.throttled");
});

function retryPolicy() {
  return {
    backoff_ms: [100, 250],
    max_attempts: 3,
    max_elapsed_ms: 1_000,
    retryable_error_codes: ["provider.throttled"],
    schema_version: "agent-gym-model-retry-policy/v1" as const,
  };
}

function retryableFailure() {
  return {
    error_code: "provider.throttled",
    invocation_ref: "model-invocation://one",
    message: "The model provider throttled the request.",
    model_id: "recorded.model-v1",
    retryable: true,
    schema_version: "agent-gym-model-failure/v1" as const,
  };
}

test("model retry decisions use deterministic backoff", () => {
  assert.deepEqual(decideAgentGymModelRetry(retryPolicy(), retryableFailure(), 1, 20), {
    attempt: 1,
    delay_ms: 100,
    reason_code: "retry.scheduled",
    retry: true,
    schema_version: "agent-gym-model-retry-decision/v1",
  });
});

test("model retry decisions stop at the attempt boundary", () => {
  const decision = decideAgentGymModelRetry(retryPolicy(), retryableFailure(), 3, 500);
  assert.equal(decision.retry, false);
  assert.equal(decision.reason_code, "retry.attempts_exhausted");
});

test("model failures retain retry and provider correlation", () => {
  const failure = validateAgentGymModelFailure({
    error_code: "provider.throttled",
    invocation_ref: "model-invocation://one",
    message: "The model provider throttled the request.",
    model_id: "recorded.model-v1",
    provider_request_ref: "provider-request://one",
    retry_after_ms: 250,
    retryable: true,
    schema_version: "agent-gym-model-failure/v1",
  });
  const error = new AgentGymModelInvocationError(failure);
  assert.equal(error.failure.retry_after_ms, 250);
  assert.equal(error.name, "AgentGymModelInvocationError");
});

test("model failures reject retry delay on terminal errors", () => {
  assert.throws(() => validateAgentGymModelFailure({
    error_code: "request.invalid",
    invocation_ref: "model-invocation://one",
    message: "The request is invalid.",
    model_id: "recorded.model-v1",
    retry_after_ms: 250,
    retryable: false,
    schema_version: "agent-gym-model-failure/v1",
  }), /model failure is invalid/u);
});

test("model invocation receipts bind request, response, and budget", async () => {
  const modelRequest = request();
  const model = new RecordedAgentGymModel([recordedResponse(modelRequest)]);
  const result = await invokeAgentGymModel(
    modelRequest,
    modelBudget(),
    model,
    "2026-08-12T09:30:00.000Z",
  );
  assert.equal(result.receipt.budget.allowed, true);
  assert.equal(result.receipt.request_digest, agentGymModelRequestDigest(modelRequest));
  assert.match(result.receipt.response_digest, /^sha256:[0-9a-f]{64}$/u);
  assert.equal(result.receipt.response_source, "recorded");
});

test("model invocation receipts reject a response for another request", async () => {
  const modelRequest = request();
  await assert.rejects(invokeAgentGymModel(
    modelRequest,
    modelBudget(),
    {
      async invoke() {
        return {
          ...modelResponse(),
          invocation_ref: "model-invocation://other",
        };
      },
    },
    "2026-08-12T09:30:00.000Z",
  ), /model invocation binding is invalid/u);
});

function modelResponse() {
  return {
    ...recordedResponse(),
    response_source: "recorded" as const,
    schema_version: "agent-gym-model-response/v1" as const,
  };
}

function modelBudget() {
  return {
    max_input_tokens: 20,
    max_invocations: 1,
    max_latency_ms: 100,
    max_output_tokens: 10,
    max_total_tokens: 30,
    schema_version: "agent-gym-model-budget/v1" as const,
  };
}

test("model budget evaluation accounts for the complete response", () => {
  const evaluation = evaluateAgentGymModelBudget(modelBudget(), [modelResponse()]);
  assert.equal(evaluation.allowed, true);
  assert.deepEqual(evaluation, {
    allowed: true,
    blockers: [],
    input_tokens: 18,
    invocation_count: 1,
    latency_ms: 42,
    output_tokens: 7,
    schema_version: "agent-gym-model-budget-evaluation/v1",
    total_tokens: 25,
  });
});

test("model budget evaluation names every exceeded limit", () => {
  const evaluation = evaluateAgentGymModelBudget({
    ...modelBudget(),
    max_input_tokens: 17,
    max_latency_ms: 41,
    max_output_tokens: 6,
    max_total_tokens: 24,
  }, [modelResponse()]);
  assert.equal(evaluation.allowed, false);
  assert.deepEqual(evaluation.blockers, [
    "model_input_tokens_exceeded",
    "model_output_tokens_exceeded",
    "model_total_tokens_exceeded",
    "model_latency_exceeded",
  ]);
});

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
