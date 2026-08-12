import { createHash } from "node:crypto";
import { AgentGymContractError } from "./index.js";

export interface AgentGymModelTextMessageV1 {
  readonly role: "assistant" | "user";
  readonly text: string;
}

export interface AgentGymModelInvocationRequestV1 {
  readonly candidate_ref: string;
  readonly invocation_ref: string;
  readonly max_output_tokens: number;
  readonly messages: readonly AgentGymModelTextMessageV1[];
  readonly model_id: string;
  readonly schema_version: "agent-gym-model-request/v1";
  readonly system_prompt: string;
}

interface AgentGymModelResponseFields {
  readonly invocation_ref: string;
  readonly latency_ms: number;
  readonly model_id: string;
  readonly output_text: string;
  readonly provider_request_ref?: string;
  readonly request_digest: `sha256:${string}`;
  readonly stop_reason: "content_filtered" | "end_turn" | "max_tokens";
  readonly token_usage: {
    readonly input_tokens: number;
    readonly output_tokens: number;
    readonly total_tokens: number;
  };
}

export interface AgentGymRecordedModelResponseV1 extends AgentGymModelResponseFields {
  readonly schema_version: "agent-gym-recorded-model-response/v1";
}

export interface AgentGymModelResponseV1 extends AgentGymModelResponseFields {
  readonly response_source: "live" | "recorded";
  readonly schema_version: "agent-gym-model-response/v1";
}

export interface AgentGymModelPort {
  invoke(request: AgentGymModelInvocationRequestV1): Promise<AgentGymModelResponseV1>;
}

/** Validates recorded provider output without trusting it as a live receipt. */
export function validateAgentGymRecordedModelResponse(
  response: AgentGymRecordedModelResponseV1,
): AgentGymRecordedModelResponseV1 {
  if (response.schema_version !== "agent-gym-recorded-model-response/v1") {
    invalidResponse();
  }
  validateResponseFields(response, invalidResponse);
  const { input_tokens: inputTokens, output_tokens: outputTokens,
    total_tokens: totalTokens } = response.token_usage;
  return Object.freeze({
    invocation_ref: response.invocation_ref,
    latency_ms: response.latency_ms,
    model_id: response.model_id,
    output_text: response.output_text,
    ...(response.provider_request_ref === undefined
      ? {}
      : { provider_request_ref: response.provider_request_ref }),
    request_digest: response.request_digest,
    schema_version: "agent-gym-recorded-model-response/v1",
    stop_reason: response.stop_reason,
    token_usage: Object.freeze({
      input_tokens: inputTokens,
      output_tokens: outputTokens,
      total_tokens: totalTokens,
    }),
  });
}

/** Validates the common response returned by recorded and live model ports. */
export function validateAgentGymModelResponse(
  response: AgentGymModelResponseV1,
): AgentGymModelResponseV1 {
  if (response.schema_version !== "agent-gym-model-response/v1"
    || (response.response_source !== "live" && response.response_source !== "recorded")) {
    invalidModelResponse();
  }
  validateResponseFields(response, invalidModelResponse);
  return Object.freeze({
    invocation_ref: response.invocation_ref,
    latency_ms: response.latency_ms,
    model_id: response.model_id,
    output_text: response.output_text,
    ...(response.provider_request_ref === undefined
      ? {}
      : { provider_request_ref: response.provider_request_ref }),
    request_digest: response.request_digest,
    response_source: response.response_source,
    schema_version: "agent-gym-model-response/v1",
    stop_reason: response.stop_reason,
    token_usage: Object.freeze({ ...response.token_usage }),
  });
}

/** Validates and freezes one provider-neutral text-model invocation. */
export function validateAgentGymModelRequest(
  request: AgentGymModelInvocationRequestV1,
): AgentGymModelInvocationRequestV1 {
  if (request.schema_version !== "agent-gym-model-request/v1") invalidRequest();
  reference(request.candidate_ref);
  reference(request.invocation_ref);
  text(request.model_id, 240);
  text(request.system_prompt, 64_000);
  if (!Number.isSafeInteger(request.max_output_tokens)
    || request.max_output_tokens < 1 || request.max_output_tokens > 32_768
    || !Array.isArray(request.messages) || request.messages.length < 1
    || request.messages.length > 64) invalidRequest();
  const messages = request.messages.map((message, index) => {
    if (message.role !== "assistant" && message.role !== "user") invalidRequest();
    text(message.text, 64_000);
    if (index > 0 && request.messages[index - 1]?.role === message.role) invalidRequest();
    return Object.freeze({ role: message.role, text: message.text });
  });
  if (messages[0]?.role !== "user" || messages.at(-1)?.role !== "user") {
    invalidRequest();
  }
  const validated = Object.freeze({
    candidate_ref: request.candidate_ref,
    invocation_ref: request.invocation_ref,
    max_output_tokens: request.max_output_tokens,
    messages: Object.freeze(messages),
    model_id: request.model_id,
    schema_version: "agent-gym-model-request/v1" as const,
    system_prompt: request.system_prompt,
  });
  if (Buffer.byteLength(JSON.stringify(validated), "utf8") > 256_000) invalidRequest();
  return validated;
}

/** Binds a fixture response to the validated request bytes. */
export function agentGymModelRequestDigest(
  request: AgentGymModelInvocationRequestV1,
): `sha256:${string}` {
  const validated = validateAgentGymModelRequest(request);
  return `sha256:${createHash("sha256").update(JSON.stringify(validated)).digest("hex")}`;
}

function reference(value: string): void {
  text(value, 240);
  if (!value.includes("://")) invalidRequest();
}

function referenceWith(value: string, invalid: () => never): void {
  boundedWith(value, 240, invalid);
  if (!value.includes("://")) invalid();
}

function boundedWith(value: string, maximum: number, invalid: () => never): void {
  if (typeof value !== "string" || !value.trim() || value.length > maximum
    || /[\u0000-\u001f\u007f]/u.test(value)) invalid();
}

function digest(value: string): void {
  if (!/^sha256:[0-9a-f]{64}$/u.test(value)) invalidResponse();
}

function validateResponseFields(
  response: AgentGymModelResponseFields,
  invalid: () => never,
): void {
  referenceWith(response.invocation_ref, invalid);
  boundedWith(response.model_id, 240, invalid);
  if (!/^sha256:[0-9a-f]{64}$/u.test(response.request_digest)) invalid();
  if (response.provider_request_ref !== undefined) {
    referenceWith(response.provider_request_ref, invalid);
  }
  if (!Number.isSafeInteger(response.latency_ms) || response.latency_ms < 0
    || response.latency_ms > 60 * 60_000
    || !["content_filtered", "end_turn", "max_tokens"].includes(response.stop_reason)) {
    invalid();
  }
  if (typeof response.output_text !== "string" || response.output_text.length > 256_000
    || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(response.output_text)
    || (response.stop_reason !== "content_filtered" && !response.output_text.trim())) {
    invalid();
  }
  const { input_tokens: inputTokens, output_tokens: outputTokens,
    total_tokens: totalTokens } = response.token_usage;
  for (const tokens of [inputTokens, outputTokens, totalTokens]) {
    if (!Number.isSafeInteger(tokens) || tokens < 0 || tokens > 10_000_000) invalid();
  }
  if (totalTokens !== inputTokens + outputTokens) invalid();
}

function text(value: string, maximum: number): void {
  if (typeof value !== "string" || !value.trim() || value.length > maximum
    || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value)) {
    invalidRequest();
  }
}

function invalidRequest(): never {
  throw new AgentGymContractError("Agent gym model request is invalid.");
}

function invalidResponse(): never {
  throw new AgentGymContractError("Agent gym recorded model response is invalid.");
}

function invalidModelResponse(): never {
  throw new AgentGymContractError("Agent gym model response is invalid.");
}
