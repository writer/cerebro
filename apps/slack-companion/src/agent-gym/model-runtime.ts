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

function text(value: string, maximum: number): void {
  if (typeof value !== "string" || !value.trim() || value.length > maximum
    || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value)) {
    invalidRequest();
  }
}

function invalidRequest(): never {
  throw new AgentGymContractError("Agent gym model request is invalid.");
}
