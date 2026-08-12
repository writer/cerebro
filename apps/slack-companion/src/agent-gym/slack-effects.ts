import { createHash } from "node:crypto";
import type { AgentGymJson } from "./fixture-case.js";
import { AgentGymContractError } from "./index.js";

export type AgentGymSlackEffectOperation =
  | "open_modal"
  | "post_ephemeral"
  | "post_message"
  | "publish_home"
  | "update_message";

export interface AgentGymSlackEffectV1 {
  readonly effect_ref: string;
  readonly idempotency_key: string;
  readonly operation: AgentGymSlackEffectOperation;
  readonly payload: Readonly<Record<string, AgentGymJson>>;
  readonly schema_version: "agent-gym-slack-effect/v1";
  readonly target_refs: readonly string[];
}

export interface CaptureAgentGymSlackPostMessage {
  readonly channel_ref: string;
  readonly idempotency_key: string;
  readonly text: string;
  readonly thread_ref?: string;
}

export interface CaptureAgentGymSlackUpdateMessage {
  readonly idempotency_key: string;
  readonly message_ref: string;
  readonly text: string;
}

export interface CaptureAgentGymSlackPublishHome {
  readonly idempotency_key: string;
  readonly user_ref: string;
  readonly view: Readonly<Record<string, AgentGymJson>>;
}

export interface CaptureAgentGymSlackOpenModal {
  readonly idempotency_key: string;
  readonly trigger_ref: string;
  readonly user_ref: string;
  readonly view: Readonly<Record<string, AgentGymJson>>;
}

export interface CaptureAgentGymSlackPostEphemeral {
  readonly channel_ref: string;
  readonly idempotency_key: string;
  readonly text: string;
  readonly thread_ref?: string;
  readonly user_ref: string;
}

/** Captures a user-scoped ephemeral response with its channel boundary. */
export function captureAgentGymSlackPostEphemeral(
  input: CaptureAgentGymSlackPostEphemeral,
): AgentGymSlackEffectV1 {
  reference(input.channel_ref, "channel reference");
  reference(input.user_ref, "user reference");
  if (input.thread_ref !== undefined) reference(input.thread_ref, "thread reference");
  safeText(input.text, 40_000, "ephemeral text");
  return effect("post_ephemeral", input.idempotency_key, [
    input.channel_ref,
    input.user_ref,
    ...(input.thread_ref === undefined ? [] : [input.thread_ref]),
  ], {
    text: input.text,
    user_ref: input.user_ref,
    ...(input.thread_ref === undefined ? {} : { thread_ref: input.thread_ref }),
  });
}

/** Captures a modal open request bound to its one-use trigger and actor. */
export function captureAgentGymSlackOpenModal(
  input: CaptureAgentGymSlackOpenModal,
): AgentGymSlackEffectV1 {
  reference(input.trigger_ref, "trigger reference");
  reference(input.user_ref, "user reference");
  jsonObject(input.view, "modal view");
  if (input.view.type !== "modal") invalid("modal view type");
  return effect("open_modal", input.idempotency_key, [
    input.trigger_ref,
    input.user_ref,
  ], { view: input.view });
}

/** Captures an App Home publication with a fully inspectable view payload. */
export function captureAgentGymSlackPublishHome(
  input: CaptureAgentGymSlackPublishHome,
): AgentGymSlackEffectV1 {
  reference(input.user_ref, "user reference");
  jsonObject(input.view, "Home view");
  if (input.view.type !== "home") invalid("Home view type");
  return effect("publish_home", input.idempotency_key, [input.user_ref], {
    view: input.view,
  });
}

/** Captures replacement content bound to one existing message. */
export function captureAgentGymSlackUpdateMessage(
  input: CaptureAgentGymSlackUpdateMessage,
): AgentGymSlackEffectV1 {
  reference(input.message_ref, "message reference");
  safeText(input.text, 40_000, "message text");
  return effect("update_message", input.idempotency_key, [input.message_ref], {
    text: input.text,
  });
}

/** Captures a message post as data instead of invoking Slack. */
export function captureAgentGymSlackPostMessage(
  input: CaptureAgentGymSlackPostMessage,
): AgentGymSlackEffectV1 {
  reference(input.channel_ref, "channel reference");
  if (input.thread_ref !== undefined) reference(input.thread_ref, "thread reference");
  safeText(input.text, 40_000, "message text");
  return effect("post_message", input.idempotency_key, [
    input.channel_ref,
    ...(input.thread_ref === undefined ? [] : [input.thread_ref]),
  ], {
    text: input.text,
    ...(input.thread_ref === undefined ? {} : { thread_ref: input.thread_ref }),
  });
}

function effect(
  operation: AgentGymSlackEffectOperation,
  idempotencyKey: string,
  targetRefs: readonly string[],
  payload: Readonly<Record<string, AgentGymJson>>,
): AgentGymSlackEffectV1 {
  bounded(idempotencyKey, 240, "idempotency key");
  if (targetRefs.length === 0 || targetRefs.length > 8
    || new Set(targetRefs).size !== targetRefs.length) invalid("targets");
  const frozenPayload = deepFreeze({ ...payload });
  return Object.freeze({
    effect_ref: `slack-effect://sha256/${digest(JSON.stringify({
      idempotency_key: idempotencyKey,
      operation,
      payload: frozenPayload,
      target_refs: targetRefs,
    }))}`,
    idempotency_key: idempotencyKey,
    operation,
    payload: frozenPayload,
    schema_version: "agent-gym-slack-effect/v1",
    target_refs: Object.freeze([...targetRefs]),
  });
}

function deepFreeze<T extends AgentGymJson>(value: T): T {
  if (value !== null && typeof value === "object") {
    for (const nested of Object.values(value)) deepFreeze(nested);
    Object.freeze(value);
  }
  return value;
}

function bounded(value: string, maximum: number, label: string): void {
  if (typeof value !== "string" || !value.trim() || value.length > maximum
    || /[\u0000-\u001f\u007f]/u.test(value)) invalid(label);
}
function digest(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
function reference(value: string, label: string): void {
  bounded(value, 240, label);
  if (!value.includes("://")) invalid(label);
}
function jsonObject(value: object, label: string): void {
  try {
    const encoded = JSON.stringify(value);
    if (encoded === undefined || Buffer.byteLength(encoded, "utf8") > 256_000) invalid(label);
  } catch {
    invalid(label);
  }
}
function safeText(value: string, maximum: number, label: string): void {
  if (typeof value !== "string" || !value.trim() || value.length > maximum
    || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value)) invalid(label);
}
function invalid(label: string): never {
  throw new AgentGymContractError(`Agent gym Slack effect ${label} is invalid.`);
}
