import { createHash } from "node:crypto";
import type { AgentGymJson } from "./fixture-case.js";
import { AgentGymContractError } from "./index.js";

export interface AgentGymToolDefinitionV1 {
  readonly description: string;
  readonly input_schema: Readonly<Record<string, AgentGymJson>>;
  readonly tool_id: string;
}

export interface AgentGymToolRegistrySnapshotV1 {
  readonly registry_digest: `sha256:${string}`;
  readonly schema_version: "agent-gym-tool-registry/v1";
  readonly tools: readonly AgentGymToolDefinitionV1[];
}

export interface AgentGymRecordedToolResultV1 {
  readonly call_ref: string;
  readonly input_digest: `sha256:${string}`;
  readonly output: Readonly<Record<string, AgentGymJson>>;
  readonly recorded_at: string;
  readonly schema_version: "agent-gym-recorded-tool-result/v1";
  readonly tool_id: string;
}

export interface AgentGymToolErrorFixtureV1 {
  readonly call_ref: string;
  readonly error_code: string;
  readonly message: string;
  readonly retryable: boolean;
  readonly schema_version: "agent-gym-tool-error-fixture/v1";
  readonly tool_id: string;
}

export interface AgentGymToolTimeoutFixtureV1 {
  readonly call_ref: string;
  readonly elapsed_ms: number;
  readonly timeout_ms: number;
  readonly schema_version: "agent-gym-tool-timeout-fixture/v1";
  readonly tool_id: string;
}

export interface AgentGymPartialToolResultV1 {
  readonly call_ref: string;
  readonly missing_fields: readonly string[];
  readonly output: Readonly<Record<string, AgentGymJson>>;
  readonly reason_code: string;
  readonly schema_version: "agent-gym-partial-tool-result/v1";
  readonly tool_id: string;
}

/** Records useful but explicitly incomplete tool output. */
export function injectAgentGymPartialToolResult(
  input: Omit<AgentGymPartialToolResultV1, "schema_version">,
): AgentGymPartialToolResultV1 {
  reference(input.call_ref);
  bounded(input.tool_id, 160);
  bounded(input.reason_code, 120);
  if (!/^[a-z0-9][a-z0-9._-]*$/u.test(input.reason_code)
    || !Array.isArray(input.missing_fields)
    || input.missing_fields.length === 0
    || input.missing_fields.length > 64
    || new Set(input.missing_fields).size !== input.missing_fields.length) {
    invalidPartial();
  }
  for (const field of input.missing_fields) {
    bounded(field, 160);
    if (!/^[a-z][a-z0-9_.-]*$/u.test(field)) invalidPartial();
  }
  return Object.freeze({
    ...input,
    missing_fields: Object.freeze([...input.missing_fields].sort()),
    output: deepFreeze({ ...input.output }),
    schema_version: "agent-gym-partial-tool-result/v1",
  });
}

/** Records a deterministic timeout boundary without waiting in real time. */
export function injectAgentGymToolTimeout(
  input: Omit<AgentGymToolTimeoutFixtureV1, "schema_version">,
): AgentGymToolTimeoutFixtureV1 {
  reference(input.call_ref);
  bounded(input.tool_id, 160);
  integer(input.timeout_ms, 15 * 60_000, false);
  integer(input.elapsed_ms, 60 * 60_000, false);
  if (input.elapsed_ms < input.timeout_ms) invalidTimeout();
  return Object.freeze({
    ...input,
    schema_version: "agent-gym-tool-timeout-fixture/v1",
  });
}

/** Creates a bounded provider-error fixture without a thrown live error. */
export function injectAgentGymToolError(
  input: Omit<AgentGymToolErrorFixtureV1, "schema_version">,
): AgentGymToolErrorFixtureV1 {
  reference(input.call_ref);
  bounded(input.tool_id, 160);
  bounded(input.error_code, 120);
  bounded(input.message, 1_000);
  if (!/^[a-z0-9][a-z0-9._-]*$/u.test(input.error_code)) invalidError();
  return Object.freeze({
    ...input,
    schema_version: "agent-gym-tool-error-fixture/v1",
  });
}

export interface RecordAgentGymToolResult {
  readonly call_ref: string;
  readonly input: Readonly<Record<string, AgentGymJson>>;
  readonly output: Readonly<Record<string, AgentGymJson>>;
  readonly recorded_at: string;
  readonly tool_id: string;
}

/** Records one successful tool response for deterministic replay. */
export function recordAgentGymToolResult(
  input: RecordAgentGymToolResult,
): AgentGymRecordedToolResultV1 {
  reference(input.call_ref);
  bounded(input.tool_id, 160);
  timestamp(input.recorded_at);
  const output = deepFreeze({ ...input.output });
  return Object.freeze({
    call_ref: input.call_ref,
    input_digest: `sha256:${createHash("sha256").update(JSON.stringify(input.input)).digest("hex")}`,
    output,
    recorded_at: input.recorded_at,
    schema_version: "agent-gym-recorded-tool-result/v1",
    tool_id: input.tool_id,
  });
}

/** Builds a stable tool registry for one offline candidate replay. */
export function createAgentGymToolRegistry(
  definitions: readonly AgentGymToolDefinitionV1[],
): AgentGymToolRegistrySnapshotV1 {
  if (!Array.isArray(definitions) || definitions.length === 0
    || definitions.length > 256) invalid();
  const tools = [...definitions].map((definition) => {
    bounded(definition.tool_id, 160);
    bounded(definition.description, 2_000);
    if (definition.input_schema.type !== "object") invalid();
    const schema = deepFreeze({ ...definition.input_schema });
    return Object.freeze({ ...definition, input_schema: schema });
  }).sort((left, right) => left.tool_id.localeCompare(right.tool_id));
  if (new Set(tools.map((tool) => tool.tool_id)).size !== tools.length) invalid();
  return Object.freeze({
    registry_digest: `sha256:${createHash("sha256").update(JSON.stringify(tools)).digest("hex")}`,
    schema_version: "agent-gym-tool-registry/v1",
    tools: Object.freeze(tools),
  });
}

function bounded(value: string, maximum: number): void {
  if (typeof value !== "string" || !value.trim() || value.length > maximum
    || /[\u0000-\u001f\u007f]/u.test(value)) invalid();
}
function deepFreeze<T extends AgentGymJson>(value: T): T {
  if (value !== null && typeof value === "object") {
    for (const nested of Object.values(value)) deepFreeze(nested);
    Object.freeze(value);
  }
  return value;
}
function reference(value: string): void {
  bounded(value, 240);
  if (!value.includes("://")) invalidResult();
}
function integer(value: number, maximum: number, allowZero = true): void {
  if (!Number.isSafeInteger(value) || value < (allowZero ? 0 : 1)
    || value > maximum) invalidTimeout();
}
function timestamp(value: string): void {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)
    || !Number.isFinite(Date.parse(value))) invalidResult();
}
function invalid(): never {
  throw new AgentGymContractError("Agent gym tool registry is invalid.");
}
function invalidResult(): never {
  throw new AgentGymContractError("Agent gym recorded tool result is invalid.");
}
function invalidError(): never {
  throw new AgentGymContractError("Agent gym tool error fixture is invalid.");
}
function invalidTimeout(): never {
  throw new AgentGymContractError("Agent gym tool timeout fixture is invalid.");
}
function invalidPartial(): never {
  throw new AgentGymContractError("Agent gym partial tool result is invalid.");
}
