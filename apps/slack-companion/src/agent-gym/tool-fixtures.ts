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
