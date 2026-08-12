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
function invalid(): never {
  throw new AgentGymContractError("Agent gym tool registry is invalid.");
}
