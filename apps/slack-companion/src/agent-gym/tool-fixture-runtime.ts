import type { AgentGymJson } from "./fixture-case.js";
import { AgentGymContractError } from "./index.js";
import type { AgentGymToolRegistrySnapshotV1 } from "./tool-fixtures.js";

export interface AgentGymToolPageFixtureV1 {
  readonly call_ref: string;
  readonly items: readonly AgentGymJson[];
  readonly next_cursor: string | null;
  readonly page_index: number;
  readonly schema_version: "agent-gym-tool-page-fixture/v1";
  readonly tool_id: string;
}

export interface CreateAgentGymToolPageFixture {
  readonly call_ref: string;
  readonly items: readonly AgentGymJson[];
  readonly next_cursor: string | null;
  readonly page_index: number;
  readonly tool_id: string;
}

export interface AgentGymStaleEvidenceFixtureV1 {
  readonly age_ms: number;
  readonly evaluated_at: string;
  readonly evidence_ref: string;
  readonly max_age_ms: number;
  readonly observed_at: string;
  readonly schema_version: "agent-gym-stale-evidence-fixture/v1";
  readonly stale: boolean;
}

export interface CreateAgentGymStaleEvidenceFixture {
  readonly evaluated_at: string;
  readonly evidence_ref: string;
  readonly max_age_ms: number;
  readonly observed_at: string;
}

export interface AgentGymAuthorizationFixtureV1 {
  readonly action: string;
  readonly decision: "allow" | "deny";
  readonly policy_ref: string;
  readonly principal_ref: string;
  readonly reason_code: string;
  readonly request_ref: string;
  readonly resource_ref: string;
  readonly schema_version: "agent-gym-authorization-fixture/v1";
}

export type CreateAgentGymAuthorizationFixture = Omit<
  AgentGymAuthorizationFixtureV1,
  "schema_version"
>;

export interface AgentGymToolCallV1 {
  readonly call_ref: string;
  readonly input: Readonly<Record<string, AgentGymJson>>;
  readonly tool_id: string;
}

export interface AgentGymToolCallValidationV1 {
  readonly call_ref: string;
  readonly issues: readonly string[];
  readonly schema_version: "agent-gym-tool-call-validation/v1";
  readonly tool_id: string;
  readonly valid: boolean;
}

export interface AgentGymToolUsageAnalysisV1 {
  readonly call_count: number;
  readonly schema_version: "agent-gym-tool-usage-analysis/v1";
  readonly unregistered_tool_ids: readonly string[];
  readonly unused_tool_ids: readonly string[];
  readonly used_tool_ids: readonly string[];
}

/** Reports excess registry surface and calls outside the declared tool boundary. */
export function analyzeAgentGymToolUsage(
  registry: AgentGymToolRegistrySnapshotV1,
  calls: readonly AgentGymToolCallV1[],
): AgentGymToolUsageAnalysisV1 {
  if (!Array.isArray(calls) || calls.length > 10_000) invalidToolUsage();
  const callRefs = new Set<string>();
  const calledToolIds = new Set<string>();
  for (const call of calls) {
    reference(call.call_ref, invalidToolUsage);
    toolIdentifier(call.tool_id, invalidToolUsage);
    if (callRefs.has(call.call_ref)) invalidToolUsage();
    callRefs.add(call.call_ref);
    calledToolIds.add(call.tool_id);
  }
  const registeredToolIds = new Set(registry.tools.map((tool) => tool.tool_id));
  const usedToolIds = [...calledToolIds]
    .filter((toolId) => registeredToolIds.has(toolId)).sort();
  const unusedToolIds = [...registeredToolIds]
    .filter((toolId) => !calledToolIds.has(toolId)).sort();
  const unregisteredToolIds = [...calledToolIds]
    .filter((toolId) => !registeredToolIds.has(toolId)).sort();
  return Object.freeze({
    call_count: calls.length,
    schema_version: "agent-gym-tool-usage-analysis/v1",
    unregistered_tool_ids: Object.freeze(unregisteredToolIds),
    unused_tool_ids: Object.freeze(unusedToolIds),
    used_tool_ids: Object.freeze(usedToolIds),
  });
}

/** Validates a replayed call against the frozen registry's JSON Schema subset. */
export function validateAgentGymToolCall(
  registry: AgentGymToolRegistrySnapshotV1,
  call: AgentGymToolCallV1,
): AgentGymToolCallValidationV1 {
  reference(call.call_ref, invalidToolCall);
  toolIdentifier(call.tool_id, invalidToolCall);
  const definition = registry.tools.find((tool) => tool.tool_id === call.tool_id);
  const issues: string[] = [];
  if (definition === undefined) {
    issues.push("tool.not_registered");
  } else {
    validateSchema(definition.input_schema, call.input, "$", issues, 0);
  }
  const stableIssues = Object.freeze([...new Set(issues)].sort());
  return Object.freeze({
    call_ref: call.call_ref,
    issues: stableIssues,
    schema_version: "agent-gym-tool-call-validation/v1",
    tool_id: call.tool_id,
    valid: stableIssues.length === 0,
  });
}

/** Records a replay-only authorization decision with its policy evidence. */
export function createAgentGymAuthorizationFixture(
  input: CreateAgentGymAuthorizationFixture,
): AgentGymAuthorizationFixtureV1 {
  reference(input.request_ref, invalidAuthorization);
  reference(input.policy_ref, invalidAuthorization);
  reference(input.principal_ref, invalidAuthorization);
  reference(input.resource_ref, invalidAuthorization);
  code(input.action, 160);
  code(input.reason_code, 160);
  if (input.decision !== "allow" && input.decision !== "deny") {
    invalidAuthorization();
  }
  return Object.freeze({
    ...input,
    schema_version: "agent-gym-authorization-fixture/v1",
  });
}

/** Evaluates evidence age against an explicit replay clock. */
export function createAgentGymStaleEvidenceFixture(
  input: CreateAgentGymStaleEvidenceFixture,
): AgentGymStaleEvidenceFixtureV1 {
  reference(input.evidence_ref, invalidStaleEvidence);
  const observedAt = canonicalTime(input.observed_at);
  const evaluatedAt = canonicalTime(input.evaluated_at);
  if (!Number.isSafeInteger(input.max_age_ms) || input.max_age_ms < 1
    || input.max_age_ms > 365 * 24 * 60 * 60_000
    || evaluatedAt < observedAt) invalidStaleEvidence();
  const ageMs = evaluatedAt - observedAt;
  return Object.freeze({
    age_ms: ageMs,
    evaluated_at: input.evaluated_at,
    evidence_ref: input.evidence_ref,
    max_age_ms: input.max_age_ms,
    observed_at: input.observed_at,
    schema_version: "agent-gym-stale-evidence-fixture/v1",
    stale: ageMs > input.max_age_ms,
  });
}

/** Creates one deterministic page without contacting or advancing a live source. */
export function createAgentGymToolPageFixture(
  input: CreateAgentGymToolPageFixture,
): AgentGymToolPageFixtureV1 {
  reference(input.call_ref);
  identifier(input.tool_id, 160);
  if (!Array.isArray(input.items) || input.items.length > 1_000
    || !Number.isSafeInteger(input.page_index) || input.page_index < 0
    || input.page_index > 10_000) invalidPage();
  if (input.next_cursor !== null) identifier(input.next_cursor, 1_000);
  const items = structuredClone(input.items);
  deepFreeze(items);
  return Object.freeze({
    ...input,
    items,
    schema_version: "agent-gym-tool-page-fixture/v1",
  });
}

function deepFreeze(value: AgentGymJson): void {
  if (value !== null && typeof value === "object") {
    for (const nested of Object.values(value)) deepFreeze(nested);
    Object.freeze(value);
  }
}

function identifier(value: string, maximum: number): void {
  if (typeof value !== "string" || !value.trim() || value.length > maximum
    || /[\u0000-\u001f\u007f]/u.test(value)) invalidPage();
}

function reference(value: string, invalid: () => never = invalidPage): void {
  if (typeof value !== "string" || !value.trim() || value.length > 240
    || /[\u0000-\u001f\u007f]/u.test(value) || !value.includes("://")) invalid();
}

function canonicalTime(value: string): number {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)) {
    invalidStaleEvidence();
  }
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) invalidStaleEvidence();
  return parsed;
}

function code(value: string, maximum: number): void {
  if (typeof value !== "string" || value.length > maximum
    || !/^[a-z0-9][a-z0-9._:-]*$/u.test(value)) invalidAuthorization();
}

function validateSchema(
  schema: AgentGymJson,
  value: AgentGymJson,
  path: string,
  issues: string[],
  depth: number,
): void {
  if (issues.length >= 128) return;
  if (depth > 32 || !jsonRecord(schema) || typeof schema.type !== "string") {
    issues.push(`${path}:schema.unsupported`);
    return;
  }
  if (!matchesType(schema.type, value)) {
    issues.push(`${path}:input.type_mismatch`);
    return;
  }
  if (Array.isArray(schema.enum)
    && !schema.enum.some((candidate) => JSON.stringify(candidate) === JSON.stringify(value))) {
    issues.push(`${path}:input.enum_mismatch`);
  }
  if (schema.type === "object" && jsonRecord(value)) {
    const properties = schema.properties;
    if (properties !== undefined && !jsonRecord(properties)) {
      issues.push(`${path}:schema.unsupported`);
      return;
    }
    const required = schema.required;
    if (required !== undefined) {
      if (!Array.isArray(required)) {
        issues.push(`${path}:schema.unsupported`);
        return;
      }
      for (const name of required) {
        if (typeof name !== "string") {
          issues.push(`${path}:schema.unsupported`);
          return;
        }
        if (!(name in value)) issues.push(`${path}.${name}:input.required_missing`);
      }
    }
    if (schema.additionalProperties === false && jsonRecord(properties)) {
      for (const name of Object.keys(value)) {
        if (!(name in properties)) issues.push(`${path}.${name}:input.unknown_property`);
      }
    }
    if (jsonRecord(properties)) {
      for (const [name, propertyValue] of Object.entries(value)) {
        const propertySchema = properties[name];
        if (propertySchema !== undefined) {
          validateSchema(propertySchema, propertyValue, `${path}.${name}`, issues, depth + 1);
        }
      }
    }
  }
  const itemSchema = schema.items;
  if (schema.type === "array" && Array.isArray(value) && itemSchema !== undefined) {
    for (const [index, item] of value.entries()) {
      validateSchema(itemSchema, item, `${path}[${index}]`, issues, depth + 1);
    }
  }
}

function matchesType(type: string, value: AgentGymJson): boolean {
  switch (type) {
    case "array": return Array.isArray(value);
    case "boolean": return typeof value === "boolean";
    case "integer": return typeof value === "number" && Number.isSafeInteger(value);
    case "null": return value === null;
    case "number": return typeof value === "number" && Number.isFinite(value);
    case "object": return jsonRecord(value);
    case "string": return typeof value === "string";
    default: return false;
  }
}

function jsonRecord(value: AgentGymJson | undefined): value is Readonly<Record<string, AgentGymJson>> {
  return value !== null && value !== undefined && typeof value === "object"
    && !Array.isArray(value);
}

function toolIdentifier(value: string, invalid: () => never): void {
  if (typeof value !== "string" || !value.trim() || value.length > 160
    || /[\u0000-\u001f\u007f]/u.test(value)) invalid();
}

function invalidPage(): never {
  throw new AgentGymContractError("Agent gym tool page fixture is invalid.");
}

function invalidStaleEvidence(): never {
  throw new AgentGymContractError("Agent gym stale evidence fixture is invalid.");
}

function invalidAuthorization(): never {
  throw new AgentGymContractError("Agent gym authorization fixture is invalid.");
}

function invalidToolCall(): never {
  throw new AgentGymContractError("Agent gym tool call is invalid.");
}

function invalidToolUsage(): never {
  throw new AgentGymContractError("Agent gym tool usage is invalid.");
}
