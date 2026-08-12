import type { AgentGymJson } from "./fixture-case.js";
import { AgentGymContractError } from "./index.js";

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

function invalidPage(): never {
  throw new AgentGymContractError("Agent gym tool page fixture is invalid.");
}

function invalidStaleEvidence(): never {
  throw new AgentGymContractError("Agent gym stale evidence fixture is invalid.");
}

function invalidAuthorization(): never {
  throw new AgentGymContractError("Agent gym authorization fixture is invalid.");
}
