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

/** Evaluates evidence age against an explicit replay clock. */
export function createAgentGymStaleEvidenceFixture(
  input: CreateAgentGymStaleEvidenceFixture,
): AgentGymStaleEvidenceFixtureV1 {
  reference(input.evidence_ref);
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

function reference(value: string): void {
  identifier(value, 240);
  if (!value.includes("://")) invalidPage();
}

function canonicalTime(value: string): number {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)) {
    invalidStaleEvidence();
  }
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) invalidStaleEvidence();
  return parsed;
}

function invalidPage(): never {
  throw new AgentGymContractError("Agent gym tool page fixture is invalid.");
}

function invalidStaleEvidence(): never {
  throw new AgentGymContractError("Agent gym stale evidence fixture is invalid.");
}
