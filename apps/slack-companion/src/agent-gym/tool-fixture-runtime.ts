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

function invalidPage(): never {
  throw new AgentGymContractError("Agent gym tool page fixture is invalid.");
}
