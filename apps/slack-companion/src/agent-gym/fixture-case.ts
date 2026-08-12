import { AgentGymContractError } from "./contract-error.js";

export type AgentGymJson =
  | boolean | number | string | null
  | readonly AgentGymJson[]
  | { readonly [key: string]: AgentGymJson };

export type AgentGymSlackEventKind =
  | "app_home_opened"
  | "button_action"
  | "direct_message"
  | "mention"
  | "message_changed"
  | "message_deleted"
  | "reaction_added"
  | "thread_reply";

export interface AgentGymSlackEventV1 {
  readonly event_ref: string;
  readonly kind: AgentGymSlackEventKind;
  readonly occurred_at: string;
  readonly payload: { readonly [key: string]: AgentGymJson };
}

export interface AgentGymToolFixtureV1 {
  readonly call_ref: string;
  readonly error_code?: string;
  readonly input: { readonly [key: string]: AgentGymJson };
  readonly outcome: "error" | "success" | "timeout";
  readonly output?: { readonly [key: string]: AgentGymJson };
  readonly tool_id: string;
}

export interface AgentGymFixtureCaseV1 {
  readonly case_ref: string;
  readonly expected_invariants: readonly string[];
  readonly labels: readonly string[];
  readonly partition: "held_out" | "shadow" | "train";
  readonly schema_version: "agent-gym-fixture-case/v1";
  readonly slack_events: readonly AgentGymSlackEventV1[];
  readonly tool_fixtures: readonly AgentGymToolFixtureV1[];
}

const EVENT_KINDS: readonly AgentGymSlackEventKind[] = [
  "app_home_opened", "button_action", "direct_message", "mention",
  "message_changed", "message_deleted", "reaction_added", "thread_reply",
];

/** Validates and freezes one portable Slack-agent scenario. */
export function validateAgentGymFixtureCase(
  fixture: AgentGymFixtureCaseV1,
): AgentGymFixtureCaseV1 {
  if (fixture.schema_version !== "agent-gym-fixture-case/v1") invalid();
  reference(fixture.case_ref, "case reference");
  if (!["held_out", "shadow", "train"].includes(fixture.partition)) invalid();
  strings(fixture.labels, 32, "labels");
  strings(fixture.expected_invariants, 64, "expected invariants");
  if (fixture.slack_events.length === 0 || fixture.slack_events.length > 100) invalid();
  const eventRefs = new Set<string>();
  const events = fixture.slack_events.map((event) => {
    reference(event.event_ref, "event reference");
    if (eventRefs.has(event.event_ref) || !EVENT_KINDS.includes(event.kind)) invalid();
    eventRefs.add(event.event_ref);
    timestamp(event.occurred_at);
    jsonObject(event.payload, "event payload");
    return Object.freeze({ ...event, payload: deepFreeze(event.payload) });
  });
  const callRefs = new Set<string>();
  const tools = fixture.tool_fixtures.map((tool) => {
    reference(tool.call_ref, "tool call reference");
    text(tool.tool_id, 160, "tool id");
    if (callRefs.has(tool.call_ref) || !["error", "success", "timeout"].includes(tool.outcome)) invalid();
    callRefs.add(tool.call_ref);
    jsonObject(tool.input, "tool input");
    if (tool.outcome === "success" && tool.output === undefined) invalid();
    if (tool.output !== undefined) jsonObject(tool.output, "tool output");
    if (tool.error_code !== undefined) text(tool.error_code, 120, "tool error code");
    return Object.freeze({
      ...tool,
      input: deepFreeze(tool.input),
      ...(tool.output === undefined ? {} : { output: deepFreeze(tool.output) }),
    });
  });
  return Object.freeze({
    ...fixture,
    expected_invariants: Object.freeze([...fixture.expected_invariants]),
    labels: Object.freeze([...fixture.labels]),
    slack_events: Object.freeze(events),
    tool_fixtures: Object.freeze(tools),
  });
}

function deepFreeze<T extends AgentGymJson>(value: T): T {
  if (value !== null && typeof value === "object") {
    for (const nested of Object.values(value)) deepFreeze(nested);
    Object.freeze(value);
  }
  return value;
}
function invalid(): never { throw new AgentGymContractError("Agent gym fixture is invalid."); }
function jsonObject(value: object, field: string): void {
  try {
    const encoded = JSON.stringify(value);
    if (encoded === undefined || Buffer.byteLength(encoded, "utf8") > 256_000) throw new Error();
  } catch { throw new AgentGymContractError(`Agent gym ${field} is invalid.`); }
}
function reference(value: string, field: string): void {
  text(value, 240, field);
  if (!value.includes("://")) throw new AgentGymContractError(`Agent gym ${field} is invalid.`);
}
function strings(values: readonly string[], limit: number, field: string): void {
  if (!Array.isArray(values) || values.length > limit || new Set(values).size !== values.length) invalid();
  for (const value of values) text(value, 160, field);
}
function text(value: string, maximum: number, field: string): void {
  if (typeof value !== "string" || !value.trim() || value.length > maximum || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new AgentGymContractError(`Agent gym ${field} is invalid.`);
  }
}
function timestamp(value: string): void {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) || !Number.isFinite(Date.parse(value))) invalid();
}
