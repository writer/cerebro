import { projectSlackHome, type SlackHomeProjectionV1 } from "../projections/home.js";
import type { SlackStatusProjectionV1 } from "../projections/status.js";

export interface SlackOperatorSourceStateV1 {
  readonly label: string;
  readonly state: "available" | "degraded" | "stale" | "unavailable";
}

export interface SlackOperatorHomeInputV1 {
  readonly enabled_capabilities: readonly string[];
  readonly memory_note_count?: number;
  readonly notification_mode: "immediate" | "digest" | "muted";
  readonly pending_outcome_count: number;
  readonly projection_key: string;
  readonly source_states: readonly SlackOperatorSourceStateV1[];
  readonly statuses: readonly SlackStatusProjectionV1[];
  readonly view_selector: string;
}

export class SlackOperatorHomeError extends Error {}

/** Builds the operator's current scope, source health, memory, and follow-through view. */
export function projectSlackOperatorHome(
  input: SlackOperatorHomeInputV1,
): SlackHomeProjectionV1 {
  integer(input.pending_outcome_count, "pending outcome count");
  if (input.memory_note_count !== undefined) {
    integer(input.memory_note_count, "memory note count");
  }
  if (!Array.isArray(input.enabled_capabilities) || input.enabled_capabilities.length > 20
    || new Set(input.enabled_capabilities).size !== input.enabled_capabilities.length) {
    throw new SlackOperatorHomeError("Enabled capabilities are invalid.");
  }
  if (!Array.isArray(input.source_states) || input.source_states.length > 20) {
    throw new SlackOperatorHomeError("Source states are invalid.");
  }
  const sources = [...input.source_states].map((source) => {
    const label = bounded(source.label, 80);
    if (!["available", "degraded", "stale", "unavailable"].includes(source.state)) {
      throw new SlackOperatorHomeError("Source state is unsupported.");
    }
    return `${label}: ${source.state}`;
  }).sort();
  const capabilities = [...input.enabled_capabilities].map((value) => bounded(value, 80)).sort();
  return projectSlackHome({
    projection_key: input.projection_key,
    statuses: input.statuses,
    summary: [
      `Scope: ${capabilities.length === 0 ? "No capabilities enabled" : capabilities.join(", ")}`,
      `Sources: ${sources.length === 0 ? "No source health reported" : sources.join("; ")}`,
      `Memory: ${input.memory_note_count === undefined ? "unavailable" : `${input.memory_note_count} retained notes`}`,
      `Outcome checks: ${input.pending_outcome_count} pending; notifications ${input.notification_mode}`,
    ].join("\n"),
    title: "Cerebro operator state",
    view_selector: input.view_selector,
  });
}

function integer(value: number, field: string): void {
  if (!Number.isSafeInteger(value) || value < 0 || value > 1_000_000) {
    throw new SlackOperatorHomeError(`${field} is invalid.`);
  }
}
function bounded(value: string, maximum: number): string {
  const normalized = value.trim();
  if (!normalized || normalized.length > maximum || /[\u0000-\u001f\u007f]/u.test(normalized)) {
    throw new SlackOperatorHomeError("Operator state text is invalid.");
  }
  return normalized;
}
