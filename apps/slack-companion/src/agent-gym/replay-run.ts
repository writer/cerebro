import { AgentGymContractError } from "./contract-error.js";

export interface AgentGymReplayTurnV1 {
  readonly content_digest: `sha256:${string}`;
  readonly kind: "effect" | "input" | "model" | "tool";
  readonly latency_ms: number;
  readonly provider_request_id?: string;
  readonly recorded_at: string;
  readonly token_usage?: {
    readonly input_tokens: number;
    readonly output_tokens: number;
  };
  readonly turn_index: number;
}

export interface AgentGymReplayRunV1 {
  readonly artifact_digest: `sha256:${string}`;
  readonly candidate_ref: string;
  readonly completed_at: string;
  readonly failure_code?: string;
  readonly fixture_ref: string;
  readonly run_ref: string;
  readonly schema_version: "agent-gym-replay-run/v1";
  readonly started_at: string;
  readonly status: "failed" | "passed";
  readonly turns: readonly AgentGymReplayTurnV1[];
}

/** Validates the immutable receipt for one complete fixture replay. */
export function validateAgentGymReplayRun(run: AgentGymReplayRunV1): AgentGymReplayRunV1 {
  if (run.schema_version !== "agent-gym-replay-run/v1") invalid();
  for (const ref of [run.run_ref, run.candidate_ref, run.fixture_ref]) reference(ref);
  timestamp(run.started_at);
  timestamp(run.completed_at);
  if (Date.parse(run.completed_at) < Date.parse(run.started_at)) invalid();
  digest(run.artifact_digest);
  if (!["failed", "passed"].includes(run.status)) invalid();
  if ((run.status === "failed") !== (run.failure_code !== undefined)) invalid();
  if (run.failure_code !== undefined) bounded(run.failure_code, 120);
  if (!Array.isArray(run.turns) || run.turns.length === 0 || run.turns.length > 1_000) invalid();
  let priorTime = Date.parse(run.started_at);
  const turns = run.turns.map((turn, index) => {
    if (turn.turn_index !== index || !["effect", "input", "model", "tool"].includes(turn.kind)) invalid();
    timestamp(turn.recorded_at);
    const time = Date.parse(turn.recorded_at);
    if (time < priorTime || time > Date.parse(run.completed_at)) invalid();
    priorTime = time;
    digest(turn.content_digest);
    integer(turn.latency_ms, 3_600_000);
    if (turn.provider_request_id !== undefined) bounded(turn.provider_request_id, 240);
    if (turn.token_usage !== undefined) {
      integer(turn.token_usage.input_tokens, 100_000_000);
      integer(turn.token_usage.output_tokens, 100_000_000);
    }
    return Object.freeze({
      ...turn,
      ...(turn.token_usage === undefined ? {} : { token_usage: Object.freeze({ ...turn.token_usage }) }),
    });
  });
  return Object.freeze({ ...run, turns: Object.freeze(turns) });
}

function bounded(value: string, maximum: number): void {
  if (typeof value !== "string" || !value.trim() || value.length > maximum
    || /[\u0000-\u001f\u007f]/u.test(value)) invalid();
}
function digest(value: string): void { if (!/^sha256:[0-9a-f]{64}$/u.test(value)) invalid(); }
function integer(value: number, maximum: number): void {
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum) invalid();
}
function reference(value: string): void { bounded(value, 240); if (!value.includes("://")) invalid(); }
function timestamp(value: string): void {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)
    || !Number.isFinite(Date.parse(value))) invalid();
}
function invalid(): never { throw new AgentGymContractError("Agent gym replay run is invalid."); }
