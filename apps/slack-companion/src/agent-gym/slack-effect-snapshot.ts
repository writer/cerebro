import { createHash } from "node:crypto";
import { AgentGymContractError } from "./contract-error.js";
import type { AgentGymSlackEffectV1 } from "./slack-effects.js";

export interface AgentGymSlackEffectSnapshotV1 {
  readonly effect_count: number;
  readonly effect_refs: readonly string[];
  readonly operations: Readonly<Record<string, number>>;
  readonly schema_version: "agent-gym-slack-effect-snapshot/v1";
  readonly snapshot_digest: `sha256:${string}`;
}

/** Renders a stable, content-addressed summary for test and PR receipts. */
export function snapshotAgentGymSlackEffects(
  effects: readonly AgentGymSlackEffectV1[],
): AgentGymSlackEffectSnapshotV1 {
  if (!Array.isArray(effects) || effects.length > 10_000) invalid();
  const byRef = [...effects].sort((left, right) =>
    left.effect_ref.localeCompare(right.effect_ref)
  );
  if (new Set(byRef.map((effect) => effect.effect_ref)).size !== byRef.length
    || byRef.some((effect) => effect.schema_version !== "agent-gym-slack-effect/v1")) invalid();
  const operations: Record<string, number> = {};
  for (const effect of byRef) {
    operations[effect.operation] = (operations[effect.operation] ?? 0) + 1;
  }
  const effectRefs = Object.freeze(byRef.map((effect) => effect.effect_ref));
  const frozenOperations = Object.freeze(Object.fromEntries(
    Object.entries(operations).sort(([left], [right]) => left.localeCompare(right)),
  ));
  return Object.freeze({
    effect_count: byRef.length,
    effect_refs: effectRefs,
    operations: frozenOperations,
    schema_version: "agent-gym-slack-effect-snapshot/v1",
    snapshot_digest: `sha256:${createHash("sha256").update(JSON.stringify({
      effect_refs: effectRefs,
      operations: frozenOperations,
    })).digest("hex")}`,
  });
}

function invalid(): never {
  throw new AgentGymContractError("Agent gym Slack effect snapshot is invalid.");
}
