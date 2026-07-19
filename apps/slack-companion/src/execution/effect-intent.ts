import { createHash } from "node:crypto";
import { ExecutionInvariantError } from "./coordinator.js";
import type {
  EffectIntentValue,
  ExternalEffectIntentDraft,
  ExternalEffectIntentV1,
} from "./model.js";

export function normalizeEffectIntentValue(value: unknown): EffectIntentValue {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new ExecutionInvariantError("effect intent numbers must be finite");
    }
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => normalizeEffectIntentValue(item));
  }
  if (typeof value !== "object") {
    throw new ExecutionInvariantError("effect intent must contain JSON values only");
  }

  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new ExecutionInvariantError("effect intent objects must be plain records");
  }

  const normalized: Record<string, EffectIntentValue> = {};
  for (const key of Object.keys(value as Record<string, unknown>).sort()) {
    if (key.trim() === "") {
      throw new ExecutionInvariantError("effect intent keys must not be empty");
    }
    if (key === "__proto__" || key === "constructor" || key === "prototype") {
      throw new ExecutionInvariantError("effect intent contains an unsafe key");
    }
    normalized[key] = normalizeEffectIntentValue(
      (value as Record<string, unknown>)[key],
    );
  }
  return normalized;
}

export type ExternalEffectIntentDigestInput = Omit<
  ExternalEffectIntentDraft,
  "request_digest"
>;

export function effectIntentDigest(
  input: ExternalEffectIntentDigestInput,
): string {
  const digestInput: EffectIntentValue = {
    approval_ref: input.approval_ref ?? null,
    approval_required: input.approval_required,
    candidate_version: input.candidate_version,
    effect_id: input.effect_id,
    idempotency_key: input.idempotency_key,
    request: input.request,
    rollback_plan_ref: input.rollback_plan_ref ?? null,
    step_id: input.step_id,
    target_ref: input.target_ref,
  };
  return `sha256:${createHash("sha256").update(JSON.stringify(digestInput)).digest("hex")}`;
}

export function sameExternalEffectIntent(
  intent: ExternalEffectIntentV1,
  draft: ExternalEffectIntentDraft,
): boolean {
  return (
    intent.approval_ref === draft.approval_ref &&
    intent.approval_required === draft.approval_required &&
    intent.candidate_version === draft.candidate_version &&
    intent.effect_id === draft.effect_id &&
    intent.idempotency_key === draft.idempotency_key &&
    intent.request_digest === draft.request_digest &&
    intent.rollback_plan_ref === draft.rollback_plan_ref &&
    intent.step_id === draft.step_id &&
    intent.target_ref === draft.target_ref &&
    JSON.stringify(intent.request) === JSON.stringify(draft.request)
  );
}
