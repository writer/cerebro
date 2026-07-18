import { createHash } from "node:crypto";
import {
  ASSISTANT_TURN_EVALUATION_BLOCKERS,
  type AssistantTurnEvaluationDimensionsV1,
  type AssistantTurnEvaluationV1,
} from "../assistant-turn/evaluation.js";
import type {
  ImprovementOutcomeEvaluationSetReceiptV1,
  ImprovementOutcomeEvaluationSetV1,
} from "./contracts.js";

const EVALUATION_SET_RECEIPT_SCHEMA =
  "improvement-outcome-evaluation-set-receipt/v1" as const;
const MAXIMUM_EVALUATIONS = 512;
const MAXIMUM_OBJECT_FIELDS = 64;
const MAXIMUM_PLAIN_DATA_DEPTH = 8;
const MAXIMUM_PLAIN_DATA_NODES = 50_000;
const MAXIMUM_REFERENCE_BYTES = 2_048;
const SHA256_DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/;
const OPAQUE_REFERENCE_PATTERN = /^[a-z][a-z0-9+.-]*:\/\/[a-z0-9][a-z0-9._/-]{0,2047}$/;

const EVALUATION_KEYS = [
  "blockers",
  "case_digest",
  "case_ref",
  "dimensions",
  "evaluator_ref",
  "observation_digest",
  "observation_ref",
  "partition",
  "passed",
  "policy_ref",
  "schema_version",
  "score",
] as const;
const DIMENSION_KEYS = [
  "coverage_honesty",
  "delivery_completeness",
  "evidence_use",
  "execution_efficiency",
  "grounding",
  "human_burden",
  "intervention_fit",
  "latency_budget",
  "outcome_closure",
] as const satisfies readonly (keyof AssistantTurnEvaluationDimensionsV1)[];
const RECEIPT_KEYS = [
  "evaluated_head_digest",
  "evaluator_ref",
  "ordered_row_digests",
  "receipt_digest",
  "schema_version",
] as const;

export class ImprovementEvaluationSetReceiptError extends Error {}

/** Validate evaluator-owned rows before trusting their receipt integrity. */
export function validateImprovementOutcomeEvaluationSet(
  value: ImprovementOutcomeEvaluationSetV1,
): void {
  assertStrictPlainData(
    value,
    "evaluation set",
    new WeakSet<object>(),
    0,
    { remaining: MAXIMUM_PLAIN_DATA_NODES },
  );
  assertExactKeys(value, ["evaluations", "receipt"], "evaluation set");
  assertDenseArray(value.evaluations, "evaluation rows", 1, MAXIMUM_EVALUATIONS);
  assertExactKeys(value.receipt, RECEIPT_KEYS, "evaluation receipt");

  const receipt = value.receipt;
  assertDigest(receipt.evaluated_head_digest, "evaluated head");
  assertOpaqueReference(receipt.evaluator_ref, "evaluator");
  if (receipt.schema_version !== EVALUATION_SET_RECEIPT_SCHEMA) {
    throw new ImprovementEvaluationSetReceiptError(
      "The evaluation set receipt version is unsupported.",
    );
  }
  assertDenseArray(
    receipt.ordered_row_digests,
    "ordered row digests",
    value.evaluations.length,
    value.evaluations.length,
  );
  for (const rowDigest of receipt.ordered_row_digests) {
    assertDigest(rowDigest, "evaluation row");
  }

  const orderedRowDigests = value.evaluations.map((evaluation) => {
    validateEvaluation(evaluation, receipt.evaluator_ref);
    return evaluationRowDigest(evaluation);
  });
  if (
    orderedRowDigests.some(
      (rowDigest, index) => rowDigest !== receipt.ordered_row_digests[index],
    )
  ) {
    throw new ImprovementEvaluationSetReceiptError(
      "The evaluation set receipt rows changed.",
    );
  }
  const { receipt_digest: receiptDigest, ...receiptContent } = receipt;
  assertDigest(receiptDigest, "evaluation receipt");
  if (receiptDigest !== evaluationSetReceiptDigest(receiptContent)) {
    throw new ImprovementEvaluationSetReceiptError(
      "The evaluation set receipt integrity is invalid.",
    );
  }
}

function validateEvaluation(
  evaluation: AssistantTurnEvaluationV1,
  evaluatorRef: string,
): void {
  assertExactKeys(evaluation, EVALUATION_KEYS, "evaluation row");
  assertDenseArray(
    evaluation.blockers,
    "evaluation blockers",
    0,
    ASSISTANT_TURN_EVALUATION_BLOCKERS.length,
  );
  if (
    new Set(evaluation.blockers).size !== evaluation.blockers.length ||
    evaluation.blockers.some(
      (blocker) => !ASSISTANT_TURN_EVALUATION_BLOCKERS.includes(blocker),
    )
  ) {
    throw new ImprovementEvaluationSetReceiptError(
      "The evaluation blockers must be distinct supported values.",
    );
  }
  assertDigest(evaluation.case_digest, "case");
  assertOpaqueReference(evaluation.case_ref, "case");
  assertExactKeys(evaluation.dimensions, DIMENSION_KEYS, "evaluation dimensions");
  for (const key of DIMENSION_KEYS) assertUnitInterval(evaluation.dimensions[key], key);
  if (evaluation.evaluator_ref !== evaluatorRef) {
    throw new ImprovementEvaluationSetReceiptError(
      "The evaluation set receipt evaluator identity changed.",
    );
  }
  assertOpaqueReference(evaluation.evaluator_ref, "evaluator");
  assertDigest(evaluation.observation_digest, "observation");
  assertOpaqueReference(evaluation.observation_ref, "observation");
  if (evaluation.partition !== "held_out" && evaluation.partition !== "shadow") {
    throw new ImprovementEvaluationSetReceiptError(
      "The evaluation partition is unsupported for promotion.",
    );
  }
  if (typeof evaluation.passed !== "boolean") {
    throw new ImprovementEvaluationSetReceiptError(
      "The evaluation pass state must be boolean.",
    );
  }
  assertOpaqueReference(evaluation.policy_ref, "policy");
  if (evaluation.schema_version !== "assistant-turn-evaluation/v1") {
    throw new ImprovementEvaluationSetReceiptError(
      "The evaluation row version is unsupported.",
    );
  }
  assertUnitInterval(evaluation.score, "score");
}

function evaluationRowDigest(evaluation: AssistantTurnEvaluationV1): string {
  return sha256(canonicalStringify(evaluation));
}

function evaluationSetReceiptDigest(
  receipt: Omit<ImprovementOutcomeEvaluationSetReceiptV1, "receipt_digest">,
): string {
  return sha256(JSON.stringify([
    receipt.schema_version,
    receipt.evaluated_head_digest,
    receipt.evaluator_ref,
    receipt.ordered_row_digests,
  ]));
}

function assertStrictPlainData(
  value: unknown,
  label: string,
  ancestors: WeakSet<object>,
  depth: number,
  budget: { remaining: number },
): void {
  budget.remaining -= 1;
  if (depth > MAXIMUM_PLAIN_DATA_DEPTH || budget.remaining < 0) {
    throw new ImprovementEvaluationSetReceiptError(
      `The ${label} exceeds the plain-data complexity bound.`,
    );
  }
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) return;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new ImprovementEvaluationSetReceiptError(
        `The ${label} contains a non-finite number.`,
      );
    }
    return;
  }
  if (typeof value !== "object") {
    throw new ImprovementEvaluationSetReceiptError(
      `The ${label} contains a non-data value.`,
    );
  }
  if (ancestors.has(value)) {
    throw new ImprovementEvaluationSetReceiptError(`The ${label} contains a cycle.`);
  }
  ancestors.add(value);
  if (Array.isArray(value)) {
    assertDenseArray(value, label, 0, MAXIMUM_EVALUATIONS);
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
        throw new ImprovementEvaluationSetReceiptError(
          `The ${label} contains an accessor or hidden array value.`,
        );
      }
      assertStrictPlainData(descriptor.value, label, ancestors, depth + 1, budget);
    }
  } else {
    if (Object.getPrototypeOf(value) !== Object.prototype) {
      throw new ImprovementEvaluationSetReceiptError(
        `The ${label} contains a non-plain object.`,
      );
    }
    const keys = Reflect.ownKeys(value);
    if (keys.length > MAXIMUM_OBJECT_FIELDS || keys.some((key) => typeof key !== "string")) {
      throw new ImprovementEvaluationSetReceiptError(
        `The ${label} object fields are invalid or unbounded.`,
      );
    }
    for (const key of keys as string[]) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
        throw new ImprovementEvaluationSetReceiptError(
          `The ${label} contains an accessor or hidden field.`,
        );
      }
      if (descriptor.value === undefined) {
        throw new ImprovementEvaluationSetReceiptError(
          `The ${label} contains an undefined field.`,
        );
      }
      assertStrictPlainData(descriptor.value, label, ancestors, depth + 1, budget);
    }
  }
  ancestors.delete(value);
}

function assertExactKeys(
  value: object,
  expected: readonly string[],
  label: string,
): void {
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== expected.length ||
    keys.some((key) => typeof key !== "string" || !expected.includes(key))
  ) {
    throw new ImprovementEvaluationSetReceiptError(
      `The ${label} must contain exactly the supported fields.`,
    );
  }
}

function assertDenseArray(
  value: readonly unknown[],
  label: string,
  minimum: number,
  maximum: number,
): void {
  if (
    Object.getPrototypeOf(value) !== Array.prototype ||
    !Number.isSafeInteger(value.length) ||
    value.length < minimum ||
    value.length > maximum
  ) {
    throw new ImprovementEvaluationSetReceiptError(`The ${label} is invalid or unbounded.`);
  }
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== value.length + 1 ||
    keys.some((key) => (
      typeof key !== "string" ||
      (key !== "length" && (!/^(0|[1-9][0-9]*)$/.test(key) || Number(key) >= value.length))
    ))
  ) {
    throw new ImprovementEvaluationSetReceiptError(
      `The ${label} must be a dense array without extra fields.`,
    );
  }
}

function assertDigest(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || !SHA256_DIGEST_PATTERN.test(value)) {
    throw new ImprovementEvaluationSetReceiptError(
      `The ${label} digest must use sha256.`,
    );
  }
}

function assertOpaqueReference(value: unknown, label: string): asserts value is string {
  if (
    typeof value !== "string" ||
    Buffer.byteLength(value, "utf8") > MAXIMUM_REFERENCE_BYTES ||
    !OPAQUE_REFERENCE_PATTERN.test(value)
  ) {
    throw new ImprovementEvaluationSetReceiptError(
      `The ${label} reference must be opaque and bounded.`,
    );
  }
}

function assertUnitInterval(value: unknown, label: string): asserts value is number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > 1) {
    throw new ImprovementEvaluationSetReceiptError(
      `The evaluation ${label} must be between zero and one.`,
    );
  }
}

function canonicalStringify(value: unknown): string {
  if (Array.isArray(value)) {
    const rows: string[] = [];
    for (let index = 0; index < value.length; index += 1) {
      rows.push(canonicalStringify(value[index]));
    }
    return `[${rows.join(",")}]`;
  }
  if (value !== null && typeof value === "object") {
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => (
      `${JSON.stringify(key)}:${canonicalStringify((value as Record<string, unknown>)[key])}`
    )).join(",")}}`;
  }
  const serialized = JSON.stringify(value);
  if (serialized === undefined) {
    throw new ImprovementEvaluationSetReceiptError(
      "The evaluation set contains a non-canonical value.",
    );
  }
  return serialized;
}

function sha256(value: string): string {
  return `sha256:${createHash("sha256").update(value, "utf8").digest("hex")}`;
}
