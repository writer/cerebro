import { createHash } from "node:crypto";
import type { AssistantTurnEvaluationV1 } from "../assistant-turn/evaluation.js";
import type {
  ImprovementOutcomeEvaluationSetReceiptV1,
  ImprovementOutcomeEvaluationSetV1,
} from "./contracts.js";

const EVALUATION_SET_RECEIPT_SCHEMA =
  "improvement-outcome-evaluation-set-receipt/v1" as const;
const SHA256_DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/;

export class ImprovementEvaluationSetReceiptError extends Error {}

/** Seal an evaluator's exact ordered rows to the source head that produced them. */
export function sealImprovementOutcomeEvaluationSet(
  evaluatedHeadDigest: string,
  evaluations: readonly AssistantTurnEvaluationV1[],
): ImprovementOutcomeEvaluationSetV1 {
  if (!SHA256_DIGEST_PATTERN.test(evaluatedHeadDigest)) {
    throw new ImprovementEvaluationSetReceiptError(
      "The evaluated head must be a sha256 digest.",
    );
  }
  const evaluatorRef = evaluations[0]?.evaluator_ref;
  if (evaluatorRef === undefined || !evaluatorRef.trim()) {
    throw new ImprovementEvaluationSetReceiptError(
      "The evaluation set requires an evaluator identity.",
    );
  }
  if (evaluations.some((evaluation) => evaluation.evaluator_ref !== evaluatorRef)) {
    throw new ImprovementEvaluationSetReceiptError(
      "The evaluation set must use one evaluator identity.",
    );
  }
  const orderedRowDigests = evaluations.map(evaluationRowDigest);
  const receiptContent = {
    evaluated_head_digest: evaluatedHeadDigest,
    evaluator_ref: evaluatorRef,
    ordered_row_digests: orderedRowDigests,
    schema_version: EVALUATION_SET_RECEIPT_SCHEMA,
  };
  return {
    evaluations: structuredClone(evaluations),
    receipt: {
      ...receiptContent,
      receipt_digest: evaluationSetReceiptDigest(receiptContent),
    },
  };
}

/** Verify the seal without accepting any unsealed outer head or evaluator label. */
export function validateImprovementOutcomeEvaluationSet(
  value: ImprovementOutcomeEvaluationSetV1,
): void {
  const receipt = value.receipt;
  if (
    receipt.schema_version !== EVALUATION_SET_RECEIPT_SCHEMA ||
    !SHA256_DIGEST_PATTERN.test(receipt.evaluated_head_digest) ||
    !receipt.evaluator_ref.trim() ||
    receipt.ordered_row_digests.length !== value.evaluations.length ||
    receipt.ordered_row_digests.some((rowDigest) => !SHA256_DIGEST_PATTERN.test(rowDigest))
  ) {
    throw new ImprovementEvaluationSetReceiptError(
      "The evaluation set receipt fields are invalid.",
    );
  }
  const orderedRowDigests = value.evaluations.map((evaluation) => {
    if (evaluation.evaluator_ref !== receipt.evaluator_ref) {
      throw new ImprovementEvaluationSetReceiptError(
        "The evaluation set receipt evaluator identity changed.",
      );
    }
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
  if (
    !SHA256_DIGEST_PATTERN.test(receiptDigest) ||
    receiptDigest !== evaluationSetReceiptDigest(receiptContent)
  ) {
    throw new ImprovementEvaluationSetReceiptError(
      "The evaluation set receipt integrity is invalid.",
    );
  }
}

function evaluationRowDigest(evaluation: AssistantTurnEvaluationV1): string {
  return sha256(stableStringify(evaluation));
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

function sha256(value: string): string {
  return `sha256:${createHash("sha256").update(value, "utf8").digest("hex")}`;
}

function stableStringify(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(",")}]`;
  }
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .filter(([, nested]) => nested !== undefined)
      .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
      .map(([key, nested]) => `${JSON.stringify(key)}:${stableStringify(nested)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}
