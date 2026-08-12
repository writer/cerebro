export interface MemoryRetrievalEvaluationInputV1 {
  readonly available: boolean;
  readonly expected_memory_refs: readonly string[];
  readonly retrieved_memory_refs: readonly string[];
  readonly stale_memory_refs: readonly string[];
}

export interface MemoryRetrievalEvaluationV1 {
  readonly blockers: readonly ("expected_memory_missed" | "stale_memory_retrieved")[];
  readonly evaluated: boolean;
  readonly precision: number | null;
  readonly recall_at_1: number | null;
  readonly recall_at_5: number | null;
  readonly recall_at_10: number | null;
  readonly schema_version: "memory-retrieval-evaluation/v1";
}

export class MemoryRetrievalEvaluationError extends Error {}

/** Scores attributed retrieval references without treating retained memory as current evidence. */
export function evaluateMemoryRetrieval(
  input: MemoryRetrievalEvaluationInputV1,
): MemoryRetrievalEvaluationV1 {
  const expected = uniqueRefs(input.expected_memory_refs, "expected memory");
  const retrieved = uniqueRefs(input.retrieved_memory_refs, "retrieved memory");
  const stale = new Set(uniqueRefs(input.stale_memory_refs, "stale memory"));
  if (!input.available) {
    if (expected.length > 0 || retrieved.length > 0 || stale.size > 0) {
      throw new MemoryRetrievalEvaluationError(
        "Unavailable memory evaluation cannot contain retrieval observations.",
      );
    }
    return Object.freeze({
      blockers: Object.freeze([]), evaluated: false, precision: null,
      recall_at_1: null, recall_at_5: null, recall_at_10: null,
      schema_version: "memory-retrieval-evaluation/v1",
    });
  }
  const expectedSet = new Set(expected);
  const recall = (limit: number): number => expected.length === 0
    ? 1
    : retrieved.slice(0, limit).filter((ref) => expectedSet.has(ref)).length / expected.length;
  const matched = retrieved.filter((ref) => expectedSet.has(ref)).length;
  const blockers: MemoryRetrievalEvaluationV1["blockers"][number][] = [];
  if (recall(10) < 1) blockers.push("expected_memory_missed");
  if (retrieved.some((ref) => stale.has(ref))) blockers.push("stale_memory_retrieved");
  return Object.freeze({
    blockers: Object.freeze(blockers),
    evaluated: true,
    precision: retrieved.length === 0 ? (expected.length === 0 ? 1 : 0) : matched / retrieved.length,
    recall_at_1: recall(1), recall_at_5: recall(5), recall_at_10: recall(10),
    schema_version: "memory-retrieval-evaluation/v1",
  });
}

function uniqueRefs(values: readonly string[], label: string): string[] {
  if (!Array.isArray(values) || values.length > 100 || values.some((value) =>
    typeof value !== "string" || !/^[a-z][a-z0-9+.-]*:\/\/[^\s\u0000-\u001f]{1,500}$/u.test(value)
  )) throw new MemoryRetrievalEvaluationError(`${label} references are invalid.`);
  const unique = [...new Set(values)];
  if (unique.length !== values.length) {
    throw new MemoryRetrievalEvaluationError(`${label} references must be unique.`);
  }
  return unique;
}
