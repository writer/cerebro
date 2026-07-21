import type { AssistantTurnOutputV1 } from "./contracts.js";
import { normalizeAssistantTurnOutput } from "./policy.js";

export const ASSISTANT_TURN_SOURCE_GAP_STATES = [
  "not_configured",
  "not_found",
  "timed_out",
  "unauthorized",
  "unavailable",
] as const;

export type AssistantTurnSourceGapStateV1 =
  (typeof ASSISTANT_TURN_SOURCE_GAP_STATES)[number];

export interface AssistantTurnEvidenceReceiptV1 {
  evidence_id: string;
  observed_at: string;
  receipt_digest: string;
  receipt_ref: string;
  source_label: string;
  source_ref: string;
  statement: string;
}

export interface AssistantTurnSourceGapV1 {
  scope: string;
  source_label: string;
  source_ref: string;
  state: AssistantTurnSourceGapStateV1;
}

export interface AssistantTurnEvidenceFallbackInput {
  evidence: readonly AssistantTurnEvidenceReceiptV1[];
  gaps: readonly AssistantTurnSourceGapV1[];
  next_action: string;
}

/**
 * Produces a deterministic answer from already-sanitized evidence statements.
 * Opaque receipts remain out of the user-facing output.
 */
export function buildAssistantTurnEvidenceFallback(
  input: AssistantTurnEvidenceFallbackInput,
): AssistantTurnOutputV1 {
  const evidence = validateEvidence(input.evidence);
  const gaps = validateGaps(input.gaps);
  const nextAction = displayText(input.next_action, "next_action", 600);
  if (evidence.length === 0 && gaps.length === 0) {
    throw new AssistantTurnEvidenceInputError(
      "Evidence fallback requires evidence or an exact source gap",
    );
  }

  const coverageNotice = gaps.length === 0
    ? undefined
    : gaps.map((gap) => `${gap.source_label}: ${gap.scope} (${gap.state.replaceAll("_", " ")}).`).join(" ");
  const answer = evidence.length === 0
    ? undefined
    : evidence.map((receipt) => `- ${receipt.statement}`).join("\n");

  return normalizeAssistantTurnOutput(
    evidence.length === 0
      ? {
          coverage_notice: coverageNotice,
          next_action: nextAction,
          state: "blocked",
        }
      : gaps.length === 0
        ? { answer, next_action: nextAction, state: "answered" }
        : {
            answer,
            coverage_notice: coverageNotice,
            next_action: nextAction,
            state: "partial",
          },
  );
}

function validateEvidence(
  values: readonly AssistantTurnEvidenceReceiptV1[],
): AssistantTurnEvidenceReceiptV1[] {
  if (values.length > 5) {
    throw new AssistantTurnEvidenceInputError("Evidence fallback supports at most five receipts");
  }
  const ids = new Set<string>();
  return values.map((value) => {
    const evidenceId = opaque(value.evidence_id, "evidence_id");
    if (ids.has(evidenceId)) {
      throw new AssistantTurnEvidenceInputError("Evidence ids must be distinct");
    }
    ids.add(evidenceId);
    timestamp(value.observed_at, "observed_at");
    return {
      evidence_id: evidenceId,
      observed_at: value.observed_at,
      receipt_digest: opaque(value.receipt_digest, "receipt_digest"),
      receipt_ref: opaque(value.receipt_ref, "receipt_ref"),
      source_label: displayText(value.source_label, "source_label", 120),
      source_ref: opaque(value.source_ref, "source_ref"),
      statement: displayText(value.statement, "statement", 2_000),
    };
  }).sort((left, right) =>
    left.observed_at.localeCompare(right.observed_at) ||
    left.evidence_id.localeCompare(right.evidence_id)
  );
}

function validateGaps(
  values: readonly AssistantTurnSourceGapV1[],
): AssistantTurnSourceGapV1[] {
  if (values.length > 3) {
    throw new AssistantTurnEvidenceInputError("Evidence fallback supports at most three source gaps");
  }
  const sources = new Set<string>();
  return values.map((value) => {
    const sourceRef = opaque(value.source_ref, "source_ref");
    if (sources.has(sourceRef)) {
      throw new AssistantTurnEvidenceInputError("Source gaps must be distinct");
    }
    sources.add(sourceRef);
    if (!ASSISTANT_TURN_SOURCE_GAP_STATES.includes(value.state)) {
      throw new AssistantTurnEvidenceInputError("Source gap state is unsupported");
    }
    return {
      scope: displayText(value.scope, "scope", 100),
      source_label: displayText(value.source_label, "source_label", 60),
      source_ref: sourceRef,
      state: value.state,
    };
  }).sort((left, right) => left.source_label.localeCompare(right.source_label));
}

function displayText(value: string, label: string, limit: number): string {
  if (
    typeof value !== "string" ||
    value.trim() === "" ||
    Array.from(value).length > limit ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw new AssistantTurnEvidenceInputError(`${label} is invalid`);
  }
  return value.replace(/\s+/g, " ").trim();
}

function opaque(value: string, label: string): string {
  if (typeof value !== "string" || value.trim() === "" || value.length > 2_048) {
    throw new AssistantTurnEvidenceInputError(`${label} is invalid`);
  }
  return value;
}

function timestamp(value: string, label: string): void {
  const milliseconds = Date.parse(value);
  if (
    !Number.isFinite(milliseconds) ||
    new Date(milliseconds).toISOString() !== value
  ) {
    throw new AssistantTurnEvidenceInputError(`${label} must be canonical UTC`);
  }
}

export class AssistantTurnEvidenceInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AssistantTurnEvidenceInputError";
  }
}
