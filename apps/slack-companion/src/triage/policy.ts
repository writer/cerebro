import type {
  AlertTriageCaseV1,
  AlertTriageDecisionV1,
  AlertTriageStateV1,
  AlertTriageTransitionV1,
  TriageEvidenceGateReasonV1,
  TriageEvidenceGateV1,
  TriageEvidenceReceiptV1,
  TriageEvidenceReplacementV1,
  TriageEvidenceStatusV1,
  TriageSuggestionPlanV1,
  TriageSuggestionPolicyV1,
  TriageSuggestionRequestV1,
  TriageSuggestionStateV1,
  TriageSuggestionV1,
} from "./contracts.js";

const TRIAGE_TRANSITIONS: Readonly<Record<AlertTriageStateV1, readonly AlertTriageStateV1[]>> = {
  awaiting_evidence: ["investigating", "ready_for_decision", "suppressed"],
  closed: [],
  decided: ["suggestion_planned", "published", "suppressed", "needs_reverification", "closed"],
  investigating: ["awaiting_evidence", "ready_for_decision", "suppressed"],
  needs_reverification: ["investigating", "suppressed", "closed"],
  published: ["needs_reverification", "closed"],
  ready_for_decision: ["decided", "needs_reverification", "suppressed"],
  received: ["investigating", "suppressed"],
  suggestion_planned: ["published", "suppressed", "needs_reverification"],
  suppressed: ["closed"],
};

const EVIDENCE_TRANSITIONS: Readonly<Record<TriageEvidenceStatusV1, readonly TriageEvidenceStatusV1[]>> = {
  contradicted: [],
  current: ["expired", "needs_reverification", "contradicted", "inaccessible"],
  expired: ["needs_reverification"],
  inaccessible: ["current", "expired", "needs_reverification"],
  needs_reverification: ["current", "expired", "contradicted", "inaccessible"],
};

const SUGGESTION_TRANSITIONS: Readonly<Record<TriageSuggestionStateV1, readonly TriageSuggestionStateV1[]>> = {
  accepted: [],
  dismissed: [],
  expired: [],
  planned: ["queued", "suppressed", "expired"],
  published: ["accepted", "dismissed", "superseded", "expired"],
  queued: ["published", "suppressed", "expired"],
  superseded: [],
  suppressed: [],
};

export class AlertTriageInvariantError extends Error {}

export function createAlertTriageCase(input: {
  idempotency_key: string;
  received_at: string;
  source_event_ref: string;
  thread_ref: string;
  triage_id: string;
}): AlertTriageCaseV1 {
  requireText(input.triage_id, "triage_id");
  requireText(input.source_event_ref, "source_event_ref");
  requireText(input.thread_ref, "thread_ref");
  requireText(input.idempotency_key, "idempotency_key");
  const receivedAt = requireTimestamp(input.received_at, "received_at");
  return {
    idempotency_key: input.idempotency_key,
    received_at: receivedAt,
    schema_version: "alert-triage-case/v1",
    source_event_ref: input.source_event_ref,
    state: "received",
    state_sequence: 0,
    thread_ref: input.thread_ref,
    triage_id: input.triage_id,
    updated_at: receivedAt,
  };
}

export function advanceAlertTriageCase(
  current: AlertTriageCaseV1,
  toState: AlertTriageStateV1,
  occurredAt: string,
  reasonCode: string,
  refs: { active_suggestion_ref?: string; latest_decision_ref?: string } = {},
): { case_record: AlertTriageCaseV1; transition: AlertTriageTransitionV1 } {
  validateCase(current);
  requireText(reasonCode, "reason_code");
  requireAllowedTransition(TRIAGE_TRANSITIONS, current.state, toState, "triage");
  const normalizedOccurredAt = requireMonotonicTimestamp(occurredAt, current.updated_at, "occurred_at");
  const sequence = current.state_sequence + 1;
  const transition: AlertTriageTransitionV1 = {
    event_id: `${current.triage_id}:transition:${sequence}`,
    from_state: current.state,
    idempotency_key: `${current.idempotency_key}:transition:${sequence}:${toState}`,
    occurred_at: normalizedOccurredAt,
    reason_code: reasonCode,
    schema_version: "alert-triage-transition/v1",
    sequence,
    to_state: toState,
    triage_id: current.triage_id,
  };
  return {
    case_record: {
      ...current,
      ...(refs.active_suggestion_ref === undefined ? {} : { active_suggestion_ref: refs.active_suggestion_ref }),
      ...(refs.latest_decision_ref === undefined ? {} : { latest_decision_ref: refs.latest_decision_ref }),
      state: toState,
      state_sequence: sequence,
      updated_at: normalizedOccurredAt,
    },
    transition,
  };
}

export function advanceTriageEvidence(
  current: TriageEvidenceReceiptV1,
  toStatus: TriageEvidenceStatusV1,
  occurredAt: string,
  reasonCode: string,
  replacement?: TriageEvidenceReplacementV1,
): TriageEvidenceReceiptV1 {
  validateEvidence(current);
  requireText(reasonCode, "reason_code");
  requireAllowedTransition(EVIDENCE_TRANSITIONS, current.status, toStatus, "evidence");
  const normalizedOccurredAt = requireMonotonicTimestamp(occurredAt, current.updated_at, "occurred_at");
  if (toStatus === "current") {
    if (replacement === undefined) {
      throw new AlertTriageInvariantError("Returning evidence to current requires a replacement receipt.");
    }
    if (!Number.isSafeInteger(replacement.version) || replacement.version <= current.version) {
      throw new AlertTriageInvariantError("Replacement evidence version must increase.");
    }
    requireText(replacement.evidence_digest, "evidence_digest");
    const observedAt = requireTimestamp(replacement.observed_at, "observed_at");
    if (Date.parse(observedAt) > Date.parse(normalizedOccurredAt)) {
      throw new AlertTriageInvariantError("Replacement evidence cannot be observed in the future.");
    }
    const validUntil = replacement.valid_until === undefined
      ? undefined
      : requireTimestamp(replacement.valid_until, "valid_until");
    if (validUntil !== undefined && Date.parse(validUntil) <= Date.parse(observedAt)) {
      throw new AlertTriageInvariantError("Replacement evidence must remain valid after it is observed.");
    }
    return {
      ...current,
      evidence_digest: replacement.evidence_digest,
      observed_at: observedAt,
      reason_code: reasonCode,
      state_sequence: current.state_sequence + 1,
      status: toStatus,
      updated_at: normalizedOccurredAt,
      ...(validUntil === undefined ? { valid_until: undefined } : { valid_until: validUntil }),
      version: replacement.version,
    };
  }
  if (replacement !== undefined) {
    throw new AlertTriageInvariantError("Replacement evidence is only valid when returning to current.");
  }
  return {
    ...current,
    reason_code: reasonCode,
    state_sequence: current.state_sequence + 1,
    status: toStatus,
    updated_at: normalizedOccurredAt,
  };
}

export function evaluateTriageEvidence(
  decision: AlertTriageDecisionV1,
  evidence: readonly TriageEvidenceReceiptV1[],
  now: string,
): TriageEvidenceGateV1 {
  validateDecision(decision);
  const normalizedNow = requireTimestamp(now, "now");
  const byRef = new Map<string, TriageEvidenceReceiptV1>();
  for (const receipt of evidence) {
    validateEvidence(receipt);
    if (byRef.has(receipt.receipt_ref)) {
      throw new AlertTriageInvariantError(`Duplicate evidence receipt: ${receipt.receipt_ref}`);
    }
    byRef.set(receipt.receipt_ref, receipt);
  }

  const currentRefs: string[] = [];
  const reasons = new Set<TriageEvidenceGateReasonV1>();
  for (const receiptRef of decision.evidence_receipt_refs) {
    const receipt = byRef.get(receiptRef);
    if (receipt === undefined) {
      reasons.add("evidence_missing");
      continue;
    }
    if (receipt.access !== "allowed") reasons.add("evidence_inaccessible");
    if (receipt.status !== "current") reasons.add("evidence_not_current");
    if (Date.parse(receipt.observed_at) > Date.parse(normalizedNow)) {
      reasons.add("evidence_observed_in_future");
    }
    if (receipt.valid_until !== undefined && Date.parse(receipt.valid_until) <= Date.parse(normalizedNow)) {
      reasons.add("evidence_expired");
    }
    if (
      receipt.access === "allowed" &&
      receipt.status === "current" &&
      Date.parse(receipt.observed_at) <= Date.parse(normalizedNow) &&
      (receipt.valid_until === undefined || Date.parse(receipt.valid_until) > Date.parse(normalizedNow))
    ) {
      currentRefs.push(receiptRef);
    }
  }
  if (decision.classification === "actionable" && currentRefs.length === 0) {
    reasons.add("evidence_missing");
  }
  return {
    current_evidence_receipt_refs: currentRefs,
    passed: reasons.size === 0,
    reason_codes: [...reasons].sort(),
    schema_version: "triage-evidence-gate/v1",
  };
}

export function planTriageSuggestion(
  triageCase: AlertTriageCaseV1,
  decision: AlertTriageDecisionV1,
  evidence: readonly TriageEvidenceReceiptV1[],
  request: TriageSuggestionRequestV1,
  policy: TriageSuggestionPolicyV1,
  now: string,
): TriageSuggestionPlanV1 {
  validateCase(triageCase);
  validateDecision(decision);
  validateSuggestionRequest(request);
  validateSuggestionPolicy(policy);
  const normalizedNow = requireTimestamp(now, "now");
  if (triageCase.triage_id !== decision.triage_id) return suppressed("decision_mismatch");
  if (triageCase.state !== "decided") return suppressed("case_not_decided");
  if (decision.classification !== "actionable") return suppressed("classification_not_actionable");
  if (decision.confidence < policy.minimum_confidence) return suppressed("confidence_below_threshold");
  if (!policy.allowed_kinds.includes(request.kind)) return suppressed("suggestion_kind_not_allowed");

  const evidenceGate = evaluateTriageEvidence(decision, evidence, normalizedNow);
  if (!evidenceGate.passed) return suppressed("evidence_gate_failed", evidenceGate.reason_codes);

  const idempotencyKey = `triage-suggestion:${triageCase.triage_id}:${decision.decision_id}:${request.kind}:${request.action_key}`;
  const expiresAt = new Date(Date.parse(normalizedNow) + policy.ttl_seconds * 1_000).toISOString();
  const suggestion: TriageSuggestionV1 = {
    action: request.action,
    created_at: normalizedNow,
    decision_id: decision.decision_id,
    evidence_receipt_refs: evidenceGate.current_evidence_receipt_refs,
    expires_at: expiresAt,
    idempotency_key: idempotencyKey,
    kind: request.kind,
    schema_version: "triage-suggestion/v1",
    state: "planned",
    state_sequence: 0,
    suggestion_id: idempotencyKey,
    title: request.title,
    triage_id: triageCase.triage_id,
    updated_at: normalizedNow,
  };
  return {
    disposition: "planned",
    schema_version: "triage-suggestion-plan/v1",
    suggestion,
  };
}

export function advanceTriageSuggestion(
  current: TriageSuggestionV1,
  toState: TriageSuggestionStateV1,
  occurredAt: string,
): TriageSuggestionV1 {
  validateSuggestion(current);
  requireAllowedTransition(SUGGESTION_TRANSITIONS, current.state, toState, "suggestion");
  const normalizedOccurredAt = requireMonotonicTimestamp(occurredAt, current.updated_at, "occurred_at");
  return {
    ...current,
    state: toState,
    state_sequence: current.state_sequence + 1,
    updated_at: normalizedOccurredAt,
  };
}

function suppressed(
  reasonCode: Exclude<TriageSuggestionPlanV1, { disposition: "planned" }>["reason_code"],
  evidenceReasonCodes: TriageEvidenceGateReasonV1[] = [],
): TriageSuggestionPlanV1 {
  return {
    disposition: "suppressed",
    evidence_reason_codes: evidenceReasonCodes,
    reason_code: reasonCode,
    schema_version: "triage-suggestion-plan/v1",
  };
}

function validateCase(value: AlertTriageCaseV1): void {
  if (value.schema_version !== "alert-triage-case/v1") {
    throw new AlertTriageInvariantError("Unsupported alert triage case version.");
  }
  requireText(value.triage_id, "triage_id");
  requireText(value.idempotency_key, "idempotency_key");
  requireNonNegativeInteger(value.state_sequence, "state_sequence");
  requireTimestamp(value.received_at, "received_at");
  requireTimestamp(value.updated_at, "updated_at");
}

function validateDecision(value: AlertTriageDecisionV1): void {
  if (value.schema_version !== "alert-triage-decision/v1") {
    throw new AlertTriageInvariantError("Unsupported alert triage decision version.");
  }
  requireText(value.decision_id, "decision_id");
  requireText(value.triage_id, "triage_id");
  requireText(value.summary, "summary");
  requireTimestamp(value.decided_at, "decided_at");
  if (!Number.isFinite(value.confidence) || value.confidence < 0 || value.confidence > 1) {
    throw new AlertTriageInvariantError("confidence must be between zero and one.");
  }
  requireUniqueTexts(value.evidence_receipt_refs, "evidence_receipt_refs");
  requireUniqueTexts(value.recommended_actions, "recommended_actions");
  if (value.classification === "actionable" && value.recommended_actions.length === 0) {
    throw new AlertTriageInvariantError("Actionable decisions require a recommended action.");
  }
}

function validateEvidence(value: TriageEvidenceReceiptV1): void {
  if (value.schema_version !== "triage-evidence-receipt/v1") {
    throw new AlertTriageInvariantError("Unsupported triage evidence receipt version.");
  }
  for (const [label, text] of Object.entries({
    evidence_digest: value.evidence_digest,
    evidence_id: value.evidence_id,
    receipt_ref: value.receipt_ref,
    source_capability: value.source_capability,
    subject_ref: value.subject_ref,
  })) {
    requireText(text, label);
  }
  requirePositiveInteger(value.version, "version");
  requireNonNegativeInteger(value.state_sequence, "state_sequence");
  const observedAt = requireTimestamp(value.observed_at, "observed_at");
  requireTimestamp(value.updated_at, "updated_at");
  if (value.valid_until !== undefined) {
    const validUntil = requireTimestamp(value.valid_until, "valid_until");
    if (Date.parse(validUntil) <= Date.parse(observedAt)) {
      throw new AlertTriageInvariantError("valid_until must be after observed_at.");
    }
  }
}

function validateSuggestionPolicy(value: TriageSuggestionPolicyV1): void {
  if (value.schema_version !== "triage-suggestion-policy/v1") {
    throw new AlertTriageInvariantError("Unsupported triage suggestion policy version.");
  }
  if (!Number.isFinite(value.minimum_confidence) || value.minimum_confidence < 0 || value.minimum_confidence > 1) {
    throw new AlertTriageInvariantError("minimum_confidence must be between zero and one.");
  }
  requirePositiveInteger(value.ttl_seconds, "ttl_seconds");
  if (new Set(value.allowed_kinds).size !== value.allowed_kinds.length) {
    throw new AlertTriageInvariantError("allowed_kinds must be unique.");
  }
}

function validateSuggestionRequest(value: TriageSuggestionRequestV1): void {
  requireText(value.title, "title");
  requireText(value.action, "action");
  if (!/^[a-z0-9][a-z0-9._:-]{0,127}$/.test(value.action_key)) {
    throw new AlertTriageInvariantError("action_key must be a stable lowercase token.");
  }
}

function validateSuggestion(value: TriageSuggestionV1): void {
  if (value.schema_version !== "triage-suggestion/v1") {
    throw new AlertTriageInvariantError("Unsupported triage suggestion version.");
  }
  requireText(value.suggestion_id, "suggestion_id");
  requireNonNegativeInteger(value.state_sequence, "state_sequence");
  requireTimestamp(value.created_at, "created_at");
  requireTimestamp(value.updated_at, "updated_at");
  requireTimestamp(value.expires_at, "expires_at");
}

function requireAllowedTransition<T extends string>(
  transitions: Readonly<Record<T, readonly T[]>>,
  from: T,
  to: T,
  machine: string,
): void {
  if (!transitions[from]?.includes(to)) {
    throw new AlertTriageInvariantError(`Invalid ${machine} transition: ${from} -> ${to}.`);
  }
}

function requireTimestamp(value: string, label: string): string {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) {
    throw new AlertTriageInvariantError(`${label} must be an ISO timestamp.`);
  }
  return new Date(parsed).toISOString();
}

function requireMonotonicTimestamp(value: string, previous: string, label: string): string {
  const normalized = requireTimestamp(value, label);
  if (Date.parse(normalized) < Date.parse(previous)) {
    throw new AlertTriageInvariantError(`${label} cannot move backward.`);
  }
  return normalized;
}

function requireText(value: string, label: string): void {
  if (typeof value !== "string" || !value.trim()) {
    throw new AlertTriageInvariantError(`${label} must be non-empty.`);
  }
}

function requireUniqueTexts(values: readonly string[], label: string): void {
  values.forEach((value) => requireText(value, label));
  if (new Set(values).size !== values.length) {
    throw new AlertTriageInvariantError(`${label} must contain unique values.`);
  }
}

function requirePositiveInteger(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new AlertTriageInvariantError(`${label} must be a positive integer.`);
  }
}

function requireNonNegativeInteger(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new AlertTriageInvariantError(`${label} must be a non-negative integer.`);
  }
}
