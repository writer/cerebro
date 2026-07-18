import assert from "node:assert/strict";
import { describe, test } from "node:test";
import type {
  AlertTriageDecisionV1,
  TriageEvidenceReceiptV1,
  TriageSuggestionPolicyV1,
} from "../src/triage/contracts.js";
import {
  advanceAlertTriageCase,
  advanceTriageEvidence,
  advanceTriageSuggestion,
  createAlertTriageCase,
  evaluateTriageEvidence,
  planTriageSuggestion,
} from "../src/triage/policy.js";

const receivedAt = "2030-01-02T03:04:05.000Z";
const decidedAt = "2030-01-02T03:07:00.000Z";
const now = "2030-01-02T03:08:00.000Z";

describe("portable alert-triage lifecycle", () => {
  test("emits monotonic machine-specific transition records", () => {
    const received = createAlertTriageCase({
      idempotency_key: "sample-alert-event-1",
      received_at: receivedAt,
      source_event_ref: "event://sample-alert/1",
      thread_ref: "thread://sample/1",
      triage_id: "triage-sample-1",
    });
    const investigating = advanceAlertTriageCase(
      received,
      "investigating",
      "2030-01-02T03:05:00Z",
      "admitted_for_triage",
    );
    const ready = advanceAlertTriageCase(
      investigating.case_record,
      "ready_for_decision",
      "2030-01-02T03:06:00Z",
      "evidence_collected",
    );

    assert.equal(investigating.transition.sequence, 1);
    assert.equal(investigating.transition.from_state, "received");
    assert.equal(investigating.transition.to_state, "investigating");
    assert.equal(
      investigating.transition.idempotency_key,
      "sample-alert-event-1:transition:1:investigating",
    );
    assert.equal(ready.case_record.state_sequence, 2);
    assert.equal(ready.case_record.updated_at, "2030-01-02T03:06:00.000Z");
  });

  test("rejects cross-machine shortcuts and backward transition time", () => {
    const received = createAlertTriageCase({
      idempotency_key: "sample-alert-event-1",
      received_at: receivedAt,
      source_event_ref: "event://sample-alert/1",
      thread_ref: "thread://sample/1",
      triage_id: "triage-sample-1",
    });

    assert.throws(
      () => advanceAlertTriageCase(received, "published", now, "shortcut"),
      /Invalid triage transition/,
    );
    assert.throws(
      () => advanceAlertTriageCase(received, "investigating", "2030-01-02T03:03:00Z", "late_event"),
      /cannot move backward/,
    );
  });
});

describe("triage evidence lifecycle", () => {
  test("requires a newer receipt before evidence becomes current again", () => {
    const current = evidenceReceipt();
    const needsReview = advanceTriageEvidence(
      current,
      "needs_reverification",
      "2030-01-02T03:08:30Z",
      "source_version_changed",
    );

    assert.throws(
      () => advanceTriageEvidence(needsReview, "current", "2030-01-02T03:09:00Z", "rechecked"),
      /requires a replacement receipt/,
    );
    const refreshed = advanceTriageEvidence(
      needsReview,
      "current",
      "2030-01-02T03:09:00Z",
      "rechecked",
      {
        evidence_digest: "sha256:sample-evidence-v2",
        observed_at: "2030-01-02T03:08:50Z",
        valid_until: "2030-01-02T04:08:50Z",
        version: 2,
      },
    );

    assert.equal(refreshed.status, "current");
    assert.equal(refreshed.version, 2);
    assert.equal(refreshed.state_sequence, 2);
    assert.equal(refreshed.evidence_digest, "sha256:sample-evidence-v2");
  });

  test("rejects terminal evidence recovery and stale replacement versions", () => {
    const contradicted = advanceTriageEvidence(
      evidenceReceipt(),
      "contradicted",
      "2030-01-02T03:08:30Z",
      "source_disagrees",
    );
    assert.throws(
      () => advanceTriageEvidence(contradicted, "current", "2030-01-02T03:09:00Z", "rechecked", {
        evidence_digest: "sha256:sample-evidence-v2",
        observed_at: "2030-01-02T03:08:50Z",
        version: 2,
      }),
      /Invalid evidence transition/,
    );

    const needsReview = advanceTriageEvidence(
      evidenceReceipt(),
      "needs_reverification",
      "2030-01-02T03:08:30Z",
      "source_version_changed",
    );
    assert.throws(
      () => advanceTriageEvidence(needsReview, "current", "2030-01-02T03:09:00Z", "rechecked", {
        evidence_digest: "sha256:sample-evidence-v1-again",
        observed_at: "2030-01-02T03:08:50Z",
        version: 1,
      }),
      /version must increase/,
    );
  });

  test("gates actionable decisions on current accessible evidence", () => {
    const decision = actionableDecision();
    assert.deepEqual(evaluateTriageEvidence(decision, [evidenceReceipt()], now), {
      current_evidence_receipt_refs: ["receipt://evidence/sample-1"],
      passed: true,
      reason_codes: [],
      schema_version: "triage-evidence-gate/v1",
    });

    const stale = evidenceReceipt({ valid_until: "2030-01-02T03:07:45Z" });
    const staleGate = evaluateTriageEvidence(decision, [stale], now);
    assert.equal(staleGate.passed, false);
    assert.deepEqual(staleGate.reason_codes, ["evidence_expired", "evidence_missing"]);

    const restricted = evidenceReceipt({ access: "restricted" });
    const restrictedGate = evaluateTriageEvidence(decision, [restricted], now);
    assert.equal(restrictedGate.passed, false);
    assert.deepEqual(restrictedGate.reason_codes, ["evidence_inaccessible", "evidence_missing"]);
  });
});

describe("triage suggestion lifecycle", () => {
  test("plans the same evidence-bound suggestion on retry", () => {
    const triageCase = decidedCase();
    const decision = actionableDecision();
    const first = planTriageSuggestion(
      triageCase,
      decision,
      [evidenceReceipt()],
      suggestionRequest(),
      suggestionPolicy(),
      now,
    );
    const retried = planTriageSuggestion(
      triageCase,
      decision,
      [evidenceReceipt()],
      suggestionRequest(),
      suggestionPolicy(),
      now,
    );

    assert.deepEqual(retried, first);
    assert.equal(first.disposition, "planned");
    if (first.disposition !== "planned") assert.fail("expected a planned suggestion");
    assert.equal(
      first.suggestion.suggestion_id,
      "triage-suggestion:triage-sample-1:decision-sample-1:remediation:review-owner",
    );
    assert.deepEqual(first.suggestion.evidence_receipt_refs, ["receipt://evidence/sample-1"]);
    assert.equal(first.suggestion.expires_at, "2030-01-02T04:08:00.000Z");
  });

  test("suppresses suggestions before planning when decision gates fail", () => {
    const triageCase = decidedCase();
    const lowConfidence = planTriageSuggestion(
      triageCase,
      { ...actionableDecision(), confidence: 0.69 },
      [evidenceReceipt()],
      suggestionRequest(),
      suggestionPolicy(),
      now,
    );
    assert.deepEqual(lowConfidence, {
      disposition: "suppressed",
      evidence_reason_codes: [],
      reason_code: "confidence_below_threshold",
      schema_version: "triage-suggestion-plan/v1",
    });

    const staleEvidence = planTriageSuggestion(
      triageCase,
      actionableDecision(),
      [evidenceReceipt({ status: "needs_reverification" })],
      suggestionRequest(),
      suggestionPolicy(),
      now,
    );
    assert.equal(staleEvidence.disposition, "suppressed");
    if (staleEvidence.disposition !== "suppressed") assert.fail("expected suppression");
    assert.equal(staleEvidence.reason_code, "evidence_gate_failed");
    assert.deepEqual(staleEvidence.evidence_reason_codes, ["evidence_missing", "evidence_not_current"]);
  });

  test("keeps suggestion terminal states terminal", () => {
    const planned = planTriageSuggestion(
      decidedCase(),
      actionableDecision(),
      [evidenceReceipt()],
      suggestionRequest(),
      suggestionPolicy(),
      now,
    );
    if (planned.disposition !== "planned") assert.fail("expected a planned suggestion");
    const queued = advanceTriageSuggestion(planned.suggestion, "queued", "2030-01-02T03:08:10Z");
    const published = advanceTriageSuggestion(queued, "published", "2030-01-02T03:08:20Z");
    const accepted = advanceTriageSuggestion(published, "accepted", "2030-01-02T03:08:30Z");

    assert.equal(accepted.state_sequence, 3);
    assert.throws(
      () => advanceTriageSuggestion(accepted, "queued", "2030-01-02T03:08:40Z"),
      /Invalid suggestion transition/,
    );
  });
});

function decidedCase() {
  const received = createAlertTriageCase({
    idempotency_key: "sample-alert-event-1",
    received_at: receivedAt,
    source_event_ref: "event://sample-alert/1",
    thread_ref: "thread://sample/1",
    triage_id: "triage-sample-1",
  });
  const investigating = advanceAlertTriageCase(received, "investigating", "2030-01-02T03:05:00Z", "admitted");
  const ready = advanceAlertTriageCase(investigating.case_record, "ready_for_decision", "2030-01-02T03:06:00Z", "evidence_collected");
  return advanceAlertTriageCase(
    ready.case_record,
    "decided",
    decidedAt,
    "decision_recorded",
    { latest_decision_ref: "decision://sample/1" },
  ).case_record;
}

function actionableDecision(): AlertTriageDecisionV1 {
  return {
    classification: "actionable",
    confidence: 0.84,
    decided_at: decidedAt,
    decision_id: "decision-sample-1",
    evidence_receipt_refs: ["receipt://evidence/sample-1"],
    recommended_actions: ["Confirm the accountable owner before the next change window."],
    schema_version: "alert-triage-decision/v1",
    severity: "high",
    summary: "A privileged change needs an accountable owner review.",
    triage_id: "triage-sample-1",
  };
}

function evidenceReceipt(
  overrides: Partial<TriageEvidenceReceiptV1> = {},
): TriageEvidenceReceiptV1 {
  return {
    access: "allowed",
    evidence_digest: "sha256:sample-evidence-v1",
    evidence_id: "evidence-sample-1",
    observed_at: "2030-01-02T03:07:30.000Z",
    receipt_ref: "receipt://evidence/sample-1",
    schema_version: "triage-evidence-receipt/v1",
    source_capability: "capability://alert-context/read",
    state_sequence: 0,
    status: "current",
    subject_ref: "subject://sample-service",
    updated_at: "2030-01-02T03:07:30.000Z",
    valid_until: "2030-01-02T04:07:30.000Z",
    version: 1,
    ...overrides,
  };
}

function suggestionPolicy(): TriageSuggestionPolicyV1 {
  return {
    allowed_kinds: ["follow_up", "monitor", "remediation"],
    minimum_confidence: 0.7,
    schema_version: "triage-suggestion-policy/v1",
    ttl_seconds: 3_600,
  };
}

function suggestionRequest() {
  return {
    action: "Confirm the accountable owner before the next change window.",
    action_key: "review-owner",
    kind: "remediation" as const,
    title: "Review accountable ownership",
  };
}
