import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { describe, test } from "node:test";

import type {
  RiskAttestationDecisionKindV1,
  RiskAttestationDecisionReceiptV1,
  RiskAttestationDecisionRequestV1,
  RiskAttestationV1,
} from "../src/risk-attestation/contracts.js";
import { RISK_ATTESTATION_LIMITS } from "../src/risk-attestation/contracts.js";
import {
  createRiskAttestation,
  decideRiskAttestation,
  RiskAttestationPolicyError,
  riskAttestationDecisionIdentity,
  riskAttestationDecisionReceiptIdentity,
} from "../src/risk-attestation/policy.js";

function attestation() {
  return createRiskAttestation({
    created_at: "2030-01-02T03:04:05.000Z",
    request_key: "attestation-request-1",
    schema_version: "create-risk-attestation-input/v1",
    subject_ref: "subject:sample-1",
  });
}

function receiptDigest(
  receipt: Omit<RiskAttestationDecisionReceiptV1, "receipt_digest">,
): string {
  const from = receipt.from_attestation;
  const to = receipt.attestation;
  const values = [
    receipt.schema_version,
    receipt.receipt_id,
    receipt.request_digest,
    receipt.decision_id,
    receipt.decision_key,
    receipt.decision,
    receipt.from_attestation_digest,
    String(receipt.from_revision),
    receipt.from_state,
    String(receipt.from_state_sequence),
    String(receipt.to_revision),
    receipt.to_state,
    String(receipt.to_state_sequence),
    from.schema_version,
    from.attestation_id,
    from.subject_ref,
    from.request_key,
    from.created_at,
    from.updated_at,
    String(from.revision),
    String(from.state_sequence),
    from.state,
    from.last_decision_id ?? "",
    to.schema_version,
    to.attestation_id,
    to.subject_ref,
    to.request_key,
    to.created_at,
    to.updated_at,
    String(to.revision),
    String(to.state_sequence),
    to.state,
    to.last_decision_id ?? "",
  ];
  return `sha256:${createHash("sha256").update(JSON.stringify(values), "utf8").digest("hex")}`;
}

function decision(
  kind: RiskAttestationDecisionKindV1 = "accept",
  overrides: Partial<RiskAttestationDecisionRequestV1> = {},
): RiskAttestationDecisionRequestV1 {
  return {
    actor_ref: "actor:sample-1",
    decided_at: "2030-01-02T03:05:05.000Z",
    decision: kind,
    decision_key: `decision-${kind}-1`,
    expected_revision: 1,
    rationale_ref: "rationale:sample-1",
    schema_version: "risk-attestation-decision-request/v1",
    ...overrides,
  };
}

function missingLookup(current: RiskAttestationV1, request: RiskAttestationDecisionRequestV1) {
  const decisionId = riskAttestationDecisionIdentity(current.attestation_id, request.decision_key);
  return {
    found: false as const,
    receipt_id: riskAttestationDecisionReceiptIdentity(decisionId),
    schema_version: "risk-attestation-decision-receipt-lookup/v1" as const,
  };
}

describe("risk attestation lifecycle decisions", () => {
  test("creates a stable immutable pending attestation", () => {
    const first = attestation();
    assert.deepEqual(attestation(), first);
    assert.equal(first.state, "pending");
    assert.equal(first.revision, 1);
    assert.equal(first.state_sequence, 0);
    assert.match(first.attestation_id, /^risk-attestation:[a-f0-9]{32}$/);
    assert.equal(Object.isFrozen(first), true);
  });

  test("applies and exactly replays one durable transition", () => {
    const current = attestation();
    const request = decision();
    const applied = decideRiskAttestation(current, request, missingLookup(current, request));
    assert.equal(applied.applied, true);
    if (!applied.applied) assert.fail("expected applied decision");
    assert.equal(applied.replayed, false);
    assert.equal(applied.receipt.from_state, "pending");
    assert.equal(applied.receipt.to_state, "accepted");
    assert.equal(applied.receipt.from_revision, 1);
    assert.equal(applied.receipt.to_revision, 2);
    assert.equal(applied.receipt.from_state_sequence, 0);
    assert.equal(applied.receipt.to_state_sequence, 1);
    assert.deepEqual(applied.receipt.from_attestation, current);
    assert.match(applied.receipt.from_attestation_digest, /^sha256:[a-f0-9]{64}$/);
    assert.equal(applied.receipt.attestation.revision, 2);
    assert.match(applied.receipt.receipt_digest, /^sha256:[a-f0-9]{64}$/);
    assert.equal(Object.isFrozen(applied.receipt.attestation), true);

    const replayFromPreState = decideRiskAttestation(current, request, {
      found: true,
      receipt: applied.receipt,
      schema_version: "risk-attestation-decision-receipt-lookup/v1",
    });
    assert.equal(replayFromPreState.applied, true);
    if (!replayFromPreState.applied) assert.fail("expected replayed decision");
    assert.equal(replayFromPreState.replayed, true);
    assert.deepEqual(replayFromPreState.receipt, applied.receipt);

    const replayFromPostState = decideRiskAttestation(applied.receipt.attestation, request, {
      found: true,
      receipt: applied.receipt,
      schema_version: "risk-attestation-decision-receipt-lookup/v1",
    });
    assert.equal(replayFromPostState.applied, true);
    if (!replayFromPostState.applied) assert.fail("expected replayed decision");
    assert.equal(replayFromPostState.replayed, true);
  });

  test("rejects changed retries and receipt tampering", () => {
    const current = attestation();
    const request = decision();
    const applied = decideRiskAttestation(current, request, missingLookup(current, request));
    assert.equal(applied.applied, true);
    if (!applied.applied) assert.fail("expected applied decision");
    const changed = { ...request, rationale_ref: "rationale:changed" };
    assert.deepEqual(decideRiskAttestation(applied.receipt.attestation, changed, {
      found: true,
      receipt: applied.receipt,
      schema_version: "risk-attestation-decision-receipt-lookup/v1",
    }), {
      applied: false,
      reason_code: "idempotency_conflict",
      receipt_ref: applied.receipt.receipt_id,
      replayed: false,
      schema_version: "risk-attestation-decision-result/v1",
    });
    assert.throws(() => decideRiskAttestation(applied.receipt.attestation, request, {
      found: true,
      receipt: {
        ...applied.receipt,
        attestation: { ...applied.receipt.attestation, updated_at: "2030-01-02T03:06:05.000Z" },
      },
      schema_version: "risk-attestation-decision-receipt-lookup/v1",
    }), /receipt digest/);
  });

  test("rejects a recomputed receipt with a legal but false pre-state", () => {
    const current = attestation();
    const request = decision("expire");
    const applied = decideRiskAttestation(current, request, missingLookup(current, request));
    assert.equal(applied.applied, true);
    if (!applied.applied) assert.fail("expected applied decision");
    const withoutDigest = {
      ...applied.receipt,
      from_state: "accepted" as const,
    };
    const tampered = {
      ...withoutDigest,
      receipt_digest: receiptDigest(withoutDigest),
    };
    assert.throws(() => decideRiskAttestation(current, request, {
      found: true,
      receipt: tampered,
      schema_version: "risk-attestation-decision-receipt-lookup/v1",
    }), /state boundary/);
  });

  test("rejects an old receipt after the attestation advances again", () => {
    const current = attestation();
    const accept = decision("accept");
    const accepted = decideRiskAttestation(current, accept, missingLookup(current, accept));
    assert.equal(accepted.applied, true);
    if (!accepted.applied) assert.fail("expected accepted decision");
    const expire = decision("expire", {
      decided_at: "2030-01-02T03:06:05.000Z",
      decision_key: "decision-expire-2",
      expected_revision: 2,
    });
    const expired = decideRiskAttestation(
      accepted.receipt.attestation,
      expire,
      missingLookup(accepted.receipt.attestation, expire),
    );
    assert.equal(expired.applied, true);
    if (!expired.applied) assert.fail("expected expired decision");
    assert.throws(() => decideRiskAttestation(expired.receipt.attestation, accept, {
      found: true,
      receipt: accepted.receipt,
      schema_version: "risk-attestation-decision-receipt-lookup/v1",
    }), /does not match the current state/);
  });

  test("enforces the explicit state transition table", () => {
    for (const kind of ["reject", "expire", "withdraw"] as const) {
      const current = attestation();
      const request = decision(kind);
      const result = decideRiskAttestation(current, request, missingLookup(current, request));
      assert.equal(result.applied, true);
    }

    const current = attestation();
    const accept = decision();
    const accepted = decideRiskAttestation(current, accept, missingLookup(current, accept));
    assert.equal(accepted.applied, true);
    if (!accepted.applied) assert.fail("expected accepted attestation");
    const rejectedAfterAccept = decision("reject", {
      decided_at: "2030-01-02T03:06:05.000Z",
      expected_revision: 2,
    });
    assert.throws(() => decideRiskAttestation(
      accepted.receipt.attestation,
      rejectedAfterAccept,
      missingLookup(accepted.receipt.attestation, rejectedAfterAccept),
    ), /invalid for its state/);
  });

  test("rejects stale revisions, noncanonical time, and UTF-8 overflow", () => {
    const current = attestation();
    const stale = decision("accept", { expected_revision: 2 });
    assert.throws(() => decideRiskAttestation(
      current,
      stale,
      missingLookup(current, stale),
    ), /revision changed/);
    const noncanonical = decision("accept", { decided_at: "2030-01-02T03:05:05Z" });
    assert.throws(() => decideRiskAttestation(
      current,
      noncanonical,
      missingLookup(current, noncanonical),
    ), /canonical timestamp/);
    const overflow = decision("accept", {
      decision_key: "é".repeat(RISK_ATTESTATION_LIMITS.decision_key_utf8_bytes / 2 + 1),
    });
    assert.throws(() => riskAttestationDecisionIdentity(current.attestation_id, overflow.decision_key), /invalid/);
  });

  test("rejects every non-plain top-level and nested record", () => {
    const invalidRecords = [null, [], 7, () => undefined, new Date()];
    const current = attestation();
    const request = decision();
    for (const invalid of invalidRecords) {
      assert.throws(
        () => createRiskAttestation(invalid as never),
        RiskAttestationPolicyError,
      );
      assert.throws(
        () => decideRiskAttestation(invalid as never, request, missingLookup(current, request)),
        RiskAttestationPolicyError,
      );
      assert.throws(
        () => decideRiskAttestation(current, invalid as never, missingLookup(current, request)),
        RiskAttestationPolicyError,
      );
      assert.throws(
        () => decideRiskAttestation(current, request, invalid as never),
        RiskAttestationPolicyError,
      );
      assert.throws(
        () => decideRiskAttestation(current, request, {
          found: true,
          receipt: invalid,
          schema_version: "risk-attestation-decision-receipt-lookup/v1",
        } as never),
        RiskAttestationPolicyError,
      );
    }
  });
});
