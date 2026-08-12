import assert from "node:assert/strict";
import test from "node:test";

import {
  decideAgentGymPromotionVerdict,
  digestAgentGymJson,
  issueAgentGymPromotionAuthorization,
  validateAgentGymPromotionAuthorization,
  validateAgentGymPromotionVerdict,
  type AgentGymPromotionInputReceiptV1,
} from "../src/index.js";

test("promotion verdicts deterministically preserve eligible evidence", () => {
  const verdict = decideAgentGymPromotionVerdict(promotionInput(), {
    decided_at: "2026-08-12T11:10:00.000Z",
    decision_ref: "agent-gym-promotion-verdict://nightly/one",
  });
  assert.equal(verdict.disposition, "promote");
  assert.deepEqual(verdict.reason_codes, ["comparison.eligible"]);
  assert.deepEqual(validateAgentGymPromotionVerdict(verdict), verdict);
});

test("promotion verdicts cannot rewrite policy blockers", () => {
  const input = promotionInput({
    blocker_codes: ["comparison.slice_regression"],
    eligible: false,
  });
  const verdict = decideAgentGymPromotionVerdict(input, {
    decided_at: "2026-08-12T11:10:00.000Z",
    decision_ref: "agent-gym-promotion-verdict://nightly/blocked",
  });
  assert.equal(verdict.disposition, "blocked");
  assert.deepEqual(verdict.reason_codes, ["comparison.slice_regression"]);
  assert.throws(() => validateAgentGymPromotionVerdict({
    ...verdict,
    disposition: "promote",
  }), /promotion verdict is invalid/u);
});

test("promotion authorization is separate, scoped, and expiring", () => {
  const authorization = issueAgentGymPromotionAuthorization(promotionVerdict(), {
    authorization_ref: "agent-gym-promotion-authorization://nightly/one",
    authority_ref: "agent-gym-authority://release/default",
    expires_at: "2026-08-12T12:11:00.000Z",
    issued_at: "2026-08-12T11:11:00.000Z",
    issued_by_ref: "agent-gym-actor://release/controller",
    outcome: "authorized",
    reason_codes: ["release.policy_satisfied"],
  });
  assert.equal(authorization.permission, "activate_candidate");
  assert.equal(authorization.outcome, "authorized");
  assert.deepEqual(validateAgentGymPromotionAuthorization(authorization), authorization);
});

test("blocked verdicts cannot receive activation authority", () => {
  const blocked = decideAgentGymPromotionVerdict(promotionInput({
    blocker_codes: ["comparison.slice_regression"],
    eligible: false,
  }), {
    decided_at: "2026-08-12T11:10:00.000Z",
    decision_ref: "agent-gym-promotion-verdict://nightly/blocked-authorization",
  });
  assert.throws(() => issueAgentGymPromotionAuthorization(blocked, {
    authorization_ref: "agent-gym-promotion-authorization://nightly/blocked",
    authority_ref: "agent-gym-authority://release/default",
    expires_at: "2026-08-12T12:11:00.000Z",
    issued_at: "2026-08-12T11:11:00.000Z",
    issued_by_ref: "agent-gym-actor://release/controller",
    outcome: "authorized",
    reason_codes: ["release.policy_satisfied"],
  }), /promotion authorization is invalid/u);
});

function promotionVerdict() {
  return decideAgentGymPromotionVerdict(promotionInput(), {
    decided_at: "2026-08-12T11:10:00.000Z",
    decision_ref: "agent-gym-promotion-verdict://nightly/one",
  });
}

function promotionInput(
  overrides: Partial<AgentGymPromotionInputReceiptV1> = {},
): AgentGymPromotionInputReceiptV1 {
  const body = {
    baseline_candidate_ref: "agent-gym-candidate://nightly/baseline",
    blocker_codes: [],
    candidate_ref: "agent-gym-candidate://nightly/challenger",
    case_delta_report_digest: digest("a"),
    eligible: true,
    evaluated_at: "2026-08-12T11:09:00.000Z",
    pair_digest: digest("b"),
    policy_digest: digest("c"),
    policy_ref: "agent-gym-promotion-input-policy://nightly/default",
    schema_version: "agent-gym-promotion-input-receipt/v1" as const,
    slice_report_digest: digest("e"),
    uncertainty_digest: digest("f"),
    ...overrides,
  };
  return { ...body, receipt_digest: digestAgentGymJson(body) };
}

function digest(character: string): string {
  return `sha256:${character.repeat(64)}`;
}
