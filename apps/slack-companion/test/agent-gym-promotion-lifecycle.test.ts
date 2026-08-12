import assert from "node:assert/strict";
import test from "node:test";

import {
  decideAgentGymPromotionVerdict,
  digestAgentGymJson,
  issueAgentGymPromotionAuthorization,
  planAgentGymCandidateActivation,
  recordAgentGymActivation,
  validateAgentGymActivationPlan,
  validateAgentGymActivationReceipt,
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

test("activation plans bind exact candidates, authority, and canary scope", () => {
  const plan = planAgentGymCandidateActivation(promotionAuthorization(), candidateManifest(), {
    activation_ref: "agent-gym-activation://nightly/one",
    baseline_candidate_ref: "agent-gym-candidate://nightly/baseline",
    initial_traffic_percent: 10,
    mode: "canary",
    planned_at: "2026-08-12T11:12:00.000Z",
    target_ref: "agent-gym-target://slack-companion/default",
  });
  assert.equal(plan.initial_traffic_percent, 10);
  assert.match(plan.idempotency_key, /^sha256:[0-9a-f]{64}$/u);
  assert.deepEqual(validateAgentGymActivationPlan(plan), plan);
});

test("expired authority cannot produce an activation plan", () => {
  assert.throws(() => planAgentGymCandidateActivation(promotionAuthorization(), candidateManifest(), {
    activation_ref: "agent-gym-activation://nightly/expired",
    baseline_candidate_ref: "agent-gym-candidate://nightly/baseline",
    initial_traffic_percent: 100,
    mode: "direct",
    planned_at: "2026-08-12T12:11:00.000Z",
    target_ref: "agent-gym-target://slack-companion/default",
  }), /activation plan is invalid/u);
});

test("activation receipts retain exact observed candidate state", () => {
  const receipt = recordAgentGymActivation(activationPlan(), {
    completed_at: "2026-08-12T11:14:00.000Z",
    executor_ref: "agent-gym-executor://release/default",
    failure_codes: [],
    observed_active_candidate_ref: "agent-gym-candidate://nightly/challenger",
    observed_traffic_percent: 10,
    previous_candidate_ref: "agent-gym-candidate://nightly/baseline",
    receipt_ref: "agent-gym-activation-receipt://nightly/one",
    started_at: "2026-08-12T11:13:00.000Z",
    status: "applied",
  });
  assert.equal(receipt.status, "applied");
  assert.equal(receipt.observed_active_candidate_ref, receipt.candidate_ref);
  assert.deepEqual(validateAgentGymActivationReceipt(receipt), receipt);
});

test("activation receipts reject unobserved success", () => {
  assert.throws(() => recordAgentGymActivation(activationPlan(), {
    completed_at: "2026-08-12T11:14:00.000Z",
    executor_ref: "agent-gym-executor://release/default",
    failure_codes: [],
    observed_active_candidate_ref: "agent-gym-candidate://nightly/baseline",
    observed_traffic_percent: 10,
    previous_candidate_ref: "agent-gym-candidate://nightly/baseline",
    receipt_ref: "agent-gym-activation-receipt://nightly/unobserved",
    started_at: "2026-08-12T11:13:00.000Z",
    status: "applied",
  }), /activation receipt is invalid/u);
});

function activationPlan() {
  return planAgentGymCandidateActivation(promotionAuthorization(), candidateManifest(), {
    activation_ref: "agent-gym-activation://nightly/one",
    baseline_candidate_ref: "agent-gym-candidate://nightly/baseline",
    initial_traffic_percent: 10,
    mode: "canary",
    planned_at: "2026-08-12T11:12:00.000Z",
    target_ref: "agent-gym-target://slack-companion/default",
  });
}

function promotionAuthorization() {
  return issueAgentGymPromotionAuthorization(promotionVerdict(), {
    authorization_ref: "agent-gym-promotion-authorization://nightly/one",
    authority_ref: "agent-gym-authority://release/default",
    expires_at: "2026-08-12T12:11:00.000Z",
    issued_at: "2026-08-12T11:11:00.000Z",
    issued_by_ref: "agent-gym-actor://release/controller",
    outcome: "authorized",
    reason_codes: ["release.policy_satisfied"],
  });
}

function candidateManifest() {
  return {
    candidate_ref: "agent-gym-candidate://nightly/challenger",
    max_output_tokens: 1_024,
    model_id: "us.anthropic.claude-sonnet-4-20250514-v1:0",
    policy_digest: digest("1") as `sha256:${string}`,
    prompt_digest: digest("2") as `sha256:${string}`,
    provider: "aws_bedrock" as const,
    region: "us-east-1",
    schema_version: "agent-gym-candidate-manifest/v1" as const,
    source_revision: "3".repeat(40),
    tool_catalog_digest: digest("4") as `sha256:${string}`,
    tool_ids: ["cerebro.search"],
  };
}

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
