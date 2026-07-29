import { describe, expect, it } from "vitest";

import {
  actionStateIntent,
  actionStateLabel,
  actionTimeLabel,
  summarizeActionPage,
  type ActionOperation,
  type ActionState,
} from "./actions";

const operation = (state: ActionState): ActionOperation => ({
  proposal: {
    operation_id: `operation:${state}`,
    tenant_id: "tenant:one",
    finding_id: "finding:one",
    finding_revision_digest: "a".repeat(64),
    finding_validation_receipt_digest: "b".repeat(64),
    graph_revision: 1,
    action_kind: "revoke_access",
    action_definition_digest: "c".repeat(64),
    target_id: "grant:one",
    expected_effects: [],
    rollback_ref: "rollback:one",
    idempotency_key: `idempotency:${state}`,
    simulation_digest: "d".repeat(64),
    verification_plan_digest: "e".repeat(64),
    proposed_by: "operator:one",
    proposed_at_unix_ms: 1,
    proposal_expires_at_unix_ms: 2,
    proposal_digest: "f".repeat(64),
  },
  state,
  version: 1,
  verification_state: "pending",
});

describe("Action UI state", () => {
  it("uses the exact authority state for labels and intent", () => {
    expect(actionStateLabel("waiting_for_approval")).toBe("Waiting For Approval");
    expect(actionStateIntent("verified")).toBe("success");
    expect(actionStateIntent("outcome_unknown")).toBe("danger");
    expect(actionStateIntent("waiting_for_approval")).toBe("warning");
  });

  it("summarizes only the operations in the current bounded page", () => {
    expect(summarizeActionPage([
      operation("waiting_for_approval"),
      operation("executing"),
      operation("dispatched"),
      operation("outcome_unknown"),
      operation("verified"),
      operation("failed"),
      operation("rolled_back"),
    ])).toEqual({
      waitingForApproval: 1,
      inExecution: 3,
      verified: 1,
      failedOrRolledBack: 2,
    });
  });

  it("does not render invalid authority timestamps as real dates", () => {
    expect(actionTimeLabel()).toBe("Not recorded");
    expect(actionTimeLabel(0)).toBe("Not recorded");
    expect(actionTimeLabel(Number.MAX_SAFE_INTEGER + 1)).toBe("Not recorded");
  });
});
