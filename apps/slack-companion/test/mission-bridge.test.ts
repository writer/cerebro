import assert from "node:assert/strict";
import { describe, test } from "node:test";
import type { RunReceiptV1 } from "@writer/cerebro-sdk";
import { ExecutionCoordinator } from "../src/execution/coordinator.js";
import type {
  ExecutionSession,
  ServiceAvailabilityState,
} from "../src/execution/model.js";
import { ReferenceMemoryExecutionStore } from "../src/execution/reference-store.js";
import {
  MissionBridgeCoordinator,
  MissionBridgeInvariantError,
} from "../src/mission/coordinator.js";
import type {
  MissionDecisionProjectionV1,
  MissionPlanProjectionV1,
  MissionVerificationProjectionV1,
} from "../src/mission/model.js";

describe("MissionBridgeCoordinator", () => {
  test("projects missing inputs and capability bindings to explicit waits", () => {
    const fixture = makeFixture();

    assert.deepEqual(
      fixture.bridge.readiness(plan(), {
        capability_bindings: [],
        missing_input_refs: ["input-request://scope"],
      }),
      {
        kind: "missing_input",
        status: "waiting",
        waiting_on_ref: "input-request://scope",
      },
    );
    assert.deepEqual(
      fixture.bridge.readiness(plan(), {
        capability_bindings: [],
        missing_input_refs: [],
      }),
      {
        kind: "missing_tool_binding",
        status: "waiting",
        waiting_on_ref: "capability://bounded-action/v1",
      },
    );
    assert.deepEqual(
      fixture.bridge.readiness(plan(), {
        capability_bindings: [capabilityBinding("bound")],
        missing_input_refs: [],
      }),
      { status: "ready" },
    );
  });

  test("waits durably and resumes from the mission checkpoint", async () => {
    const fixture = makeFixture();
    const session = await fixture.session();

    const waiting = await fixture.bridge.wait(session, plan(), {
      checkpoint_id: "checkpoint-wait-1",
      completed_step_ids: [],
      effect_receipt_ids: [],
      kind: "missing_input",
      sequence: 1,
      state_receipt: receipt("mission-state://wait-1", "sha256:wait-1"),
      waiting_on_ref: "input-request://scope",
    });

    assert.equal(waiting.run.state, "waiting");
    assert.equal(waiting.checkpoint.waiting_on_ref, "input-request://scope");
    assert.equal(waiting.checkpoint.payload_digest, "sha256:wait-1");
    assert.notEqual(waiting.run.state, "completed");

    const resumed = await fixture.start("ready", 2, "executor-b", "lease-b");
    if (resumed.status === "not_runnable") {
      assert.fail("expected a waiting mission run to resume");
    }
    assert.equal(resumed.status, "resumed");
    assert.equal(resumed.session.run.state, "running");
    assert.equal(resumed.session.checkpoint?.checkpoint_id, "checkpoint-wait-1");
    assert.equal(resumed.session.lease.generation, 2);
  });

  test("keeps drain pause resumable instead of reporting completion", async () => {
    const fixture = makeFixture();
    const session = await fixture.session();

    const paused = await fixture.bridge.pauseForDrain(session, plan(), {
      checkpoint_id: "checkpoint-drain-1",
      completed_step_ids: [],
      effect_receipt_ids: [],
      sequence: 1,
      state_receipt: receipt("mission-state://drain-1", "sha256:drain-1"),
    });

    assert.equal(paused.run.state, "paused");
    assert.notEqual(paused.run.state, "completed");
    const resumed = await fixture.start("ready", 2, "executor-b", "lease-b");
    assert.notEqual(resumed.status, "not_runnable");
  });

  test("requires evidence-backed approval, rollback, and independent verification", async () => {
    const fixture = makeFixture();
    const session = await fixture.session();

    await assert.rejects(
      fixture.bridge.beginEffect(session, plan(), "step-1"),
      MissionBridgeInvariantError,
    );
    await assert.rejects(
      fixture.bridge.beginEffect(
        session,
        plan(),
        "step-1",
        decision("rejected"),
      ),
      MissionBridgeInvariantError,
    );
    await assert.rejects(
      async () =>
        fixture.bridge.beginEffect(session, plan(), "step-1", {
          ...decision("approved"),
          plan_digest: "sha256:another-plan",
        }),
      MissionBridgeInvariantError,
    );

    const planned = await fixture.bridge.beginEffect(
      session,
      plan(),
      "step-1",
      decision("approved"),
    );
    assert.equal(planned.approval_ref, "decision://approval-1");
    assert.equal(planned.rollback_plan_ref, "rollback://step-1");
    assert.equal(planned.request_digest, "sha256:effect-request-1");

    await fixture.bridge.markEffectExecuting(session, plan(), "step-1");
    await assert.rejects(
      async () =>
        fixture.bridge.resolveEffect(session, plan(), "step-1", {
          executor_ref: "actor://executor-a",
          result: receipt("effect-result://step-1", "sha256:effect-result-1"),
          state: "succeeded",
          verification: {
            ...verification(),
            verifier_ref: "actor://executor-a",
          },
        }),
      MissionBridgeInvariantError,
    );
    await assert.rejects(
      async () =>
        fixture.bridge.resolveEffect(session, plan(), "step-1", {
          executor_ref: "actor://executor-a",
          result: receipt("effect-result://step-1", "sha256:effect-result-1"),
          state: "succeeded",
          verification: {
            ...verification(),
            evidence: [
              {
                ...evidence(),
                source_revision: "source-revision-unrelated",
              },
            ],
          },
        }),
      /verification evidence does not prove the observed source revision/,
    );

    const resolved = await fixture.bridge.resolveEffect(
      session,
      plan(),
      "step-1",
      {
        executor_ref: "actor://executor-a",
        result: receipt("effect-result://step-1", "sha256:effect-result-1"),
        state: "succeeded",
        verification: verification(),
      },
    );
    assert.equal(resolved.state, "succeeded");
    assert.equal(resolved.result_digest, "sha256:effect-result-1");
    assert.equal(resolved.verification_receipt_ref, "verification://step-1");
    assert.equal(resolved.verification_state, "verified");
  });

  test("hands off to delivery only after evidence-backed verified closure", async () => {
    const fixture = makeFixture();
    const session = await fixture.session();
    await resolveEffect(fixture, session);

    await assert.rejects(
      fixture.bridge.close(session, plan(), {
        armed_wake_condition_refs: [],
        checkpoint_id: "checkpoint-close-invalid",
        completed_step_ids: ["step-1"],
        desired_condition_verified: true,
        effect_receipt_ids: ["effect-receipt://step-1"],
        executor_ref: "actor://executor-a",
        sequence: 1,
        verification: {
          ...verification(),
          observed_source_revision: "source-revision-1",
        },
      }),
      MissionBridgeInvariantError,
    );

    const closed = await fixture.bridge.close(session, plan(), {
      armed_wake_condition_refs: [],
      checkpoint_id: "checkpoint-close-1",
      completed_step_ids: ["step-1"],
      desired_condition_verified: true,
      effect_receipt_ids: ["effect-receipt://step-1"],
      executor_ref: "actor://executor-a",
      sequence: 1,
      verification: verification(),
    });

    assert.equal(closed.checkpoint.payload_ref, "verification://step-1");
    assert.equal(closed.checkpoint.payload_digest, "sha256:verification-1");
    assert.equal(closed.run.state, "delivering");
    assert.notEqual(closed.run.state, "completed");
  });

  test("rejects a plan that does not match the native contract or run", async () => {
    const fixture = makeFixture();
    const session = await fixture.session();

    await assert.rejects(
      async () =>
        fixture.bridge.wait(
          session,
          { ...plan(), run_id: "run-other" },
          {
            checkpoint_id: "checkpoint-invalid",
            completed_step_ids: [],
            effect_receipt_ids: [],
            kind: "decision_required",
            sequence: 1,
            state_receipt: receipt(
              "mission-state://invalid",
              "sha256:invalid",
            ),
            waiting_on_ref: "decision-request://invalid",
          },
        ),
      MissionBridgeInvariantError,
    );
    assert.throws(
      () =>
        fixture.bridge.readiness(
          {
            ...plan(),
            mission_schema_version: "cerebro.control-kernel.v2" as never,
          },
          { capability_bindings: [], missing_input_refs: [] },
        ),
      MissionBridgeInvariantError,
    );
  });
});

async function resolveEffect(
  fixture: ReturnType<typeof makeFixture>,
  session: ExecutionSession,
): Promise<void> {
  await fixture.bridge.beginEffect(
    session,
    plan(),
    "step-1",
    decision("approved"),
  );
  await fixture.bridge.markEffectExecuting(session, plan(), "step-1");
  await fixture.bridge.resolveEffect(session, plan(), "step-1", {
    executor_ref: "actor://executor-a",
    result: receipt("effect-result://step-1", "sha256:effect-result-1"),
    state: "succeeded",
    verification: verification(),
  });
}

function makeFixture(runId = "run-1") {
  const clock = new FixedClock();
  const store = new ReferenceMemoryExecutionStore();
  store.seedRun(runReceipt(runId));
  const execution = new ExecutionCoordinator({
    clock,
    lease_duration_ms: 30_000,
    store,
  });
  const start = (
    serviceState: ServiceAvailabilityState,
    generation: number,
    ownerId: string,
    leaseToken: string,
  ) =>
    execution.start({
      generation,
      lease_token: leaseToken,
      owner_id: ownerId,
      run_id: runId,
      service_state: serviceState,
    });
  return {
    bridge: new MissionBridgeCoordinator(execution),
    execution,
    session: async (): Promise<ExecutionSession> => {
      const result = await start("ready", 1, "executor-a", "lease-a");
      if (result.status === "not_runnable") {
        throw new Error("fixture run was not runnable");
      }
      return result.session;
    },
    start,
    store,
  };
}

class FixedClock {
  now(): Date {
    return new Date("2026-07-16T12:00:00.000Z");
  }
}

function runReceipt(runId: string): RunReceiptV1 {
  const now = "2026-07-16T11:59:00.000Z";
  return {
    admitted_at: now,
    binding_id: "binding-1",
    idempotency_key: `event:${runId}`,
    input_digest: "sha256:input",
    receipt_id: `receipt-${runId}`,
    received_at: now,
    required_capabilities: [],
    retention_policy_ref: "retention://default",
    revision: 1,
    run_id: runId,
    run_kind: "interactive",
    schema_version: "run-receipt/v1",
    state: "queued",
    subject_ref: "thread://conversation/turn",
    tenant_id: "tenant-1",
    updated_at: now,
  };
}

function plan(): MissionPlanProjectionV1 {
  return {
    mission_contract_id: "native-mission-operating-contract",
    mission_ref: "mission://mission-1",
    mission_revision: 3,
    mission_schema_version: "cerebro.control-kernel.v1",
    plan_digest: "sha256:plan-4",
    plan_ref: "mission-plan://plan-1/revision/4",
    plan_revision: 4,
    run_id: "run-1",
    schema_version: "mission-plan-projection/v1",
    steps: [
      {
        approval_required: true,
        capability_ref: "capability://bounded-action/v1",
        capability_version: "1.0.0",
        effect_id: "effect-1",
        idempotency_key: "mission-1:plan-4:step-1",
        request_digest: "sha256:effect-request-1",
        rollback_plan_ref: "rollback://step-1",
        step_id: "step-1",
        target_ref: "resource://target-1",
      },
    ],
  };
}

function capabilityBinding(state: "bound" | "missing" | "incompatible") {
  return {
    binding_ref: "capability-binding://bounded-action/v1",
    capability_ref: "capability://bounded-action/v1",
    capability_version: "1.0.0",
    state,
  } as const;
}

function receipt(receiptRef: string, receiptDigest: string) {
  return { receipt_digest: receiptDigest, receipt_ref: receiptRef };
}

function evidence() {
  return {
    evidence_digest: "sha256:evidence-1",
    evidence_ref: "evidence://observation-1",
    source_revision: "source-revision-2",
  };
}

function decision(
  value: "approved" | "rejected",
): MissionDecisionProjectionV1 {
  return {
    decision: value,
    evidence: [evidence()],
    mission_ref: "mission://mission-1",
    mission_revision: 3,
    plan_digest: "sha256:plan-4",
    plan_ref: "mission-plan://plan-1/revision/4",
    plan_revision: 4,
    receipt: receipt("decision://approval-1", "sha256:decision-1"),
    schema_version: "mission-decision-projection/v1",
  };
}

function verification(): MissionVerificationProjectionV1 {
  return {
    evidence: [evidence()],
    observed_source_revision: "source-revision-2",
    pre_action_source_revision: "source-revision-1",
    receipt: receipt("verification://step-1", "sha256:verification-1"),
    verifier_ref: "actor://verifier-b",
  };
}
