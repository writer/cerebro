import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { describe, test } from "node:test";
import type {
  CapabilityRequirement,
  CheckpointV1,
  RunReceiptV1,
  WorkLeaseV1,
} from "@writer/cerebro-sdk";
import {
  createDistributedWorkReceipt,
  distributedWorkIntentDigest,
  distributedWorkLeaseReference,
  distributedWorkPacketIdentity,
  runtimeToolObservationIdentity,
} from "../src/distributed/validation.js";
import {
  DISTRIBUTED_WORK_OBSERVATION_SCHEMA_VERSION,
  DISTRIBUTED_WORK_PACKET_SCHEMA_VERSION,
} from "../src/distributed/contracts.js";
import type {
  DistributedWorkPacketIdentityInput,
  DistributedWorkPacketV1,
  RuntimeToolObservationV1,
} from "../src/distributed/contracts.js";
import {
  createRecursiveWorkcellChild,
  createRecursiveWorkcellReconciliation,
  RecursiveWorkcellCoordinator,
  recursiveWorkcellIdentity,
} from "../src/distributed/workcells/coordinator.js";
import { MAX_RECURSIVE_WORKCELL_DEPTH } from "../src/distributed/workcells/contracts.js";
import { ReferenceMemoryRecursiveWorkcellStore } from "../src/distributed/workcells/reference-store.js";

const T0 = "2026-07-16T12:00:00.000Z";
const T1 = "2026-07-16T12:01:00.000Z";
const T2 = "2026-07-16T12:02:00.000Z";
const T3 = "2026-07-16T12:03:00.000Z";
const T4 = "2026-07-16T12:04:00.000Z";
const EXPIRES = "2026-07-16T13:00:00.000Z";

describe("topology-neutral recursive workcells", () => {
  test("derives deterministic child identity and rejects cycles and unbounded depth", () => {
    const parent = parentPacket();
    const child = childPacket(parent, 1);
    const first = createRecursiveWorkcellChild(parent, [], child, 1, T0);
    const second = createRecursiveWorkcellChild(parent, [], child, 1, T0);

    assert.equal(first.workcell_id, second.workcell_id);
    assert.equal(
      first.workcell_id,
      recursiveWorkcellIdentity(parent.packet_id, child.packet_id, 1),
    );
    assert.deepEqual(first.ancestor_packet_ids, [parent.packet_id]);
    assert.throws(
      () =>
        createRecursiveWorkcellChild(
          parent,
          [parent.packet_id],
          child,
          1,
          T0,
        ),
      /lineage contains a cycle/,
    );
    assert.throws(
      () =>
        createRecursiveWorkcellChild(
          parent,
          [opaquePacketId("a"), opaquePacketId("b"), opaquePacketId("c"), opaquePacketId("d")],
          child,
          1,
          T0,
        ),
      /leaves no room for a child/,
    );
  });

  test("treats the exact lease expiration instant as expired", async () => {
    const parent = parentPacket();
    const coordinator = new RecursiveWorkcellCoordinator(
      new ReferenceMemoryRecursiveWorkcellStore(),
    );
    const lease = {
      ...leaseFixture(parent.child_run.run_id, 1, 1, T0),
      lease_expires_at: T0,
    };

    await assert.rejects(
      coordinator.admit(
        {
          admitted_at: T0,
          child_packets: [childPacket(parent, 1)],
          parent_ancestor_packet_ids: [],
          parent_packet: parent,
        },
        lease,
      ),
      /lease is expired/,
    );
  });

  test("derives lineage from durable bindings and rejects truncated depth", async () => {
    const store = new ReferenceMemoryRecursiveWorkcellStore();
    const coordinator = new RecursiveWorkcellCoordinator(store);
    let parent = parentPacket();
    let ancestors: string[] = [];

    for (let depth = 1; depth <= MAX_RECURSIVE_WORKCELL_DEPTH; depth += 1) {
      const child = nestedChildPacket(parent, depth);
      const admitted = await coordinator.admit(
        {
          admitted_at: T0,
          child_packets: [child],
          parent_ancestor_packet_ids: ancestors,
          parent_packet: parent,
        },
        leaseFixture(parent.child_run.run_id, 1, 1, T0),
      );
      assert.equal(admitted.reconciliation.children[0]?.depth, depth);
      ancestors = [...ancestors, parent.packet_id];
      parent = child;
    }

    const overflow = nestedChildPacket(
      parent,
      MAX_RECURSIVE_WORKCELL_DEPTH + 1,
    );
    await assert.rejects(
      coordinator.admit(
        {
          admitted_at: T0,
          child_packets: [overflow],
          parent_ancestor_packet_ids: [],
          parent_packet: parent,
        },
        leaseFixture(parent.child_run.run_id, 1, 1, T0),
      ),
      /ancestry does not match the durable parent binding/,
    );
    const forged = createRecursiveWorkcellReconciliation({
      admitted_at: T0,
      child_packets: [overflow],
      parent_ancestor_packet_ids: [],
      parent_packet: parent,
    });
    await assert.rejects(
      async () =>
        store.admitChildren({
          children: forged.children,
          lease: leaseFixture(parent.child_run.run_id, 1, 1, T0),
          reconciliation: forged,
        }),
      /ancestry does not match the durable parent binding/,
    );
    await assert.rejects(
      coordinator.admit(
        {
          admitted_at: T0,
          child_packets: [overflow],
          parent_ancestor_packet_ids: ancestors,
          parent_packet: parent,
        },
        leaseFixture(parent.child_run.run_id, 1, 1, T0),
      ),
      /leaves no room for a child/,
    );

    const changedParent = structuredClone(parent);
    changedParent.child_run.run_id = "changed-durable-parent-run";
    await assert.rejects(
      coordinator.admit(
        {
          admitted_at: T0,
          child_packets: [
            nestedChildPacket(
              changedParent,
              MAX_RECURSIVE_WORKCELL_DEPTH + 2,
            ),
          ],
          parent_ancestor_packet_ids: ancestors,
          parent_packet: changedParent,
        },
        leaseFixture(changedParent.child_run.run_id, 1, 1, T0),
      ),
      /durable parent identity changed/,
    );

    const unboundParent = nestedChildPacket(parentPacket(), 100);
    const unboundCoordinator = new RecursiveWorkcellCoordinator(
      new ReferenceMemoryRecursiveWorkcellStore(),
    );
    await assert.rejects(
      unboundCoordinator.admit(
        {
          admitted_at: T0,
          child_packets: [nestedChildPacket(unboundParent, 101)],
          parent_ancestor_packet_ids: [],
          parent_packet: unboundParent,
        },
        leaseFixture(unboundParent.child_run.run_id, 1, 1, T0),
      ),
      /durable parent binding does not exist/,
    );
  });

  test("renews active work atomically under the same authority", async () => {
    const { children, coordinator, lease, parent } = await admittedFixture();
    const renewed = {
      ...lease,
      heartbeat_at: T1,
      lease_expires_at: "2026-07-16T14:00:00.000Z",
    };

    await assert.rejects(
      coordinator.claimActiveLease(parent.packet_id, renewed, 2),
      /revision is stale/,
    );

    const claimed = await coordinator.claimActiveLease(
      parent.packet_id,
      renewed,
      1,
    );
    assert.equal(claimed.created, true);
    assert.equal(claimed.reconciliation.revision, 2);

    const retry = await coordinator.claimActiveLease(
      parent.packet_id,
      renewed,
      1,
    );
    assert.equal(retry.created, false);
    assert.equal(retry.reconciliation.revision, 2);

    const progressed = await coordinator.recordProgress(
      parent.packet_id,
      children[0]!.packet_id,
      {
        counterevidence: [],
        idempotency_key: "progress-after-renewal",
        phase: "running",
        recorded_at: T2,
        runtime_observations: [],
        sequence: 1,
      },
      renewed,
      2,
    );
    assert.equal(progressed.reconciliation.revision, 3);
  });

  test("recovers active work only after expiration under a newer fence", async () => {
    const parent = parentPacket();
    const child = childPacket(parent, 1);
    const coordinator = new RecursiveWorkcellCoordinator(
      new ReferenceMemoryRecursiveWorkcellStore(),
    );
    const original = {
      ...leaseFixture(parent.child_run.run_id, 1, 1, T0),
      lease_expires_at: T1,
    };
    await coordinator.admit(
      {
        admitted_at: T0,
        child_packets: [child],
        parent_ancestor_packet_ids: [],
        parent_packet: parent,
      },
      original,
    );

    await assert.rejects(
      coordinator.claimActiveLease(
        parent.packet_id,
        {
          ...leaseFixture(parent.child_run.run_id, 2, 2, T0),
          lease_expires_at: T3,
        },
        1,
      ),
      /requires an expired lease and a newer generation and fence/,
    );
    await assert.rejects(
      coordinator.claimActiveLease(
        parent.packet_id,
        {
          ...original,
          heartbeat_at: T1,
          lease_expires_at: T3,
        },
        1,
      ),
      /lease renewal must advance before expiration/,
    );
    await assert.rejects(
      coordinator.claimActiveLease(
        parent.packet_id,
        {
          ...leaseFixture(parent.child_run.run_id, 2, 1, T1),
          lease_expires_at: T3,
        },
        1,
      ),
      /requires an expired lease and a newer generation and fence/,
    );
    await assert.rejects(
      coordinator.claimActiveLease(
        parent.packet_id,
        {
          ...original,
          heartbeat_at: "2026-07-16T12:00:30.000Z",
          lease_expires_at: T3,
          owner_id: "changed-owner",
        },
        1,
      ),
      /requires an expired lease and a newer generation and fence/,
    );

    const replacement = {
      ...leaseFixture(parent.child_run.run_id, 2, 2, T1),
      lease_expires_at: T3,
    };
    const recovered = await coordinator.claimActiveLease(
      parent.packet_id,
      replacement,
      1,
    );
    assert.equal(recovered.created, true);
    assert.equal(recovered.reconciliation.coordination_state, "active");
    assert.equal(recovered.reconciliation.revision, 2);

    const recoveryRetry = await coordinator.claimActiveLease(
      parent.packet_id,
      replacement,
      1,
    );
    assert.equal(recoveryRetry.created, false);
    assert.equal(recoveryRetry.reconciliation.revision, 2);

    await assert.rejects(
      coordinator.recordProgress(
        parent.packet_id,
        child.packet_id,
        {
          counterevidence: [],
          idempotency_key: "progress-under-stale-owner",
          phase: "running",
          recorded_at: T0,
          runtime_observations: [],
          sequence: 1,
        },
        original,
        2,
      ),
      /generation or fence is stale/,
    );

    const progressed = await coordinator.recordProgress(
      parent.packet_id,
      child.packet_id,
      {
        counterevidence: [],
        idempotency_key: "progress-after-recovery",
        phase: "running",
        recorded_at: T2,
        runtime_observations: [],
        sequence: 1,
      },
      replacement,
      2,
    );
    assert.equal(progressed.reconciliation.revision, 3);
  });

  test("admits the whole child set and keeps progress idempotent under one fence", async () => {
    const { children, coordinator, lease, parent } = await admittedFixture();
    const observation = completedObservation(children[0]!, 1);
    const progress = {
      counterevidence: [counterevidence("first")],
      idempotency_key: "progress-1",
      phase: "running" as const,
      recorded_at: T1,
      runtime_observations: [observation],
      sequence: 1,
    };

    const committed = await coordinator.recordProgress(
      parent.packet_id,
      children[0]!.packet_id,
      progress,
      lease,
      1,
    );
    assert.equal(committed.created, true);
    assert.equal(committed.reconciliation.revision, 2);
    assert.equal(committed.reconciliation.observations.length, 1);
    assert.equal(committed.reconciliation.counterevidence.length, 1);

    observation.result_ref = "result://mutated-after-commit";
    const retry = await coordinator.recordProgress(
      parent.packet_id,
      children[0]!.packet_id,
      {
        ...progress,
        runtime_observations: [completedObservation(children[0]!, 1)],
      },
      lease,
      1,
    );
    assert.equal(retry.created, false);
    assert.equal(retry.reconciliation.revision, 2);
    assert.equal(
      retry.reconciliation.observations[0]?.observation.result_ref,
      "result://opaque/1",
    );

    await assert.rejects(
      coordinator.recordProgress(
        parent.packet_id,
        children[0]!.packet_id,
        {
          counterevidence: [],
          idempotency_key: "progress-stale",
          phase: "running",
          recorded_at: T2,
          runtime_observations: [],
          sequence: 2,
        },
        { ...lease, fencing_token: lease.fencing_token + 1 },
        2,
      ),
      /generation or fence is stale/,
    );
  });

  test("checkpoints durably and resumes only under a newer fence", async () => {
    const { children, coordinator, lease, parent } = await admittedFixture();
    await coordinator.recordProgress(
      parent.packet_id,
      children[0]!.packet_id,
      {
        checkpoint_ref: "checkpoint://child/1",
        counterevidence: [],
        idempotency_key: "checkpoint-progress-1",
        phase: "checkpointed",
        recorded_at: T1,
        runtime_observations: [],
        sequence: 1,
      },
      lease,
      1,
    );

    const checkpoint = checkpointFixture(parent, lease);
    const checkpointed = await coordinator.checkpoint(checkpoint, lease, 2);
    assert.equal(checkpointed.reconciliation.coordination_state, "checkpointed");
    assert.equal(checkpointed.reconciliation.revision, 3);

    await assert.rejects(
      coordinator.claimActiveLease(
        parent.packet_id,
        leaseFixture(parent.child_run.run_id, 2, 2, T3),
        3,
      ),
      /checkpointed recursive workcell ownership must use resume/,
    );

    await assert.rejects(
      coordinator.recordProgress(
        parent.packet_id,
        children[0]!.packet_id,
        {
          counterevidence: [],
          idempotency_key: "progress-before-resume",
          phase: "running",
          recorded_at: T3,
          runtime_observations: [],
          sequence: 2,
        },
        lease,
        3,
      ),
      /must resume before mutation/,
    );
    await assert.rejects(
      async () =>
        coordinator.resume(
          parent.packet_id,
          checkpoint.checkpoint_id,
          {
            ...lease,
            heartbeat_at: T3,
            lease_token: "lease-stale",
            owner_id: "worker-stale",
          },
          T3,
          3,
        ),
      /newer generation-compatible fence/,
    );

    const resumedLease = leaseFixture(parent.child_run.run_id, 2, 2, T3);
    const resumed = await coordinator.resume(
      parent.packet_id,
      checkpoint.checkpoint_id,
      resumedLease,
      T3,
      3,
    );
    assert.equal(resumed.reconciliation.coordination_state, "active");
    assert.equal(resumed.reconciliation.revision, 4);
    assert.equal(resumed.reconciliation.checkpoints.length, 1);
    assert.equal(resumed.reconciliation.resumes.length, 1);

    const retry = await coordinator.resume(
      parent.packet_id,
      checkpoint.checkpoint_id,
      resumedLease,
      T3,
      3,
    );
    assert.equal(retry.created, false);
    assert.equal(retry.reconciliation.revision, 4);
  });

  test("keeps parent truth and evidence under partial completion and child failure", async () => {
    const { children, coordinator, lease, parent } = await admittedFixture();
    const firstObservation = completedObservation(children[0]!, 1);
    await coordinator.recordProgress(
      parent.packet_id,
      children[0]!.packet_id,
      {
        counterevidence: [counterevidence("conflict")],
        idempotency_key: "progress-first",
        phase: "running",
        recorded_at: T1,
        runtime_observations: [firstObservation],
        sequence: 1,
      },
      lease,
      1,
    );

    const firstReceipt = terminalReceipt(
      children[0]!,
      "completed",
      [firstObservation],
      T2,
    );
    const partial = await coordinator.reconcileTerminal(
      parent.packet_id,
      children[0]!.packet_id,
      { counterevidence: [], receipt: firstReceipt },
      lease,
      2,
    );
    assert.equal(partial.reconciliation.state, "partially_completed");
    assert.equal(partial.reconciliation.completed_child_count, 1);
    assert.equal(partial.reconciliation.unresolved_child_count, 1);
    assert.equal(partial.reconciliation.observations.length, 1);
    assert.equal(partial.reconciliation.counterevidence.length, 1);

    const firstRetry = await coordinator.reconcileTerminal(
      parent.packet_id,
      children[0]!.packet_id,
      { counterevidence: [], receipt: firstReceipt },
      lease,
      2,
    );
    assert.equal(firstRetry.created, false);
    assert.equal(firstRetry.reconciliation.revision, 3);

    const failed = failedObservation(children[1]!, 1);
    const blocked = await coordinator.reconcileTerminal(
      parent.packet_id,
      children[1]!.packet_id,
      {
        counterevidence: [counterevidence("second-conflict")],
        receipt: terminalReceipt(children[1]!, "blocked", [failed], T4),
      },
      lease,
      3,
    );
    assert.equal(blocked.reconciliation.state, "blocked");
    assert.equal(blocked.reconciliation.completed_child_count, 1);
    assert.equal(blocked.reconciliation.blocked_child_count, 1);
    assert.equal(blocked.reconciliation.unresolved_child_count, 0);
    assert.equal(blocked.reconciliation.child_receipts.length, 2);
    assert.equal(blocked.reconciliation.observations.length, 2);
    assert.equal(blocked.reconciliation.counterevidence.length, 2);
    assert.equal(
      blocked.reconciliation.observations[1]?.observation.failure_ref,
      "failure://opaque/1",
    );
  });
});

async function admittedFixture() {
  const parent = parentPacket();
  const children = [childPacket(parent, 1), childPacket(parent, 2)];
  const store = new ReferenceMemoryRecursiveWorkcellStore();
  const coordinator = new RecursiveWorkcellCoordinator(store);
  const lease = leaseFixture(parent.child_run.run_id, 1, 1, T0);
  const admission = await coordinator.admit(
    {
      admitted_at: T0,
      child_packets: children,
      parent_ancestor_packet_ids: [],
      parent_packet: parent,
    },
    lease,
  );
  assert.equal(admission.created, true);
  assert.equal(admission.reconciliation.children.length, 2);
  assert.equal(admission.reconciliation.unresolved_child_count, 2);
  return { children, coordinator, lease, parent, store };
}

function parentPacket(): DistributedWorkPacketV1 {
  const input = identityInput({
    idempotency_key: "parent-packet",
    parent_run_id: "root-run",
    parent_subject_ref: "root-subject",
  });
  return packetFixture(input, "parent-coordinator-run");
}

function childPacket(
  parent: DistributedWorkPacketV1,
  sequence: number,
): DistributedWorkPacketV1 {
  const input = identityInput({
    causation_id: parent.child_run.run_id,
    idempotency_key: `child-packet-${sequence}`,
    objective_digest: digest(`child-objective-${sequence}`),
    objective_ref: `work-objective://opaque/child-${sequence}`,
    parent_run_id: parent.child_run.run_id,
    parent_subject_ref: parent.packet_id,
  });
  return packetFixture(input, `child-run-${sequence}`);
}

function nestedChildPacket(
  parent: DistributedWorkPacketV1,
  depth: number,
): DistributedWorkPacketV1 {
  const input = identityInput({
    causation_id: parent.child_run.run_id,
    idempotency_key: `nested-child-packet-${depth}`,
    objective_digest: digest(`nested-child-objective-${depth}`),
    objective_ref: `work-objective://opaque/nested-child-${depth}`,
    parent_run_id: parent.child_run.run_id,
    parent_subject_ref: parent.packet_id,
  });
  return packetFixture(input, `nested-child-run-${depth}`);
}

function identityInput(
  overrides: Partial<DistributedWorkPacketIdentityInput>,
): DistributedWorkPacketIdentityInput {
  return {
    causation_id: "root-causation",
    child_run_kind: "triage",
    correlation_id: "correlation-opaque",
    deliverables: [
      {
        deliverable_id: "deliverable-1",
        requirement_digest: digest("requirement"),
        requirement_ref: "deliverable-requirement://opaque/1",
        sequence: 1,
      },
    ],
    idempotency_key: "packet-idempotency",
    objective_digest: digest("objective"),
    objective_ref: "work-objective://opaque/1",
    parent_run_id: "parent-run",
    parent_subject_ref: "parent-subject",
    required_capabilities: capabilities(),
    retention_policy_ref: "retention-policy://portable/1",
    tenant_id: "tenant-opaque",
    thread_ref: "thread-binding://opaque/1",
    turn_ref: "turn-receipt://opaque/1",
    ...overrides,
  };
}

function packetFixture(
  input: DistributedWorkPacketIdentityInput,
  runId: string,
): DistributedWorkPacketV1 {
  const packetId = distributedWorkPacketIdentity(input);
  const intentDigest = distributedWorkIntentDigest(input);
  return {
    ...structuredClone(input),
    child_run: runReceipt(input, packetId, intentDigest, runId),
    created_at: T0,
    intent_digest: intentDigest,
    packet_id: packetId,
    schema_version: DISTRIBUTED_WORK_PACKET_SCHEMA_VERSION,
  };
}

function runReceipt(
  input: DistributedWorkPacketIdentityInput,
  packetId: string,
  intentDigest: string,
  runId: string,
): RunReceiptV1 {
  return {
    admitted_at: T0,
    binding_id: `binding-${runId}`,
    idempotency_key: input.idempotency_key,
    input_digest: intentDigest,
    receipt_id: `receipt-${runId}`,
    received_at: T0,
    required_capabilities: structuredClone(input.required_capabilities),
    retention_policy_ref: input.retention_policy_ref,
    revision: 2,
    run_id: runId,
    run_kind: input.child_run_kind,
    schema_version: "run-receipt/v1",
    state: "queued",
    subject_ref: packetId,
    tenant_id: input.tenant_id,
    updated_at: T0,
  };
}

function terminalReceipt(
  packet: DistributedWorkPacketV1,
  status: "blocked" | "completed",
  observations: RuntimeToolObservationV1[],
  recordedAt: string,
) {
  const childLease = leaseFixture(packet.child_run.run_id, 1, 1, T1);
  return createDistributedWorkReceipt({
    checkpoint_refs: [],
    lease_ref: distributedWorkLeaseReference(childLease),
    outcome_digest: digest(`outcome-${packet.packet_id}-${status}`),
    outcome_ref: `work-outcome://opaque/${status}`,
    packet,
    recorded_at: recordedAt,
    runtime_observations: observations,
    runtime_status: status,
  });
}

function completedObservation(
  packet: DistributedWorkPacketV1,
  sequence: number,
): RuntimeToolObservationV1 {
  const toolRef = "capability-tool://knowledge-read/1";
  return {
    attempt: sequence,
    capability_id: "knowledge.read",
    capability_version: "v1",
    completed_at: T1,
    observation_id: runtimeToolObservationIdentity(
      packet.packet_id,
      toolRef,
      sequence,
    ),
    result_digest: digest(`result-${sequence}`),
    result_ref: `result://opaque/${sequence}`,
    schema_version: DISTRIBUTED_WORK_OBSERVATION_SCHEMA_VERSION,
    sequence,
    started_at: T0,
    status: "completed",
    tool_ref: toolRef,
  };
}

function failedObservation(
  packet: DistributedWorkPacketV1,
  sequence: number,
): RuntimeToolObservationV1 {
  const toolRef = "capability-tool://knowledge-read/1";
  return {
    attempt: sequence,
    capability_id: "knowledge.read",
    capability_version: "v1",
    completed_at: T4,
    failure_digest: digest(`failure-${sequence}`),
    failure_ref: `failure://opaque/${sequence}`,
    observation_id: runtimeToolObservationIdentity(
      packet.packet_id,
      toolRef,
      sequence,
    ),
    schema_version: DISTRIBUTED_WORK_OBSERVATION_SCHEMA_VERSION,
    sequence,
    started_at: T3,
    status: "failed",
    tool_ref: toolRef,
  };
}

function counterevidence(suffix: string) {
  return {
    claim_ref: `claim://opaque/${suffix}`,
    evidence_digest: digest(`counterevidence-${suffix}`),
    evidence_ref: `evidence://opaque/${suffix}`,
    observed_at: T1,
  };
}

function checkpointFixture(
  parent: DistributedWorkPacketV1,
  lease: WorkLeaseV1,
): CheckpointV1 {
  return {
    checkpoint_id: "parent-checkpoint-1",
    completed_step_ids: ["child-progress-1"],
    created_at: T2,
    effect_receipt_ids: [],
    generation: lease.generation,
    payload_digest: digest("parent-checkpoint"),
    payload_ref: "checkpoint-payload://opaque/parent-1",
    resume_cursor: "child-sequence-1",
    run_id: parent.child_run.run_id,
    run_revision: parent.child_run.revision,
    schema_version: "checkpoint/v1",
    sequence: 1,
  };
}

function leaseFixture(
  runId: string,
  generation: number,
  fencingToken: number,
  heartbeatAt: string,
): WorkLeaseV1 {
  return {
    fencing_token: fencingToken,
    generation,
    heartbeat_at: heartbeatAt,
    lease_expires_at: EXPIRES,
    lease_token: `lease-${generation}-${fencingToken}`,
    owner_id: `worker-${generation}-${fencingToken}`,
    run_id: runId,
    schema_version: "work-lease/v1",
  };
}

function capabilities(): CapabilityRequirement[] {
  return [
    {
      capability_id: "knowledge.read",
      level: "required",
      version: "v1",
    },
  ];
}

function opaquePacketId(seed: string): string {
  return `distributed-work-packet://sha256/${seed.repeat(64)}`;
}

function digest(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}
