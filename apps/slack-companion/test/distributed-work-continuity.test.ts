import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { describe, test } from "node:test";
import type {
  CapabilityRequirement,
  RunReceiptV1,
} from "@writer/cerebro-sdk";
import {
  DistributedWorkCoordinator,
} from "../src/distributed/coordinator.js";
import type {
  DistributedWorkCompletionInput,
} from "../src/distributed/coordinator.js";
import {
  DISTRIBUTED_WORK_OBSERVATION_SCHEMA_VERSION,
  DISTRIBUTED_WORK_PACKET_SCHEMA_VERSION,
} from "../src/distributed/contracts.js";
import type {
  DistributedWorkPacketIdentityInput,
  DistributedWorkPacketV1,
  RuntimeToolObservationV1,
} from "../src/distributed/contracts.js";
import type {
  DistributedWorkAdmissionCommit,
  DistributedWorkAdmissionResult,
  DistributedWorkReceiptCommit,
  DistributedWorkReceiptCommitResult,
  DurableDistributedWorkPort,
} from "../src/distributed/ports.js";
import {
  ReferenceMemoryDistributedWorkStore,
  StaleDistributedWorkerError,
} from "../src/distributed/reference-store.js";
import {
  distributedWorkIntentDigest,
  distributedWorkPacketIdentity,
  runtimeToolObservationIdentity,
} from "../src/distributed/validation.js";
import { ExecutionCoordinator } from "../src/execution/coordinator.js";

const ADMITTED_AT = "2026-07-16T12:00:00.000Z";

describe("distributed work continuity", () => {
  test("permits transport acknowledgement only after packet, run, and queue commit", async () => {
    const clock = new MutableClock("2026-07-16T12:00:01.000Z");
    const durable = new ReferenceMemoryDistributedWorkStore();
    const gated = new GatedDistributedWorkPort(durable);
    const coordinator = coordinatorFor(clock, durable, gated);
    const packet = packetFixture();

    gated.holdAdmission();
    let acknowledged = false;
    const pending = coordinator.admit(packet).then((result) => {
      acknowledged = result.acknowledgement_permitted;
      return result;
    });
    await Promise.resolve();

    assert.equal(acknowledged, false);
    assert.equal(await durable.readPacket(packet.packet_id), undefined);
    assert.equal(durable.hasRunnableRun(packet.child_run.run_id), false);

    gated.releaseAdmission();
    const result = await pending;
    assert.equal(result.acknowledgement_permitted, true);
    assert.equal(result.duplicate, false);
    assert.equal(durable.hasRunnableRun(packet.child_run.run_id), true);
    assert.equal(durable.readRun(packet.child_run.run_id)?.state, "queued");

    const duplicate = await coordinator.admit(structuredClone(packet));
    assert.equal(duplicate.duplicate, true);
    assert.equal(duplicate.run_id, packet.child_run.run_id);
  });

  test("hands off through a fenced lease and resumes only from the durable checkpoint", async () => {
    const clock = new MutableClock("2026-07-16T12:00:01.000Z");
    const durable = new ReferenceMemoryDistributedWorkStore();
    const gated = new GatedDistributedWorkPort(durable);
    const coordinator = coordinatorFor(clock, durable, gated);
    const packet = packetFixture();
    await coordinator.admit(packet);

    const first = await coordinator.start(packet.packet_id, {
      generation: 1,
      lease_token: "lease-token-generation-1",
      owner_id: "worker-generation-1",
      service_state: "ready",
    });
    assert.notEqual(first.status, "not_runnable");
    if (first.status === "not_runnable") return;
    assert.equal(first.status, "started");
    assert.equal(first.session.checkpoint, undefined);

    clock.set("2026-07-16T12:00:02.000Z");
    const paused = await coordinator.pauseForHandoff(
      packet.packet_id,
      first.session,
      {
        checkpoint_id: "distributed-checkpoint-1",
        completed_step_ids: ["step-1"],
        effect_receipt_ids: [],
        payload_digest: digest("checkpoint-state"),
        payload_ref: "checkpoint-payload://opaque/1",
        resume_cursor: "step-2",
        sequence: 1,
      },
    );
    assert.equal(paused.checkpoint.resume_cursor, "step-2");
    assert.equal(durable.hasRunnableRun(packet.child_run.run_id), true);

    await assert.rejects(
      coordinator.complete(
        packet.packet_id,
        first.session,
        completionInput(packet, "2026-07-16T12:00:02.500Z"),
      ),
      StaleDistributedWorkerError,
    );
    await assert.rejects(
      coordinator.start(packet.packet_id, {
        generation: 1,
        lease_token: "different-token-same-generation",
        owner_id: "different-worker-same-generation",
        service_state: "ready",
      }),
      StaleDistributedWorkerError,
    );

    clock.set("2026-07-16T12:00:03.000Z");
    const resumed = await coordinator.start(packet.packet_id, {
      generation: 2,
      lease_token: "lease-token-generation-2",
      owner_id: "worker-generation-2",
      service_state: "ready",
    });
    assert.notEqual(resumed.status, "not_runnable");
    if (resumed.status === "not_runnable") return;
    assert.equal(resumed.status, "resumed");
    assert.equal(resumed.packet.packet_id, packet.packet_id);
    assert.equal(resumed.packet.correlation_id, packet.correlation_id);
    assert.equal(resumed.packet.idempotency_key, packet.idempotency_key);
    assert.equal(resumed.session.run.run_id, packet.child_run.run_id);
    assert.equal(resumed.session.checkpoint?.payload_ref, paused.checkpoint.payload_ref);
    assert.equal(resumed.session.checkpoint?.resume_cursor, "step-2");
    assert.equal(resumed.session.lease.owner_id, "worker-generation-2");
    assert.equal(resumed.session.lease.generation, 2);
    assert.ok(
      resumed.session.lease.fencing_token > first.session.lease.fencing_token,
    );

    clock.set("2026-07-16T12:00:04.000Z");
    const completion = completionInput(packet, clock.now().toISOString());
    gated.holdReceipt();
    let acknowledged = false;
    const pending = coordinator
      .complete(packet.packet_id, resumed.session, completion)
      .then((result) => {
        acknowledged = result.acknowledgement_permitted;
        return result;
      });
    await Promise.resolve();

    assert.equal(acknowledged, false);
    assert.equal(await durable.readReceipt(packet.packet_id), undefined);
    gated.releaseReceipt();
    const completed = await pending;

    assert.equal(completed.acknowledgement_permitted, true);
    assert.equal(completed.duplicate, false);
    assert.equal(completed.receipt.failed_observation_count, 1);
    assert.equal(completed.receipt.completed_observation_count, 1);
    assert.equal(completed.receipt.runtime_observations[0]?.status, "failed");
    assert.equal(completed.receipt.runtime_observations[1]?.status, "completed");
    assert.equal(durable.readRun(packet.child_run.run_id)?.state, "completed");
    assert.equal(durable.hasRunnableRun(packet.child_run.run_id), false);

    const retry = await coordinator.complete(
      packet.packet_id,
      resumed.session,
      structuredClone(completion),
    );
    assert.equal(retry.duplicate, true);
    assert.equal(retry.receipt.receipt_id, completed.receipt.receipt_id);
  });
});

function coordinatorFor(
  clock: MutableClock,
  durable: ReferenceMemoryDistributedWorkStore,
  distributed: DurableDistributedWorkPort,
): DistributedWorkCoordinator {
  return new DistributedWorkCoordinator({
    execution: new ExecutionCoordinator({
      clock,
      lease_duration_ms: 60_000,
      store: durable,
    }),
    store: distributed,
  });
}

class MutableClock {
  private instant: Date;

  constructor(value: string) {
    this.instant = new Date(value);
  }

  now(): Date {
    return new Date(this.instant);
  }

  set(value: string): void {
    this.instant = new Date(value);
  }
}

class GatedDistributedWorkPort implements DurableDistributedWorkPort {
  private admissionGate?: Deferred;
  private receiptGate?: Deferred;

  constructor(private readonly delegate: DurableDistributedWorkPort) {}

  holdAdmission(): void {
    this.admissionGate = deferred();
  }

  releaseAdmission(): void {
    this.admissionGate?.resolve();
    this.admissionGate = undefined;
  }

  holdReceipt(): void {
    this.receiptGate = deferred();
  }

  releaseReceipt(): void {
    this.receiptGate?.resolve();
    this.receiptGate = undefined;
  }

  async admitAndEnqueue(
    commit: DistributedWorkAdmissionCommit,
  ): Promise<DistributedWorkAdmissionResult> {
    await this.admissionGate?.promise;
    return this.delegate.admitAndEnqueue(commit);
  }

  readPacket(packetId: string): Promise<DistributedWorkPacketV1 | undefined> {
    return this.delegate.readPacket(packetId);
  }

  readReceipt(packetId: string) {
    return this.delegate.readReceipt(packetId);
  }

  async commitReceipt(
    commit: DistributedWorkReceiptCommit,
  ): Promise<DistributedWorkReceiptCommitResult> {
    await this.receiptGate?.promise;
    return this.delegate.commitReceipt(commit);
  }
}

interface Deferred {
  promise: Promise<void>;
  resolve(): void;
}

function deferred(): Deferred {
  let resolve = (): void => undefined;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

function completionInput(
  packet: DistributedWorkPacketV1,
  recordedAt: string,
): DistributedWorkCompletionInput {
  return {
    checkpoint_refs: ["checkpoint://opaque/1"],
    outcome_digest: digest("distributed-outcome"),
    outcome_ref: "distributed-outcome://opaque/1",
    recorded_at: recordedAt,
    runtime_observations: [
      runtimeObservation(packet, 1, "failed"),
      runtimeObservation(packet, 2, "completed"),
    ],
    runtime_status: "completed",
  };
}

function runtimeObservation(
  packet: DistributedWorkPacketV1,
  sequence: number,
  status: "completed" | "failed",
): RuntimeToolObservationV1 {
  const toolRef = "capability-tool://knowledge-read/1";
  const common = {
    attempt: sequence,
    capability_id: "knowledge.read",
    capability_version: "v1",
    completed_at: "2026-07-16T12:00:03.500Z",
    observation_id: runtimeToolObservationIdentity(
      packet.packet_id,
      toolRef,
      sequence,
    ),
    schema_version: DISTRIBUTED_WORK_OBSERVATION_SCHEMA_VERSION,
    sequence,
    started_at: "2026-07-16T12:00:03.000Z",
    tool_ref: toolRef,
  };
  if (status === "failed") {
    return {
      ...common,
      failure_digest: digest("failed-observation"),
      failure_ref: "tool-failure://opaque/1",
      status,
    };
  }
  return {
    ...common,
    result_digest: digest("completed-observation"),
    result_ref: "tool-result://opaque/2",
    status,
  };
}

function packetFixture(): DistributedWorkPacketV1 {
  const input: DistributedWorkPacketIdentityInput = {
    causation_id: "turn-admission-1",
    child_run_kind: "triage",
    correlation_id: "turn-correlation-1",
    deliverables: [
      {
        deliverable_id: "deliverable-1",
        requirement_digest: digest("deliverable-1"),
        requirement_ref: "deliverable-requirement://opaque/1",
        sequence: 1,
      },
    ],
    idempotency_key: "distributed-work-idempotency-1",
    objective_digest: digest("objective"),
    objective_ref: "work-objective://opaque/1",
    parent_run_id: "parent-run-1",
    parent_subject_ref: "parent-subject-1",
    required_capabilities: capabilities(),
    retention_policy_ref: "retention-policy://standard/1",
    tenant_id: "tenant-opaque-1",
    thread_ref: "thread-binding://opaque/1",
    turn_ref: "turn-receipt://opaque/1",
  };
  const packetId = distributedWorkPacketIdentity(input);
  const intentDigest = distributedWorkIntentDigest(input);
  return {
    ...structuredClone(input),
    child_run: runReceipt(input, packetId, intentDigest),
    created_at: ADMITTED_AT,
    intent_digest: intentDigest,
    packet_id: packetId,
    schema_version: DISTRIBUTED_WORK_PACKET_SCHEMA_VERSION,
  };
}

function runReceipt(
  input: DistributedWorkPacketIdentityInput,
  packetId: string,
  intentDigest: string,
): RunReceiptV1 {
  return {
    admitted_at: ADMITTED_AT,
    binding_id: "binding-opaque-1",
    idempotency_key: input.idempotency_key,
    input_digest: intentDigest,
    receipt_id: "run-receipt-1",
    received_at: ADMITTED_AT,
    required_capabilities: structuredClone(input.required_capabilities),
    retention_policy_ref: input.retention_policy_ref,
    revision: 2,
    run_id: "child-run-1",
    run_kind: input.child_run_kind,
    schema_version: "run-receipt/v1",
    state: "queued",
    subject_ref: packetId,
    tenant_id: input.tenant_id,
    updated_at: ADMITTED_AT,
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

function digest(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}
