import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { describe, test } from "node:test";
import type {
  CapabilityRequirement,
  RunReceiptV1,
  WorkLeaseV1,
} from "@writer/cerebro-sdk";
import {
  createDistributedWorkReceipt,
  distributedWorkIntentDigest,
  distributedWorkLeaseReference,
  distributedWorkPacketIdentity,
  runtimeToolObservationIdentity,
  validateDistributedWorkPacket,
  validateDistributedWorkReceipt,
  validateDistributedWorkReceiptCommit,
} from "../src/distributed/validation.js";
import {
  DISTRIBUTED_WORK_OBSERVATION_SCHEMA_VERSION,
  DISTRIBUTED_WORK_PACKET_SCHEMA_VERSION,
  DISTRIBUTED_WORK_SUMMARY_SCHEMA_VERSION,
  MAX_DISTRIBUTED_WORK_DELIVERABLES,
} from "../src/distributed/contracts.js";
import type {
  DistributedWorkPacketIdentityInput,
  DistributedWorkPacketV1,
  RuntimeToolObservationV1,
} from "../src/distributed/contracts.js";

const NOW = "2026-07-16T12:00:00.000Z";
const LATER = "2026-07-16T12:01:00.000Z";

describe("topology-neutral distributed work contract", () => {
  test("derives stable packet identity and binds one queued child run", () => {
    const input = identityInput();
    const reversedCapabilities = {
      ...input,
      required_capabilities: [...input.required_capabilities].reverse(),
    };
    assert.equal(
      distributedWorkPacketIdentity(input),
      distributedWorkPacketIdentity(reversedCapabilities),
    );
    assert.equal(
      distributedWorkIntentDigest(input),
      distributedWorkIntentDigest(reversedCapabilities),
    );

    const packet = packetFixture(input);
    assert.doesNotThrow(() => validateDistributedWorkPacket(packet));
    assert.equal(packet.child_run.subject_ref, packet.packet_id);
    assert.equal(packet.child_run.input_digest, packet.intent_digest);
    assert.equal(packet.child_run.state, "queued");
  });

  test("rejects changed intent, raw transport identity, and unbounded deliverables", () => {
    const packet = packetFixture();
    assert.throws(
      () =>
        validateDistributedWorkPacket({
          ...packet,
          objective_ref: "objective://changed",
        }),
      /identity does not match its immutable intent/,
    );
    assert.throws(
      () =>
        distributedWorkPacketIdentity({
          ...identityInput(),
          thread_ref: "1700000000.000100",
        }),
      /thread_ref must be a bounded opaque reference/,
    );
    assert.throws(
      () =>
        distributedWorkPacketIdentity({
          ...identityInput(),
          deliverables: Array.from(
            { length: MAX_DISTRIBUTED_WORK_DELIVERABLES + 1 },
            (_, index) => deliverable(index + 1),
          ),
        }),
      /deliverables must contain between/,
    );
    assert.throws(
      () =>
        validateDistributedWorkPacket({
          ...packet,
          child_run: { ...packet.child_run, run_id: packet.parent_run_id },
        }),
      /child run does not match/,
    );
  });

  test("keeps ordered failed runtime outcomes authoritative over generated summary", () => {
    const packet = packetFixture();
    const failed = failedObservation(packet, 1, 1);
    const recovered = completedObservation(packet, 2, 2);
    const activeLease = leaseFixture(packet.child_run.run_id);
    const receipt = createDistributedWorkReceipt({
      checkpoint_refs: ["checkpoint://distributed-work/2"],
      generated_summary: {
        generated_at: LATER,
        reported_status: "blocked",
        schema_version: DISTRIBUTED_WORK_SUMMARY_SCHEMA_VERSION,
        summary_digest: digest("summary"),
        summary_ref: "generated-summary://distributed-work/1",
      },
      lease_ref: distributedWorkLeaseReference(activeLease),
      outcome_digest: digest("outcome"),
      outcome_ref: "work-outcome://distributed-work/1",
      packet,
      recorded_at: LATER,
      runtime_observations: [failed, recovered],
      runtime_status: "completed",
    });

    assert.equal(receipt.status, "completed");
    assert.equal(receipt.generated_summary?.reported_status, "blocked");
    assert.equal(receipt.failed_observation_count, 1);
    assert.equal(receipt.completed_observation_count, 1);
    assert.deepEqual(receipt.runtime_observations, [failed, recovered]);
    assert.equal(receipt.runtime_observations[0]?.failure_ref, failed.failure_ref);
    assert.equal(receipt.runtime_observations[1]?.status, "completed");

    failed.failure_ref = "failure://mutated-after-commit";
    assert.notEqual(receipt.runtime_observations[0]?.failure_ref, failed.failure_ref);
    assert.doesNotThrow(() => validateDistributedWorkReceipt(packet, receipt));
  });

  test("rejects reordered observations, unauthorized tools, and stale lease linkage", () => {
    const packet = packetFixture();
    const first = failedObservation(packet, 1, 1);
    const second = completedObservation(packet, 2, 2);
    const activeLease = leaseFixture(packet.child_run.run_id);
    assert.throws(
      () =>
        createDistributedWorkReceipt({
          checkpoint_refs: [],
          lease_ref: distributedWorkLeaseReference(activeLease),
          outcome_digest: digest("outcome"),
          outcome_ref: "work-outcome://distributed-work/1",
          packet,
          recorded_at: LATER,
          runtime_observations: [second, first],
          runtime_status: "blocked",
        }),
      /preserve contiguous runtime order/,
    );

    const unauthorized: RuntimeToolObservationV1 = {
      ...first,
      capability_id: "capability.not-authorized",
    };
    assert.throws(
      () =>
        createDistributedWorkReceipt({
          checkpoint_refs: [],
          lease_ref: distributedWorkLeaseReference(activeLease),
          outcome_digest: digest("outcome"),
          outcome_ref: "work-outcome://distributed-work/1",
          packet,
          recorded_at: LATER,
          runtime_observations: [unauthorized],
          runtime_status: "blocked",
        }),
      /capability was not authorized/,
    );

    const receipt = createDistributedWorkReceipt({
      checkpoint_refs: [],
      lease_ref: distributedWorkLeaseReference(activeLease),
      outcome_digest: digest("outcome"),
      outcome_ref: "work-outcome://distributed-work/1",
      packet,
      recorded_at: LATER,
      runtime_observations: [first],
      runtime_status: "blocked",
    });
    const terminalRun: RunReceiptV1 = {
      ...packet.child_run,
      revision: packet.child_run.revision + 1,
      state: "blocked",
      updated_at: receipt.recorded_at,
    };
    assert.doesNotThrow(() =>
      validateDistributedWorkReceiptCommit(packet, {
        expected_run_revision: packet.child_run.revision,
        lease: activeLease,
        receipt,
        terminal_run: terminalRun,
      }),
    );
    assert.throws(
      () =>
        validateDistributedWorkReceiptCommit(packet, {
          expected_run_revision: packet.child_run.revision,
          lease: leaseFixture("run-from-another-packet"),
          receipt,
          terminal_run: terminalRun,
        }),
      /lease does not own the packet child run/,
    );
  });
});

function identityInput(): DistributedWorkPacketIdentityInput {
  return {
    causation_id: "turn-admission-1",
    child_run_kind: "triage",
    correlation_id: "turn-correlation-1",
    deliverables: [deliverable(1), deliverable(2)],
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
}

function packetFixture(
  input: DistributedWorkPacketIdentityInput = identityInput(),
): DistributedWorkPacketV1 {
  const packetId = distributedWorkPacketIdentity(input);
  const intentDigest = distributedWorkIntentDigest(input);
  return {
    ...structuredClone(input),
    child_run: runReceipt(input, packetId, intentDigest),
    created_at: NOW,
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
    admitted_at: NOW,
    binding_id: "binding-opaque-1",
    idempotency_key: input.idempotency_key,
    input_digest: intentDigest,
    receipt_id: "run-receipt-1",
    received_at: NOW,
    required_capabilities: structuredClone(input.required_capabilities),
    retention_policy_ref: input.retention_policy_ref,
    revision: 2,
    run_id: "child-run-1",
    run_kind: input.child_run_kind,
    schema_version: "run-receipt/v1",
    state: "queued",
    subject_ref: packetId,
    tenant_id: input.tenant_id,
    updated_at: NOW,
  };
}

function deliverable(sequence: number) {
  return {
    deliverable_id: `deliverable-${sequence}`,
    requirement_digest: digest(`deliverable-${sequence}`),
    requirement_ref: `deliverable-requirement://opaque/${sequence}`,
    sequence,
  };
}

function capabilities(): CapabilityRequirement[] {
  return [
    {
      capability_id: "knowledge.read",
      level: "required",
      version: "v1",
    },
    {
      capability_id: "graph.read",
      level: "required",
      version: "v1",
    },
  ];
}

function failedObservation(
  packet: DistributedWorkPacketV1,
  sequence: number,
  attempt: number,
): RuntimeToolObservationV1 {
  const toolRef = "capability-tool://knowledge-read/1";
  return {
    attempt,
    capability_id: "knowledge.read",
    capability_version: "v1",
    completed_at: LATER,
    failure_digest: digest(`failure-${attempt}`),
    failure_ref: `tool-failure://opaque/${attempt}`,
    observation_id: runtimeToolObservationIdentity(
      packet.packet_id,
      toolRef,
      attempt,
    ),
    schema_version: DISTRIBUTED_WORK_OBSERVATION_SCHEMA_VERSION,
    sequence,
    started_at: NOW,
    status: "failed",
    tool_ref: toolRef,
  };
}

function completedObservation(
  packet: DistributedWorkPacketV1,
  sequence: number,
  attempt: number,
): RuntimeToolObservationV1 {
  const toolRef = "capability-tool://knowledge-read/1";
  return {
    attempt,
    capability_id: "knowledge.read",
    capability_version: "v1",
    completed_at: LATER,
    observation_id: runtimeToolObservationIdentity(
      packet.packet_id,
      toolRef,
      attempt,
    ),
    result_digest: digest(`result-${attempt}`),
    result_ref: `tool-result://opaque/${attempt}`,
    schema_version: DISTRIBUTED_WORK_OBSERVATION_SCHEMA_VERSION,
    sequence,
    started_at: NOW,
    status: "completed",
    tool_ref: toolRef,
  };
}

function leaseFixture(runId: string): WorkLeaseV1 {
  return {
    fencing_token: 3,
    generation: 2,
    heartbeat_at: NOW,
    lease_expires_at: LATER,
    lease_token: "lease-opaque-1",
    owner_id: "worker-opaque-1",
    run_id: runId,
    schema_version: "work-lease/v1",
  };
}

function digest(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}
