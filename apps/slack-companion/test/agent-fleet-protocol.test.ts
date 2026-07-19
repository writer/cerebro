import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { describe, test } from "node:test";
import type {
  CapabilityRequirement,
  RunReceiptV1,
  WorkLeaseV1,
} from "@writer/cerebro-sdk";
import {
  DISTRIBUTED_WORK_PACKET_SCHEMA_VERSION,
} from "../src/distributed/contracts.js";
import type {
  DistributedWorkPacketIdentityInput,
  DistributedWorkPacketV1,
} from "../src/distributed/contracts.js";
import {
  distributedWorkIntentDigest,
  distributedWorkPacketIdentity,
} from "../src/distributed/validation.js";
import { ReferenceMemoryCapacityStore } from "../src/execution/capacity-reference-store.js";
import type {
  CapacityPermitV1,
  CheckpointV1,
} from "../src/fleet/contracts.js";
import { AGENT_FLEET_PROTOCOL_VERSION } from "../src/fleet/contracts.js";
import {
  AgentFleetCoordinator,
} from "../src/fleet/coordinator.js";
import type {
  AgentFleetMailboxAdmissionCommit,
  AgentFleetMailboxAdmissionResult,
} from "../src/fleet/ports.js";
import {
  AgentFleetIdempotencyConflictError,
  ReferenceMemoryAgentFleetStore,
  StaleAgentFleetMemberError,
} from "../src/fleet/reference-store.js";
import {
  rankCompatibleAgentFleetPeers,
} from "../src/fleet/selection.js";
import {
  AgentFleetContractError,
  agentFleetMessageIdentity,
  createAgentFleetMessage,
  createAgentFleetPayloadReference,
  createAgentFleetResumeReference,
  validateAgentFleetMessage,
} from "../src/fleet/validation.js";
import type {
  AgentFleetMemberV1,
  AgentFleetMessageV1,
  AgentFleetPayloadReferenceV1,
} from "../src/fleet/contracts.js";

const NOW = "2026-07-18T12:00:00.000Z";
const NEXT = "2026-07-18T12:01:00.000Z";
const LATER = "2026-07-18T12:02:00.000Z";
const EXPIRES = "2026-07-18T13:00:00.000Z";

describe("topology-neutral agent fleet protocol", () => {
  test("enforces member lifecycle revisions, generations, and terminal retirement", async () => {
    const store = new ReferenceMemoryAgentFleetStore();
    const initial = member("worker-a", "ready", 1, 1, NOW);
    assert.equal((await store.registerMember(initial)).created, true);
    assert.equal((await store.registerMember(structuredClone(initial))).created, false);

    const refreshed = await store.updateMember({
      expected_revision: 1,
      member: {
        ...transition(initial, "ready", NEXT),
        valid_until: time(120),
      },
    });
    assert.equal(refreshed.state, "ready");
    assert.equal(refreshed.valid_until, time(120));

    await assert.rejects(
      async () =>
        store.updateMember({
          expected_revision: 2,
          member: transition(refreshed, "recovering", LATER),
        }),
      AgentFleetContractError,
    );

    const draining = await store.updateMember({
      expected_revision: 2,
      member: transition(refreshed, "draining", LATER),
    });
    const offline = await store.updateMember({
      expected_revision: 3,
      member: transition(draining, "offline", time(3)),
    });
    await assert.rejects(
      store.updateMember({
        expected_revision: 3,
        member: transition(offline, "retired", time(4)),
      }),
      StaleAgentFleetMemberError,
    );

    const recovering = await store.updateMember({
      expected_revision: 4,
      member: transition(offline, "recovering", time(4), 2),
    });
    assert.equal(recovering.generation, 2);
    assert.equal(recovering.capability_manifest.generation, 2);
    const ready = await store.updateMember({
      expected_revision: 5,
      member: transition(recovering, "ready", time(5)),
    });
    const forcedOffline = await store.updateMember({
      expected_revision: 6,
      member: transition(ready, "offline", time(6)),
    });
    const retired = await store.updateMember({
      expected_revision: 7,
      member: transition(forcedOffline, "retired", time(7)),
    });
    assert.equal(retired.state, "retired");
    await assert.rejects(
      async () =>
        store.updateMember({
          expected_revision: retired.revision,
          member: transition(retired, "recovering", time(8), 3),
        }),
      /retired->recovering is not allowed/,
    );
  });

  test("selects the same compatible ready peer for every candidate order", () => {
    const fixture = mailboxFixture();
    const readyA = member("worker-a", "ready", 1, 1, NOW);
    const readyB = member("worker-b", "ready", 1, 1, NOW);
    const degraded = member("worker-c", "degraded", 1, 1, NOW);
    const offline = member("worker-d", "offline", 1, 1, NOW);
    const missing = member("worker-e", "ready", 1, 1, NOW, []);
    const incompatible = member("worker-f", "ready", 1, 1, NOW, undefined, "v2");

    const first = rankCompatibleAgentFleetPeers({
      candidates: [readyA, degraded, missing, readyB, offline, incompatible],
      message: fixture.message,
      observed_at: NOW,
      packet: fixture.packet,
      sender: fixture.sender,
    });
    const reversed = rankCompatibleAgentFleetPeers({
      candidates: [incompatible, offline, readyB, missing, degraded, readyA],
      message: fixture.message,
      observed_at: NOW,
      packet: fixture.packet,
      sender: fixture.sender,
    });

    assert.deepEqual(
      first.compatible.map((candidate) => candidate.member.member_id),
      reversed.compatible.map((candidate) => candidate.member.member_id),
    );
    assert.deepEqual(
      first.compatible.slice(0, 2).map((candidate) => candidate.member.state),
      ["ready", "ready"],
    );
    assert.equal(first.compatible.at(-1)?.member.member_id, "worker-c");
    assert.ok(
      first.rejected.some(
        (candidate) =>
          candidate.member_id === "worker-e" &&
          candidate.reasons.some((reason) => reason.includes("knowledge.read@v1")),
      ),
    );
    assert.ok(
      first.rejected.some(
        (candidate) =>
          candidate.member_id === "worker-f" &&
          candidate.reasons.includes("contract_version_not_readable"),
      ),
    );
    assert.ok(
      first.rejected.some(
        (candidate) => candidate.member_id === "worker-d",
      ),
    );
  });

  test("accepts only bounded content-addressed redacted payload references", () => {
    const fixture = mailboxFixture();
    assert.doesNotThrow(() => validateAgentFleetMessage(fixture.message));
    assert.equal(
      fixture.message.message_id,
      agentFleetMessageIdentity(fixture.message),
    );
    assert.match(
      fixture.message.payload.payload_ref,
      /^agent-fleet-payload:\/\/sha256\//,
    );
    assert.equal("payload" in fixture.message, true);
    assert.equal("raw_payload" in fixture.message, false);

    assert.throws(
      () =>
        createAgentFleetPayloadReference({
          byte_length: 65_537,
          media_type: "text/plain",
          payload_digest: digest("payload"),
          redaction_receipt_digest: digest("redaction"),
        }),
      /payload byte length exceeds its bound/,
    );
    assert.throws(
      () =>
        createAgentFleetMessage({
          ...messageInput(fixture.packet, fixture.sender, fixture.payload),
          raw_payload: "unredacted input",
        } as ReturnType<typeof messageInput>),
      /unsupported fields/,
    );
    assert.throws(
      () =>
        createAgentFleetMessage({
          ...messageInput(fixture.packet, fixture.sender, fixture.payload),
          message_sequence: 2,
        }),
      /requires checkpoint and handoff references/,
    );
  });

  test("permits acknowledgement only after durable mailbox and run admission", async () => {
    const store = new GatedAgentFleetStore();
    const capacity = new ReferenceMemoryCapacityStore();
    const coordinator = new AgentFleetCoordinator({ capacity, fleet: store });
    const fixture = mailboxFixture();
    await store.registerMember(fixture.sender);

    store.holdAdmission();
    let acknowledged = false;
    const pending = coordinator.admit(fixture.message, fixture.packet).then((result) => {
      acknowledged = result.acknowledgement_permitted;
      return result;
    });
    await Promise.resolve();
    assert.equal(acknowledged, false);
    assert.equal(await store.readMailboxMessage(fixture.message.message_id), undefined);
    assert.equal(await store.readPacket(fixture.packet.packet_id), undefined);

    store.releaseAdmission();
    const admitted = await pending;
    assert.equal(admitted.acknowledgement_permitted, true);
    assert.equal(admitted.duplicate, false);
    assert.equal(
      store.distributedWork.hasRunnableRun(fixture.packet.child_run.run_id),
      true,
    );
    assert.equal(store.distributedWork.readRun(fixture.packet.child_run.run_id)?.state, "queued");

    const retry = await coordinator.admit(
      structuredClone(fixture.message),
      structuredClone(fixture.packet),
    );
    assert.equal(retry.duplicate, true);
    assert.equal(retry.receipt.receipt_id, admitted.receipt.receipt_id);

    const changed = createAgentFleetMessage({
      ...messageInput(fixture.packet, fixture.sender, fixture.payload),
      created_at: NEXT,
    });
    await assert.rejects(
      coordinator.admit(changed, fixture.packet),
      AgentFleetIdempotencyConflictError,
    );
  });

  test("uses durable capacity permits after deterministic compatibility ranking", async () => {
    const store = new ReferenceMemoryAgentFleetStore();
    const capacity = new ReferenceMemoryCapacityStore();
    const coordinator = new AgentFleetCoordinator({ capacity, fleet: store });
    const fixture = mailboxFixture();
    const candidates = [
      member("worker-a", "ready", 1, 1, NOW),
      member("worker-b", "ready", 1, 1, NOW),
    ];
    await store.registerMember(fixture.sender);
    for (const candidate of candidates) await store.registerMember(candidate);
    await coordinator.admit(fixture.message, fixture.packet);

    const ranking = rankCompatibleAgentFleetPeers({
      candidates,
      message: fixture.message,
      observed_at: NOW,
      packet: fixture.packet,
      sender: fixture.sender,
    });
    const first = ranking.compatible[0]?.member;
    const second = ranking.compatible[1]?.member;
    assert.ok(first !== undefined && second !== undefined);
    await capacity.acquire({
      acquired_at: NOW,
      acquisition_key: "preexisting-capacity",
      expires_at: EXPIRES,
      generation: first.generation,
      owner_id: "other-owner",
      permit_id: "preexisting-permit",
      permit_limit: 1,
      resource_ref: first.capacity_resource_ref,
      run_id: "other-run",
    });

    const reservation = await coordinator.reserveCompatiblePeer(
      fixture.message.message_id,
      {
        acquired_at: NOW,
        expires_at: EXPIRES,
        permit_limits: {
          [first.member_id]: 1,
          [second.member_id]: 1,
        },
        reservation_key: "attempt",
      },
    );
    assert.equal(reservation.status, "reserved");
    if (reservation.status !== "reserved") assert.fail("expected reservation");
    assert.equal(reservation.attempts[0]?.status, "unavailable");
    assert.equal(reservation.candidate.member.member_id, second.member_id);
    assert.equal(reservation.permit.owner_id, second.member_id);
    assert.equal(reservation.permit.run_id, fixture.packet.child_run.run_id);

    const replay = await coordinator.reserveCompatiblePeer(
      fixture.message.message_id,
      {
        acquired_at: NOW,
        expires_at: EXPIRES,
        permit_limits: {
          [first.member_id]: 1,
          [second.member_id]: 1,
        },
        reservation_key: "attempt",
      },
    );
    assert.equal(replay.status, "reserved");
    if (replay.status !== "reserved") assert.fail("expected replay");
    assert.equal(replay.permit.permit_id, reservation.permit.permit_id);
    const replayedAttempt = replay.attempts.at(-1);
    assert.equal(replayedAttempt?.status, "acquired");
    assert.equal(
      replayedAttempt?.status === "acquired"
        ? replayedAttempt.replayed
        : undefined,
      true,
    );
  });

  test("binds execution to current generation, fence, checkpoint, and handoff", async () => {
    const store = new ReferenceMemoryAgentFleetStore();
    const capacity = new ReferenceMemoryCapacityStore();
    const coordinator = new AgentFleetCoordinator({ capacity, fleet: store });
    const fixture = mailboxFixture();
    const worker = member("worker-a", "ready", 2, 1, NOW);
    await store.registerMember(fixture.sender);
    await store.registerMember(worker);
    await coordinator.admit(fixture.message, fixture.packet);
    const reservation = await coordinator.reserveCompatiblePeer(
      fixture.message.message_id,
      {
        acquired_at: NOW,
        expires_at: EXPIRES,
        permit_limits: { [worker.member_id]: 1 },
        reservation_key: "execution-1",
      },
    );
    assert.equal(reservation.status, "reserved");
    if (reservation.status !== "reserved") assert.fail("expected reservation");
    const lease = workLease(fixture.packet, worker);
    const initial = await coordinator.bindExecution({
      bound_at: NEXT,
      lease,
      member_id: worker.member_id,
      message_id: fixture.message.message_id,
      permit: reservation.permit,
    });
    assert.equal(initial.generation, worker.generation);
    assert.equal(initial.fencing_token, lease.fencing_token);
    assert.equal(initial.checkpoint_ref, undefined);

    await assert.rejects(
      coordinator.bindExecution({
        bound_at: NEXT,
        lease: { ...lease, generation: 1 },
        member_id: worker.member_id,
        message_id: fixture.message.message_id,
        permit: reservation.permit,
      }),
      /work lease does not fence this member and run/,
    );

    const checkpoint = checkpointFixture(fixture.packet, 1);
    const resume = createAgentFleetResumeReference(
      checkpoint,
      digest("handoff-1"),
    );
    const handoff = createAgentFleetMessage({
      ...messageInput(fixture.packet, fixture.sender, fixture.payload),
      created_at: LATER,
      idempotency_key: "mailbox-idempotency-2",
      message_sequence: 2,
      resume,
    });
    await coordinator.admit(handoff, fixture.packet);
    const resumed = await coordinator.bindExecution({
      bound_at: time(3),
      checkpoint,
      lease,
      member_id: worker.member_id,
      message_id: handoff.message_id,
      permit: reservation.permit,
    });
    assert.equal(resumed.checkpoint_ref, resume.checkpoint_ref);
    assert.equal(resumed.handoff_ref, resume.handoff_ref);

    await assert.rejects(
      coordinator.bindExecution({
        bound_at: time(3),
        checkpoint: { ...checkpoint, sequence: 2 },
        lease,
        member_id: worker.member_id,
        message_id: handoff.message_id,
        permit: reservation.permit,
      }),
      /resume references do not match/,
    );
  });
});

class GatedAgentFleetStore extends ReferenceMemoryAgentFleetStore {
  private gate?: Deferred;

  holdAdmission(): void {
    this.gate = deferred();
  }

  releaseAdmission(): void {
    this.gate?.resolve();
    this.gate = undefined;
  }

  async admitMailboxAndEnqueue(
    commit: AgentFleetMailboxAdmissionCommit,
  ): Promise<AgentFleetMailboxAdmissionResult> {
    await this.gate?.promise;
    return super.admitMailboxAndEnqueue(commit);
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

function mailboxFixture(): {
  message: AgentFleetMessageV1;
  packet: DistributedWorkPacketV1;
  payload: AgentFleetPayloadReferenceV1;
  sender: AgentFleetMemberV1;
} {
  const payload = createAgentFleetPayloadReference({
    byte_length: 128,
    media_type: "application/json",
    payload_digest: digest("redacted-payload"),
    redaction_receipt_digest: digest("redaction-receipt"),
  });
  const packet = packetFixture(payload);
  const sender = member("sender", "ready", 1, 1, NOW);
  return {
    message: createAgentFleetMessage(messageInput(packet, sender, payload)),
    packet,
    payload,
    sender,
  };
}

function messageInput(
  packet: DistributedWorkPacketV1,
  sender: AgentFleetMemberV1,
  payload: AgentFleetPayloadReferenceV1,
) {
  return {
    created_at: NOW,
    idempotency_key: "mailbox-idempotency-1",
    message_sequence: 1,
    packet_id: packet.packet_id,
    payload,
    protocol_version: AGENT_FLEET_PROTOCOL_VERSION,
    run_id: packet.child_run.run_id,
    sender_generation: sender.generation,
    sender_member_id: sender.member_id,
  };
}

function packetFixture(
  payload: AgentFleetPayloadReferenceV1,
): DistributedWorkPacketV1 {
  const input: DistributedWorkPacketIdentityInput = {
    child_run_kind: "interactive",
    correlation_id: "fleet-correlation-1",
    deliverables: [
      {
        deliverable_id: "deliverable-1",
        requirement_digest: digest("deliverable-1"),
        requirement_ref: "deliverable-requirement://opaque/1",
        sequence: 1,
      },
    ],
    idempotency_key: "distributed-work-idempotency-1",
    objective_digest: payload.payload_digest,
    objective_ref: payload.payload_ref,
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
    ...input,
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
    revision: 1,
    run_id: "fleet-run-1",
    run_kind: input.child_run_kind,
    schema_version: "run-receipt/v1",
    state: "queued",
    subject_ref: packetId,
    tenant_id: input.tenant_id,
    updated_at: NOW,
  };
}

function member(
  memberId: string,
  state: AgentFleetMemberV1["state"],
  generation: number,
  revision: number,
  updatedAt: string,
  memberCapabilities: CapabilityRequirement[] | undefined = capabilities(),
  schemaVersion = "v1",
): AgentFleetMemberV1 {
  return {
    capability_manifest: {
      capabilities: structuredClone(memberCapabilities),
      contract_versions: [AGENT_FLEET_PROTOCOL_VERSION],
      digest: digest(`manifest:${memberId}:${generation}:${schemaVersion}`),
      generation,
      produced_at: updatedAt,
      schema_version: "capability-manifest/v1",
      service_id: `service-${memberId}`,
    },
    capacity_resource_ref: `capacity://fleet/${memberId}`,
    generation,
    member_id: memberId,
    protocol_version: AGENT_FLEET_PROTOCOL_VERSION,
    registered_at: NOW,
    revision,
    schema_compatibility: {
      capability_decisions: ["supported", "degraded", "blocked", "incompatible"],
      current_version: schemaVersion,
      read_versions: [schemaVersion],
      rolling_upgrade_rule: "read current and previous; write current",
      write_versions: [schemaVersion],
    },
    schema_version: "agent-fleet-member/v1",
    service_id: `service-${memberId}`,
    state,
    updated_at: updatedAt,
    valid_until: EXPIRES,
  };
}

function transition(
  current: AgentFleetMemberV1,
  state: AgentFleetMemberV1["state"],
  updatedAt: string,
  generation = current.generation,
): AgentFleetMemberV1 {
  const next = structuredClone(current);
  next.state = state;
  next.revision += 1;
  next.updated_at = updatedAt;
  next.generation = generation;
  next.capability_manifest.generation = generation;
  next.capability_manifest.produced_at = updatedAt;
  if (generation !== current.generation) {
    next.capability_manifest.digest = digest(
      `manifest:${current.member_id}:${generation}:v1`,
    );
  }
  return next;
}

function workLease(
  packet: DistributedWorkPacketV1,
  worker: AgentFleetMemberV1,
): WorkLeaseV1 {
  return {
    fencing_token: 7,
    generation: worker.generation,
    heartbeat_at: NEXT,
    lease_expires_at: EXPIRES,
    lease_token: "fleet-lease-token-1",
    owner_id: worker.member_id,
    run_id: packet.child_run.run_id,
    schema_version: "work-lease/v1",
  };
}

function checkpointFixture(
  packet: DistributedWorkPacketV1,
  generation: number,
): CheckpointV1 {
  return {
    checkpoint_id: "checkpoint-1",
    completed_step_ids: ["step-1"],
    created_at: NEXT,
    effect_receipt_ids: [],
    generation,
    payload_digest: digest("checkpoint-payload"),
    payload_ref: "checkpoint-payload://opaque/1",
    resume_cursor: "step-2",
    run_id: packet.child_run.run_id,
    run_revision: 2,
    schema_version: "checkpoint/v1",
    sequence: 1,
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

function time(minutes: number): string {
  return new Date(Date.parse(NOW) + minutes * 60_000).toISOString();
}
