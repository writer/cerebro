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
import type {
  DistributedWorkDelegationManifestDraft,
  DistributedWorkDelegationUse,
} from "../src/distributed/delegation-contracts.js";
import type {
  DistributedWorkDelegationClockPort,
  DistributedWorkDelegationCurrentLeaseInput,
  DistributedWorkDelegationCurrentLeasePort,
  DistributedWorkDelegationRevocationInput,
  DistributedWorkDelegationRevocationPort,
  DistributedWorkDelegationSigningInput,
  DistributedWorkDelegationSigningPort,
  DistributedWorkDelegationSigningResult,
  DistributedWorkDelegationVerificationInput,
  DistributedWorkDelegationVerificationPort,
} from "../src/distributed/delegation-ports.js";
import {
  authorizeSignedDistributedWorkDelegation,
  createDistributedWorkDelegationManifest,
  signDistributedWorkDelegation,
} from "../src/distributed/delegation-validation.js";
import {
  distributedWorkIntentDigest,
  distributedWorkPacketIdentity,
} from "../src/distributed/validation.js";

const ISSUED_AT = "2026-07-16T12:00:00.000Z";
const ACTIVE_AT = "2026-07-16T12:05:00.000Z";
const EXPIRES_AT = "2026-07-16T12:15:00.000Z";
const LEASE_EXPIRES_AT = "2026-07-16T12:30:00.000Z";
const TEST_KEY_REF = "test-key://delegation/1";

describe("signed distributed work delegations", () => {
  test("signs deterministic bounded authority through portable ports", async () => {
    const packet = packetFixture();
    const lease = leaseFixture(packet.child_run.run_id);
    const signer = new DeterministicTestSignaturePort();
    const first = createDistributedWorkDelegationManifest(
      manifestDraft(packet, lease),
    );
    const reordered = createDistributedWorkDelegationManifest({
      ...manifestDraft(packet, lease),
      allowed_capabilities: [...packet.required_capabilities].reverse(),
      allowed_tool_refs: [
        "capability-tool://graph-read/1",
        "capability-tool://knowledge-read/1",
      ],
    });

    assert.equal(first.delegation_id, reordered.delegation_id);
    assert.equal(
      first.delegation_intent_digest,
      reordered.delegation_intent_digest,
    );

    const signed = await signDistributedWorkDelegation(
      first,
      TEST_KEY_REF,
      signer,
    );
    await assert.doesNotReject(() =>
      authorizeSignedDistributedWorkDelegation(
        signed,
        authorizedUse(packet),
        signer,
        new TestRevocationPort(),
        new TestCurrentLeasePort(lease),
        new TestClockPort(ACTIVE_AT),
      ),
    );
    assert.equal(signer.signCount, 1);
    assert.equal(signer.verifyCount, 1);
    assert.equal(signed.signature.key_ref, TEST_KEY_REF);
    assert.equal(signed.canonicalization, "sorted-json/v1");
    assert.equal(
      first.delegation_intent_digest,
      "sha256:4742ef6365c27388f7ff6caf92e97e7ae2e97ad24f087619347b4f3d013e84e7",
    );
  });

  test("permits a delegation with no tool authority", async () => {
    const packet = packetFixture();
    const lease = leaseFixture(packet.child_run.run_id);
    const signer = new DeterministicTestSignaturePort();
    const manifest = createDistributedWorkDelegationManifest({
      ...manifestDraft(packet, lease),
      allowed_tool_refs: [],
    });
    const signed = await signDistributedWorkDelegation(
      manifest,
      TEST_KEY_REF,
      signer,
    );

    await assert.doesNotReject(() =>
      authorizeSignedDistributedWorkDelegation(
        signed,
        {
          ...authorizedUse(packet),
          requested_tool_refs: [],
        },
        signer,
        new TestRevocationPort(),
        new TestCurrentLeasePort(lease),
        new TestClockPort(ACTIVE_AT),
      ),
    );
  });

  test("rejects signed-content and signature tampering", async () => {
    const packet = packetFixture();
    const lease = leaseFixture(packet.child_run.run_id);
    const signer = new DeterministicTestSignaturePort();
    const signed = await signedFixture(packet, lease, signer);

    const changedManifest = structuredClone(signed);
    changedManifest.manifest.expires_at = "2026-07-16T12:16:00.000Z";
    await assert.rejects(
      () =>
        authorizeSignedDistributedWorkDelegation(
          changedManifest,
          authorizedUse(packet),
          signer,
          new TestRevocationPort(),
          new TestCurrentLeasePort(lease),
          new TestClockPort(ACTIVE_AT),
        ),
      /manifest digest does not match/,
    );

    const changedSignature = structuredClone(signed);
    changedSignature.signature.signature_value = `${signed.signature.signature_value}0`;
    await assert.rejects(
      () =>
        authorizeSignedDistributedWorkDelegation(
          changedSignature,
          authorizedUse(packet),
          signer,
          new TestRevocationPort(),
          new TestCurrentLeasePort(lease),
          new TestClockPort(ACTIVE_AT),
        ),
      /signature is invalid/,
    );
  });

  test("rejects cross-subject reuse and replay with changed intent", async () => {
    const packet = packetFixture();
    const lease = leaseFixture(packet.child_run.run_id);
    const signer = new DeterministicTestSignaturePort();
    const signed = await signedFixture(packet, lease, signer);

    const otherSubjectPacket = packetFixture({
      ...identityInput(),
      parent_subject_ref: "subject://opaque/2",
    });
    const otherSubjectLease = leaseFixture(otherSubjectPacket.child_run.run_id);
    await assert.rejects(
      () =>
        authorizeSignedDistributedWorkDelegation(
          signed,
          authorizedUse(otherSubjectPacket),
          signer,
          new TestRevocationPort(),
          new TestCurrentLeasePort(otherSubjectLease),
          new TestClockPort(ACTIVE_AT),
        ),
      /does not match the admitted packet scope and intent/,
    );

    const changedIntentPacket = packetFixture({
      ...identityInput(),
      objective_digest: digest("changed-objective"),
      objective_ref: "work-objective://opaque/changed",
    });
    const changedIntentLease = leaseFixture(changedIntentPacket.child_run.run_id);
    const changedIntentManifest = createDistributedWorkDelegationManifest(
      manifestDraft(changedIntentPacket, changedIntentLease),
    );
    assert.notEqual(
      signed.manifest.delegation_id,
      changedIntentManifest.delegation_id,
    );
    await assert.rejects(
      () =>
        authorizeSignedDistributedWorkDelegation(
          signed,
          authorizedUse(changedIntentPacket),
          signer,
          new TestRevocationPort(),
          new TestCurrentLeasePort(changedIntentLease),
          new TestClockPort(ACTIVE_AT),
        ),
      /does not match the admitted packet scope and intent/,
    );
  });

  test("rejects capability, tool, and deliverable escalation", async () => {
    const packet = packetFixture();
    const lease = leaseFixture(packet.child_run.run_id);
    const signer = new DeterministicTestSignaturePort();
    const signed = await signedFixture(packet, lease, signer);
    const revocations = new TestRevocationPort();

    for (const use of [
      {
        ...authorizedUse(packet),
        requested_capabilities: [
          {
            capability_id: "effect.write",
            level: "required" as const,
            version: "v1",
          },
        ],
      },
      {
        ...authorizedUse(packet),
        requested_tool_refs: ["capability-tool://effect-write/1"],
      },
      {
        ...authorizedUse(packet),
        requested_deliverable_ids: ["deliverable-not-delegated"],
      },
    ]) {
      await assert.rejects(
        () =>
          authorizeSignedDistributedWorkDelegation(
            signed,
            use,
            signer,
            revocations,
            new TestCurrentLeasePort(lease),
            new TestClockPort(ACTIVE_AT),
          ),
        /requested authority exceeds/,
      );
    }
  });

  test("uses authoritative lease and clock state for authorization", async () => {
    const packet = packetFixture();
    const lease = leaseFixture(packet.child_run.run_id);
    const signer = new DeterministicTestSignaturePort();
    const signed = await signedFixture(packet, lease, signer);

    const newerLease: WorkLeaseV1 = {
      ...lease,
      fencing_token: lease.fencing_token + 1,
      generation: lease.generation + 1,
      lease_token: "lease-opaque-2",
    };
    await assert.rejects(
      () =>
        authorizeSignedDistributedWorkDelegation(
          signed,
          {
            ...authorizedUse(packet),
            lease,
            now: ACTIVE_AT,
          } as unknown as DistributedWorkDelegationUse,
          signer,
          new TestRevocationPort(),
          new TestCurrentLeasePort(newerLease),
          new TestClockPort(ACTIVE_AT),
        ),
      /active lease generation and fence/,
    );

    await assert.rejects(
      () =>
        authorizeSignedDistributedWorkDelegation(
          signed,
          authorizedUse(packet),
          signer,
          new TestRevocationPort(),
          new TestCurrentLeasePort({
            ...lease,
            lease_expires_at: ACTIVE_AT,
          }),
          new TestClockPort(ACTIVE_AT),
        ),
      /requires an active work lease/,
    );

    await assert.rejects(
      () =>
        authorizeSignedDistributedWorkDelegation(
          signed,
          { ...authorizedUse(packet), now: ACTIVE_AT } as unknown as
            DistributedWorkDelegationUse,
          signer,
          new TestRevocationPort(),
          new TestCurrentLeasePort(lease),
          new TestClockPort(EXPIRES_AT),
        ),
      /not active/,
    );

    await assert.rejects(
      () =>
        authorizeSignedDistributedWorkDelegation(
          signed,
          authorizedUse(packet),
          signer,
          new TestRevocationPort(),
          new TestCurrentLeasePort(lease),
          new TestClockPort("07/16/2026"),
        ),
      /clock.now must use YYYY-MM-DDTHH:mm:ss.SSSZ UTC/,
    );

    await assert.rejects(
      () =>
        authorizeSignedDistributedWorkDelegation(
          signed,
          authorizedUse(packet),
          signer,
          new TestRevocationPort(),
          new TestCurrentLeasePort({
            ...lease,
            lease_expires_at: "07/16/2026",
          }),
          new TestClockPort(ACTIVE_AT),
        ),
      /lease.lease_expires_at must use YYYY-MM-DDTHH:mm:ss.SSSZ UTC/,
    );

    await assert.rejects(
      () =>
        authorizeSignedDistributedWorkDelegation(
          signed,
          authorizedUse(packet),
          signer,
          new TestRevocationPort(),
          new TestCurrentLeasePort(undefined),
          new TestClockPort(ACTIVE_AT),
        ),
      /authoritative current work lease/,
    );

    const trustedRevocations = new TestRevocationPort();
    const trustedCurrentLease = new TestCurrentLeasePort(lease);
    await assert.doesNotReject(() =>
      authorizeSignedDistributedWorkDelegation(
        signed,
        authorizedUse(packet),
        signer,
        trustedRevocations,
        trustedCurrentLease,
        new TestClockPort(ISSUED_AT),
      ),
    );
    assert.equal(trustedCurrentLease.lookups[0]?.observed_at, ISSUED_AT);
    assert.equal(trustedCurrentLease.lookups[0]?.run_id, packet.child_run.run_id);
    assert.equal(trustedRevocations.observations[0]?.observed_at, ISSUED_AT);

    await assert.rejects(
      () =>
        authorizeSignedDistributedWorkDelegation(
          signed,
          authorizedUse(packet),
          signer,
          new TestRevocationPort([signed.manifest.delegation_id]),
          new TestCurrentLeasePort(lease),
          new TestClockPort(ACTIVE_AT),
        ),
      /is revoked/,
    );
  });

  test("requires one canonical UTC timestamp form", () => {
    const packet = packetFixture();
    const lease = leaseFixture(packet.child_run.run_id);

    for (const issuedAt of [
      "07/16/2026",
      "2026-07-16T12:00:00Z",
      "2026-07-16T12:00:00.000+00:00",
      "2026-02-30T12:00:00.000Z",
    ]) {
      assert.throws(
        () =>
          createDistributedWorkDelegationManifest({
            ...manifestDraft(packet, lease),
            issued_at: issuedAt,
          }),
        /must use YYYY-MM-DDTHH:mm:ss.SSSZ UTC/,
      );
    }
  });

  test("rejects non-ASCII signed identifiers and references", () => {
    const packetWithUnicodeCapability = packetFixture({
      ...identityInput(),
      required_capabilities: [
        {
          capability_id: "knowledge.réad",
          level: "required",
          version: "v1",
        },
      ],
    });
    const unicodeLease = leaseFixture(
      packetWithUnicodeCapability.child_run.run_id,
    );
    assert.throws(
      () =>
        createDistributedWorkDelegationManifest(
          manifestDraft(packetWithUnicodeCapability, unicodeLease),
        ),
      /printable ASCII identifier/,
    );

    const packet = packetFixture();
    const lease = leaseFixture(packet.child_run.run_id);
    assert.throws(
      () =>
        createDistributedWorkDelegationManifest({
          ...manifestDraft(packet, lease),
          allowed_tool_refs: ["capability-tool://réad/1"],
        }),
      /bounded opaque reference/,
    );
  });
});

class DeterministicTestSignaturePort
  implements
    DistributedWorkDelegationSigningPort,
    DistributedWorkDelegationVerificationPort
{
  signCount = 0;
  verifyCount = 0;

  async sign(
    input: DistributedWorkDelegationSigningInput,
  ): Promise<DistributedWorkDelegationSigningResult> {
    this.signCount += 1;
    return {
      signature_suite: "test-digest-v1",
      signature_value: testSignature(input),
    };
  }

  async verify(
    input: DistributedWorkDelegationVerificationInput,
  ): Promise<boolean> {
    this.verifyCount += 1;
    return (
      input.signature.signature_suite === "test-digest-v1" &&
      input.signature.key_ref === input.key_ref &&
      input.signature.signature_value === testSignature(input)
    );
  }
}

class TestRevocationPort implements DistributedWorkDelegationRevocationPort {
  readonly observations: DistributedWorkDelegationRevocationInput[] = [];
  private readonly revoked: Set<string>;

  constructor(revoked: string[] = []) {
    this.revoked = new Set(revoked);
  }

  async isRevoked(
    input: DistributedWorkDelegationRevocationInput,
  ): Promise<boolean> {
    this.observations.push(structuredClone(input));
    return this.revoked.has(input.delegation_id);
  }
}

class TestClockPort implements DistributedWorkDelegationClockPort {
  constructor(private readonly value: string) {}

  now(): string {
    return this.value;
  }
}

class TestCurrentLeasePort
  implements DistributedWorkDelegationCurrentLeasePort
{
  readonly lookups: DistributedWorkDelegationCurrentLeaseInput[] = [];

  constructor(private readonly lease: WorkLeaseV1 | undefined) {}

  async getCurrentLease(
    input: DistributedWorkDelegationCurrentLeaseInput,
  ): Promise<WorkLeaseV1 | undefined> {
    this.lookups.push(structuredClone(input));
    return this.lease === undefined ? undefined : structuredClone(this.lease);
  }
}

function testSignature(input: DistributedWorkDelegationSigningInput): string {
  return createHash("sha256")
    .update("deterministic-test-material")
    .update(input.issuer_ref)
    .update(input.key_ref)
    .update(input.manifest_digest)
    .update(input.canonical_manifest)
    .digest("hex");
}

async function signedFixture(
  packet: DistributedWorkPacketV1,
  lease: WorkLeaseV1,
  signer: DeterministicTestSignaturePort,
) {
  return signDistributedWorkDelegation(
    createDistributedWorkDelegationManifest(manifestDraft(packet, lease)),
    TEST_KEY_REF,
    signer,
  );
}

function manifestDraft(
  packet: DistributedWorkPacketV1,
  lease: WorkLeaseV1,
): DistributedWorkDelegationManifestDraft {
  return {
    allowed_capabilities: structuredClone(packet.required_capabilities),
    allowed_deliverables: structuredClone(packet.deliverables),
    allowed_tool_refs: [
      "capability-tool://knowledge-read/1",
      "capability-tool://graph-read/1",
    ],
    expires_at: EXPIRES_AT,
    issued_at: ISSUED_AT,
    issuer_ref: "agent-service://issuer/1",
    lease,
    not_before: ISSUED_AT,
    packet,
    revocation_ref: "delegation-revocations://opaque/1",
  };
}

function authorizedUse(
  packet: DistributedWorkPacketV1,
): DistributedWorkDelegationUse {
  return {
    packet,
    requested_capabilities: [structuredClone(packet.required_capabilities[0]!)],
    requested_deliverable_ids: [packet.deliverables[0]!.deliverable_id],
    requested_tool_refs: ["capability-tool://knowledge-read/1"],
  };
}

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
    parent_subject_ref: "subject://opaque/1",
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
    created_at: ISSUED_AT,
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
    admitted_at: ISSUED_AT,
    binding_id: "binding-opaque-1",
    idempotency_key: input.idempotency_key,
    input_digest: intentDigest,
    receipt_id: "run-receipt-1",
    received_at: ISSUED_AT,
    required_capabilities: structuredClone(input.required_capabilities),
    retention_policy_ref: input.retention_policy_ref,
    revision: 2,
    run_id: "child-run-1",
    run_kind: input.child_run_kind,
    schema_version: "run-receipt/v1",
    state: "queued",
    subject_ref: packetId,
    tenant_id: input.tenant_id,
    updated_at: ISSUED_AT,
  };
}

function leaseFixture(runId: string): WorkLeaseV1 {
  return {
    fencing_token: 3,
    generation: 2,
    heartbeat_at: ISSUED_AT,
    lease_expires_at: LEASE_EXPIRES_AT,
    lease_token: "lease-opaque-1",
    owner_id: "worker-opaque-1",
    run_id: runId,
    schema_version: "work-lease/v1",
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

function digest(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}
