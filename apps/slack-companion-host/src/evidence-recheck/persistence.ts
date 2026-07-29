import { createHash } from "node:crypto";
import type {
  AtomicDocument,
  AtomicDocumentStore,
  DeliveredAnswerEvidenceBindingLookupV1,
  DeliveredAnswerEvidenceBindingV1,
  DurableEvidenceRecheckAdmissionPort,
  EvidenceRecheckAdmissionCommitResultV1,
  EvidenceRecheckAdmissionCommitV1,
  EvidenceRecheckAdmissionReceiptLookupV1,
  EvidenceRecheckAdmissionReceiptV1,
  EvidenceRecheckCheckpointV1,
  EvidenceRecheckCompletionV1,
  EvidenceRecheckExecutionClaimV1,
  EvidenceRecheckExecutionLeaseV1,
  EvidenceRecheckExecutionSessionV1,
  EvidenceRecheckOutboxLeaseV1,
  EvidenceRecheckStatusDeliveryReceiptV1,
  EvidenceRecheckV1,
  PortableEvidenceRecheckContract,
} from "./contracts.js";

const BINDING_PREFIX = "evidence-recheck/bindings/";
const ADMISSION_PREFIX = "evidence-recheck/admissions/";
const MAX_CAS_ATTEMPTS = 8;
const SCAN_PAGE_SIZE = 128;

interface StoredBindingV1 {
  binding: DeliveredAnswerEvidenceBindingV1;
  fingerprint: string;
  schema_version: "private-evidence-recheck-binding/v1";
}

interface StoredExecutionV1 {
  checkpoints: EvidenceRecheckCheckpointV1[];
  fencing_token: number;
  generation: number;
  lease?: EvidenceRecheckExecutionLeaseV1;
  state: "completed" | "queued" | "running";
}

interface StoredStatusOutboxV1 {
  delivery?: EvidenceRecheckStatusDeliveryReceiptV1;
  fencing_token: number;
  generation: number;
  lease?: EvidenceRecheckOutboxLeaseV1;
  outbox_id: string;
  recheck: EvidenceRecheckV1;
  state: "delivered" | "outcome_unknown" | "pending";
  thread_ref: string;
}

interface StoredAdmissionV1 {
  commit: EvidenceRecheckAdmissionCommitV1;
  current_recheck: EvidenceRecheckV1;
  execution: StoredExecutionV1;
  outbox: StoredStatusOutboxV1[];
  request_fingerprint: string;
  schema_version: "private-evidence-recheck-admission/v1";
}

type EvidenceRecheckExecutionSessionWithoutBindingV1 = Omit<
  EvidenceRecheckExecutionSessionV1,
  "binding"
>;

export interface EvidenceRecheckStoreOptions {
  contract: Pick<
    PortableEvidenceRecheckContract,
    "validateDeliveredAnswerEvidenceBinding" | "validateEvidenceRecheck"
  >;
  documents: AtomicDocumentStore;
}

export class EvidenceRecheckStoreConflictError extends Error {}
export class EvidenceRecheckStoreInvariantError extends Error {}

/**
 * Stores each accepted recheck as one aggregate document. The immutable public
 * receipt, run, transitions, runnable queue item, and queued status intent are
 * therefore one put-if-absent operation rather than several best-effort writes.
 */
export class AtomicEvidenceRecheckStore implements DurableEvidenceRecheckAdmissionPort {
  private readonly contract: EvidenceRecheckStoreOptions["contract"];
  private readonly documents: AtomicDocumentStore;

  constructor(options: EvidenceRecheckStoreOptions) {
    this.contract = options.contract;
    this.documents = options.documents;
  }

  async putBindingIfAbsent(
    binding: DeliveredAnswerEvidenceBindingV1,
  ): Promise<{ binding: DeliveredAnswerEvidenceBindingV1; created: boolean }> {
    this.contract.validateDeliveredAnswerEvidenceBinding(binding);
    const key = bindingKey(binding.binding_ref);
    const stored: StoredBindingV1 = {
      binding: clone(binding),
      fingerprint: digest(binding),
      schema_version: "private-evidence-recheck-binding/v1",
    };
    if (await this.documents.putIfAbsent(key, stored)) {
      return { binding: clone(binding), created: true };
    }
    const current = parseBinding(await this.requireDocument(key));
    if (current.fingerprint !== stored.fingerprint) {
      throw new EvidenceRecheckStoreConflictError(
        "Evidence binding identity already belongs to different content.",
      );
    }
    this.contract.validateDeliveredAnswerEvidenceBinding(current.binding);
    return { binding: clone(current.binding), created: false };
  }

  async bindingLookup(bindingRef: string): Promise<DeliveredAnswerEvidenceBindingLookupV1> {
    requireRef(bindingRef, "binding_ref");
    const document = await this.documents.read(bindingKey(bindingRef));
    if (document === undefined) {
      return {
        binding_ref: bindingRef,
        found: false,
        schema_version: "delivered-answer-evidence-binding-lookup/v1",
      };
    }
    const stored = parseBinding(document);
    this.contract.validateDeliveredAnswerEvidenceBinding(stored.binding);
    if (stored.binding.binding_ref !== bindingRef) {
      throw new EvidenceRecheckStoreInvariantError(
        "Evidence binding store returned another identity.",
      );
    }
    return {
      binding: clone(stored.binding),
      found: true,
      schema_version: "delivered-answer-evidence-binding-lookup/v1",
    };
  }

  async receiptLookup(receiptId: string): Promise<EvidenceRecheckAdmissionReceiptLookupV1> {
    requireRef(receiptId, "receipt_id");
    const document = await this.documents.read(admissionKey(receiptId));
    if (document === undefined) {
      return {
        found: false,
        receipt_id: receiptId,
        schema_version: "evidence-recheck-admission-receipt-lookup/v1",
      };
    }
    const stored = parseAdmission(document);
    if (stored.commit.receipt.receipt_id !== receiptId) {
      throw new EvidenceRecheckStoreInvariantError(
        "Evidence recheck receipt store returned another identity.",
      );
    }
    return {
      found: true,
      receipt: clone(stored.commit.receipt),
      schema_version: "evidence-recheck-admission-receipt-lookup/v1",
    };
  }

  async admitAndEnqueue(
    commit: EvidenceRecheckAdmissionCommitV1,
  ): Promise<EvidenceRecheckAdmissionCommitResultV1> {
    validateCommitShape(commit);
    this.contract.validateEvidenceRecheck(commit.receipt.recheck);
    const key = admissionKey(commit.receipt.receipt_id);
    const stored: StoredAdmissionV1 = {
      commit: clone(commit),
      current_recheck: clone(commit.receipt.recheck),
      execution: {
        checkpoints: [],
        fencing_token: 0,
        generation: 0,
        state: "queued",
      },
      outbox: [statusOutbox(commit.receipt.recheck)],
      request_fingerprint: admissionFingerprint(commit),
      schema_version: "private-evidence-recheck-admission/v1",
    };
    if (await this.documents.putIfAbsent(key, stored)) {
      return { created: true, receipt: clone(commit.receipt) };
    }
    const winner = parseAdmission(await this.requireDocument(key));
    validateCommitShape(winner.commit);
    this.contract.validateEvidenceRecheck(winner.commit.receipt.recheck);
    if (winner.request_fingerprint !== stored.request_fingerprint) {
      throw new EvidenceRecheckStoreConflictError(
        "Evidence recheck request identity already belongs to different content.",
      );
    }
    return { created: false, receipt: clone(winner.commit.receipt) };
  }

  async claimNextExecution(
    claim: EvidenceRecheckExecutionClaimV1,
  ): Promise<EvidenceRecheckExecutionSessionV1 | undefined> {
    validateClaim(claim);
    const documents = await this.listAdmissions();
    for (const document of documents.sort((left, right) => compareOrdinal(left.key, right.key))) {
      const claimed = await this.claimExecutionDocument(document.key, claim);
      if (claimed !== undefined) {
        const lookup = await this.bindingLookup(claimed.receipt.recheck.binding_ref);
        if (!lookup.found) {
          throw new EvidenceRecheckStoreInvariantError(
            "Accepted evidence recheck no longer has its durable binding.",
          );
        }
        return { ...claimed, binding: lookup.binding };
      }
    }
    return undefined;
  }

  async renewExecution(
    lease: EvidenceRecheckExecutionLeaseV1,
    observedAt: string,
    leaseDurationMs: number,
  ): Promise<EvidenceRecheckExecutionLeaseV1> {
    requireCanonicalTimestamp(observedAt, "observed_at");
    requirePositiveInteger(leaseDurationMs, "lease_duration_ms");
    return this.updateByRunId(lease.run_id, (stored) => {
      assertExecutionLease(stored, lease, observedAt, false);
      const renewed: EvidenceRecheckExecutionLeaseV1 = {
        ...lease,
        heartbeat_at: observedAt,
        lease_expires_at: expiresAt(observedAt, leaseDurationMs),
      };
      stored.execution.lease = renewed;
      return { result: clone(renewed), stored };
    });
  }

  async appendCheckpoint(
    lease: EvidenceRecheckExecutionLeaseV1,
    payloadRef: string,
    checkpointDigest: string,
    createdAt: string,
  ): Promise<EvidenceRecheckCheckpointV1> {
    requireRef(payloadRef, "checkpoint payload_ref");
    requireDigest(checkpointDigest, "checkpoint_digest");
    requireCanonicalTimestamp(createdAt, "checkpoint created_at");
    return this.updateByRunId(lease.run_id, (stored) => {
      assertExecutionLease(stored, lease, createdAt, false);
      const sequence = stored.execution.checkpoints.length + 1;
      const checkpoint: EvidenceRecheckCheckpointV1 = {
        checkpoint_digest: checkpointDigest,
        checkpoint_id: `evidence-recheck-checkpoint:${digestHex([
          lease.run_id,
          sequence,
          checkpointDigest,
        ]).slice(0, 32)}`,
        created_at: createdAt,
        fencing_token: lease.fencing_token,
        generation: lease.generation,
        payload_ref: payloadRef,
        run_id: lease.run_id,
        schema_version: "private-evidence-recheck-checkpoint/v1",
        sequence,
      };
      stored.execution.checkpoints.push(checkpoint);
      return { result: clone(checkpoint), stored };
    });
  }

  async releaseExecutionForRecovery(
    lease: EvidenceRecheckExecutionLeaseV1,
    releasedAt: string,
    reasonCode = "execution_checkpointed",
  ): Promise<EvidenceRecheckV1> {
    requireCanonicalTimestamp(releasedAt, "released_at");
    requireRef(reasonCode, "reason_code");
    return this.updateByRunId(lease.run_id, (stored) => {
      assertExecutionLease(stored, lease, releasedAt, false);
      const degraded = advanceRecheck(
        stored.current_recheck,
        "degraded",
        reasonCode,
        releasedAt,
      );
      this.contract.validateEvidenceRecheck(degraded);
      stored.current_recheck = degraded;
      stored.execution.lease = undefined;
      stored.execution.state = "queued";
      appendStatusOutbox(stored, degraded);
      return { result: clone(degraded), stored };
    });
  }

  async completeExecution(
    lease: EvidenceRecheckExecutionLeaseV1,
    completion: EvidenceRecheckCompletionV1,
    observedAt: string,
  ): Promise<EvidenceRecheckV1> {
    validateCompletion(completion);
    requireCanonicalTimestamp(observedAt, "observed_at");
    if (Date.parse(completion.completed_at) > Date.parse(observedAt)) {
      throw new EvidenceRecheckStoreInvariantError(
        "Evidence recheck completion cannot be observed before it occurred.",
      );
    }
    return this.updateByRunId(lease.run_id, (stored) => {
      assertExecutionLease(stored, lease, observedAt, false);
      const completed: EvidenceRecheckV1 = {
        ...stored.current_recheck,
        completed_at: completion.completed_at,
        outcome_digest: completion.outcome_digest,
        outcome_ref: completion.outcome_ref,
        reason_code: completion.reason_code,
        revision: stored.current_recheck.revision + 1,
        state: "completed",
        updated_at: completion.completed_at,
      };
      this.contract.validateEvidenceRecheck(completed);
      stored.current_recheck = completed;
      stored.execution.lease = undefined;
      stored.execution.state = "completed";
      appendStatusOutbox(stored, completed);
      return { result: clone(completed), stored };
    });
  }

  async recoverExpiredExecutions(observedAt: string): Promise<string[]> {
    requireCanonicalTimestamp(observedAt, "observed_at");
    const recovered: string[] = [];
    const documents = await this.listAdmissions();
    for (const document of documents.sort((left, right) => compareOrdinal(left.key, right.key))) {
      const result = await this.updateAdmission(document.key, (stored) => {
        const lease = stored.execution.lease;
        if (
          lease === undefined ||
          Date.parse(lease.lease_expires_at) > Date.parse(observedAt) ||
          stored.execution.state === "completed"
        ) {
          return { changed: false, result: undefined, stored };
        }
        const degraded = advanceRecheck(
          stored.current_recheck,
          "degraded",
          "execution_lease_expired",
          observedAt,
        );
        this.contract.validateEvidenceRecheck(degraded);
        stored.current_recheck = degraded;
        stored.execution.lease = undefined;
        stored.execution.state = "queued";
        appendStatusOutbox(stored, degraded);
        return { changed: true, result: degraded.run_id, stored };
      });
      if (result !== undefined) recovered.push(result);
    }
    return recovered;
  }

  async claimNextOutbox(
    claim: EvidenceRecheckExecutionClaimV1,
  ): Promise<{
    lease: EvidenceRecheckOutboxLeaseV1;
    recheck: EvidenceRecheckV1;
    thread_ref: string;
  } | undefined> {
    validateClaim(claim);
    const documents = await this.listAdmissions();
    for (const document of documents.sort((left, right) => compareOrdinal(left.key, right.key))) {
      const claimed = await this.updateAdmission(document.key, (stored) => {
        const candidate = stored.outbox.find((item) => {
          if (item.state === "delivered") return false;
          if (item.lease === undefined) return true;
          return Date.parse(item.lease.lease_expires_at) <= Date.parse(claim.observed_at);
        });
        if (candidate === undefined) {
          return { changed: false, result: undefined, stored };
        }
        if (claim.generation < candidate.generation) {
          return { changed: false, result: undefined, stored };
        }
        const fencingToken = candidate.fencing_token + 1;
        const lease: EvidenceRecheckOutboxLeaseV1 = {
          fencing_token: fencingToken,
          generation: claim.generation,
          lease_expires_at: expiresAt(claim.observed_at, claim.lease_duration_ms),
          lease_token: `evidence-recheck-outbox-lease:${digestHex([
            candidate.outbox_id,
            claim.owner_id,
            claim.generation,
            fencingToken,
          ]).slice(0, 32)}`,
          mode: candidate.state === "outcome_unknown" ? "inspect" : "send",
          outbox_id: candidate.outbox_id,
          owner_id: claim.owner_id,
          schema_version: "private-evidence-recheck-outbox-lease/v1",
        };
        candidate.fencing_token = fencingToken;
        candidate.generation = claim.generation;
        candidate.lease = lease;
        return {
          changed: true,
          result: {
            lease: clone(lease),
            recheck: clone(candidate.recheck),
            thread_ref: candidate.thread_ref,
          },
          stored,
        };
      });
      if (claimed !== undefined) return claimed;
    }
    return undefined;
  }

  async beginOutboxSend(lease: EvidenceRecheckOutboxLeaseV1): Promise<void> {
    await this.updateByOutboxId(lease.outbox_id, (stored, outbox) => {
      assertOutboxLease(outbox, lease);
      if (lease.mode !== "send" || outbox.state !== "pending") {
        throw new EvidenceRecheckStoreInvariantError(
          "Only a pending status intent may begin a send.",
        );
      }
      outbox.state = "outcome_unknown";
      return { result: undefined, stored };
    });
  }

  async completeOutbox(
    lease: EvidenceRecheckOutboxLeaseV1,
    delivery: EvidenceRecheckStatusDeliveryReceiptV1,
  ): Promise<void> {
    validateDelivery(delivery, lease.outbox_id);
    await this.updateByOutboxId(lease.outbox_id, (stored, outbox) => {
      assertOutboxLease(outbox, lease);
      if (outbox.state !== "outcome_unknown") {
        throw new EvidenceRecheckStoreInvariantError(
          "Only an outcome-unknown status intent may be completed.",
        );
      }
      outbox.delivery = clone(delivery);
      outbox.lease = undefined;
      outbox.state = "delivered";
      return { result: undefined, stored };
    });
  }

  async resetOutboxAfterMissingInspection(
    lease: EvidenceRecheckOutboxLeaseV1,
  ): Promise<void> {
    await this.updateByOutboxId(lease.outbox_id, (stored, outbox) => {
      assertOutboxLease(outbox, lease);
      if (lease.mode !== "inspect" || outbox.state !== "outcome_unknown") {
        throw new EvidenceRecheckStoreInvariantError(
          "Only an outcome-unknown status send may be reset after inspection.",
        );
      }
      outbox.lease = undefined;
      outbox.state = "pending";
      return { result: undefined, stored };
    });
  }

  async readCurrentRecheck(runId: string): Promise<EvidenceRecheckV1 | undefined> {
    const document = await this.findByRunId(runId);
    return document === undefined ? undefined : clone(parseAdmission(document).current_recheck);
  }

  async pendingCounts(): Promise<{ execution: number; outbox: number }> {
    let execution = 0;
    let outbox = 0;
    for (const document of await this.listAdmissions()) {
      const stored = parseAdmission(document);
      if (stored.execution.state !== "completed") execution += 1;
      outbox += stored.outbox.filter((item) => item.state !== "delivered").length;
    }
    return { execution, outbox };
  }

  private async claimExecutionDocument(
    key: string,
    claim: EvidenceRecheckExecutionClaimV1,
  ): Promise<EvidenceRecheckExecutionSessionWithoutBindingV1 | undefined> {
    return this.updateAdmission(key, (stored) => {
      if (stored.execution.state === "completed") {
        return { changed: false, result: undefined, stored };
      }
      const currentLease = stored.execution.lease;
      // Expired running work must first pass through recoverExpiredExecutions,
      // which commits a Slack-visible degraded state before it can be claimed.
      if (currentLease !== undefined) {
        return { changed: false, result: undefined, stored };
      }
      if (claim.generation < stored.execution.generation) {
        return { changed: false, result: undefined, stored };
      }
      const fencingToken = stored.execution.fencing_token + 1;
      const lease: EvidenceRecheckExecutionLeaseV1 = {
        acquired_at: claim.observed_at,
        fencing_token: fencingToken,
        generation: claim.generation,
        heartbeat_at: claim.observed_at,
        lease_expires_at: expiresAt(claim.observed_at, claim.lease_duration_ms),
        lease_token: `evidence-recheck-lease:${digestHex([
          stored.current_recheck.run_id,
          claim.owner_id,
          claim.generation,
          fencingToken,
        ]).slice(0, 32)}`,
        owner_id: claim.owner_id,
        run_id: stored.current_recheck.run_id,
        schema_version: "private-evidence-recheck-execution-lease/v1",
      };
      const running = advanceRecheck(
        stored.current_recheck,
        "running",
        stored.execution.generation === 0 ? "execution_started" : "execution_recovered",
        claim.observed_at,
      );
      this.contract.validateEvidenceRecheck(running);
      stored.current_recheck = running;
      stored.execution.fencing_token = fencingToken;
      stored.execution.generation = claim.generation;
      stored.execution.lease = lease;
      stored.execution.state = "running";
      appendStatusOutbox(stored, running);
      return { changed: true, result: this.session(stored, lease), stored };
    });
  }

  private session(
    stored: StoredAdmissionV1,
    lease: EvidenceRecheckExecutionLeaseV1,
  ): EvidenceRecheckExecutionSessionWithoutBindingV1 {
    const latest = stored.execution.checkpoints.at(-1);
    return {
      ...(latest === undefined ? {} : { checkpoint: clone(latest) }),
      lease: clone(lease),
      receipt: clone(stored.commit.receipt),
      recheck: clone(stored.current_recheck),
    };
  }

  private async updateByRunId<T>(
    runId: string,
    mutate: (stored: StoredAdmissionV1) => { result: T; stored: StoredAdmissionV1 },
  ): Promise<T> {
    const document = await this.findByRunId(runId);
    if (document === undefined) {
      throw new EvidenceRecheckStoreInvariantError("Evidence recheck run does not exist.");
    }
    return this.updateAdmission(document.key, (stored) => ({
      changed: true,
      ...mutate(stored),
    }));
  }

  private async updateByOutboxId<T>(
    outboxId: string,
    mutate: (
      stored: StoredAdmissionV1,
      outbox: StoredStatusOutboxV1,
    ) => { result: T; stored: StoredAdmissionV1 },
  ): Promise<T> {
    const documents = await this.listAdmissions();
    const document = documents.find((candidate) =>
      parseAdmission(candidate).outbox.some((outbox) => outbox.outbox_id === outboxId)
    );
    if (document === undefined) {
      throw new EvidenceRecheckStoreInvariantError("Evidence recheck outbox item does not exist.");
    }
    return this.updateAdmission(document.key, (stored) => {
      const outbox = stored.outbox.find((candidate) => candidate.outbox_id === outboxId);
      if (outbox === undefined) {
        throw new EvidenceRecheckStoreInvariantError("Evidence recheck outbox item disappeared.");
      }
      return { changed: true, ...mutate(stored, outbox) };
    });
  }

  private async updateAdmission<T>(
    key: string,
    mutate: (stored: StoredAdmissionV1) => {
      changed: boolean;
      result: T;
      stored: StoredAdmissionV1;
    },
  ): Promise<T> {
    for (let attempt = 0; attempt < MAX_CAS_ATTEMPTS; attempt += 1) {
      const document = await this.requireDocument(key);
      const stored = clone(parseAdmission(document));
      const update = mutate(stored);
      if (!update.changed) return update.result;
      if (await this.documents.compareAndSwap(key, document.token, update.stored)) {
        return update.result;
      }
    }
    throw new EvidenceRecheckStoreConflictError(
      "Evidence recheck aggregate changed during a fenced update.",
    );
  }

  private async findByRunId(runId: string): Promise<AtomicDocument | undefined> {
    requireRef(runId, "run_id");
    const documents = await this.listAdmissions();
    return documents.find(
      (document) => parseAdmission(document).current_recheck.run_id === runId,
    );
  }

  private async listAdmissions(): Promise<AtomicDocument[]> {
    const documents: AtomicDocument[] = [];
    let afterKey: string | undefined;
    for (;;) {
      const page = (await this.documents.list(
        ADMISSION_PREFIX,
        SCAN_PAGE_SIZE,
        afterKey,
      )).sort((left, right) => compareOrdinal(left.key, right.key));
      if (page.length === 0) return documents;
      if (afterKey !== undefined && page[0]!.key <= afterKey) {
        throw new EvidenceRecheckStoreInvariantError(
          "Atomic document pagination did not advance.",
        );
      }
      documents.push(...page);
      if (page.length < SCAN_PAGE_SIZE) return documents;
      afterKey = page.at(-1)!.key;
    }
  }

  private async requireDocument(key: string): Promise<AtomicDocument> {
    const document = await this.documents.read(key);
    if (document === undefined) {
      throw new EvidenceRecheckStoreInvariantError("Evidence recheck document does not exist.");
    }
    return document;
  }
}

function statusOutbox(recheck: EvidenceRecheckV1): StoredStatusOutboxV1 {
  return {
    fencing_token: 0,
    generation: 0,
    outbox_id: statusOutboxIdentity(recheck),
    recheck: clone(recheck),
    state: "pending",
    thread_ref: recheck.thread_ref,
  };
}

function appendStatusOutbox(stored: StoredAdmissionV1, recheck: EvidenceRecheckV1): void {
  const outbox = statusOutbox(recheck);
  if (!stored.outbox.some((candidate) => candidate.outbox_id === outbox.outbox_id)) {
    stored.outbox.push(outbox);
  }
}

function statusOutboxIdentity(recheck: EvidenceRecheckV1): string {
  return `evidence-recheck-status:${digestHex([
    recheck.recheck_id,
    recheck.revision,
    recheck.state,
    recheck.updated_at,
  ]).slice(0, 32)}`;
}

function advanceRecheck(
  current: EvidenceRecheckV1,
  state: "degraded" | "running",
  reasonCode: string,
  updatedAt: string,
): EvidenceRecheckV1 {
  return {
    ...current,
    completed_at: undefined,
    outcome_digest: undefined,
    outcome_ref: undefined,
    reason_code: reasonCode,
    revision: current.revision + 1,
    state,
    updated_at: updatedAt,
  };
}

function validateCommitShape(commit: EvidenceRecheckAdmissionCommitV1): void {
  if (
    commit.transitions.length !== 2 ||
    commit.transitions[0]?.from !== "received" ||
    commit.transitions[0]?.to !== "admitted" ||
    commit.transitions[1]?.from !== "admitted" ||
    commit.transitions[1]?.to !== "queued"
  ) {
    throw new EvidenceRecheckStoreInvariantError(
      "Evidence recheck admission transitions are invalid.",
    );
  }
}

function validateClaim(claim: EvidenceRecheckExecutionClaimV1): void {
  requirePositiveInteger(claim.generation, "generation");
  requirePositiveInteger(claim.lease_duration_ms, "lease_duration_ms");
  requireCanonicalTimestamp(claim.observed_at, "observed_at");
  requireRef(claim.owner_id, "owner_id");
}

function validateCompletion(completion: EvidenceRecheckCompletionV1): void {
  requireCanonicalTimestamp(completion.completed_at, "completed_at");
  requireDigest(completion.outcome_digest, "outcome_digest");
  requireRef(completion.outcome_ref, "outcome_ref");
  requireRef(completion.reason_code, "reason_code");
}

function validateDelivery(
  delivery: EvidenceRecheckStatusDeliveryReceiptV1,
  outboxId: string,
): void {
  if (
    delivery.schema_version !== "private-evidence-recheck-status-delivery-receipt/v1" ||
    delivery.outbox_id !== outboxId ||
    delivery.idempotency_key !== outboxId
  ) {
    throw new EvidenceRecheckStoreInvariantError(
      "Evidence recheck status delivery receipt is invalid.",
    );
  }
  requireCanonicalTimestamp(delivery.accepted_at, "accepted_at");
  requireRef(delivery.destination_receipt, "destination_receipt");
}

function admissionFingerprint(commit: EvidenceRecheckAdmissionCommitV1): string {
  return digest({
    binding_ref: commit.receipt.recheck.binding_ref,
    input_digest: commit.receipt.input_digest,
    receipt_id: commit.receipt.receipt_id,
    recheck_id: commit.receipt.recheck.recheck_id,
    request_key: commit.receipt.recheck.request_key,
    run_id: commit.receipt.run.run_id,
  });
}

function assertExecutionLease(
  stored: StoredAdmissionV1,
  expected: EvidenceRecheckExecutionLeaseV1,
  observedAt: string,
  allowExpired: boolean,
): void {
  const current = stored.execution.lease;
  if (
    current === undefined ||
    current.lease_token !== expected.lease_token ||
    current.owner_id !== expected.owner_id ||
    current.generation !== expected.generation ||
    current.fencing_token !== expected.fencing_token ||
    current.run_id !== expected.run_id ||
    (!allowExpired && Date.parse(current.lease_expires_at) <= Date.parse(observedAt))
  ) {
    throw new EvidenceRecheckStoreConflictError(
      "Evidence recheck execution lease is stale.",
    );
  }
}

function assertOutboxLease(
  outbox: StoredStatusOutboxV1,
  expected: EvidenceRecheckOutboxLeaseV1,
): void {
  const current = outbox.lease;
  if (
    current === undefined ||
    current.lease_token !== expected.lease_token ||
    current.owner_id !== expected.owner_id ||
    current.generation !== expected.generation ||
    current.fencing_token !== expected.fencing_token ||
    current.outbox_id !== expected.outbox_id
  ) {
    throw new EvidenceRecheckStoreConflictError("Evidence recheck outbox lease is stale.");
  }
}

function parseBinding(document: AtomicDocument): StoredBindingV1 {
  const value = document.value as Partial<StoredBindingV1>;
  if (
    value.schema_version !== "private-evidence-recheck-binding/v1" ||
    value.binding === undefined ||
    typeof value.fingerprint !== "string"
  ) {
    throw new EvidenceRecheckStoreInvariantError("Evidence binding document is invalid.");
  }
  return value as StoredBindingV1;
}

function parseAdmission(document: AtomicDocument): StoredAdmissionV1 {
  const value = document.value as Partial<StoredAdmissionV1>;
  if (
    value.schema_version !== "private-evidence-recheck-admission/v1" ||
    value.commit === undefined ||
    value.current_recheck === undefined ||
    value.execution === undefined ||
    !Array.isArray(value.outbox) ||
    typeof value.request_fingerprint !== "string"
  ) {
    throw new EvidenceRecheckStoreInvariantError(
      "Evidence recheck admission document is invalid.",
    );
  }
  return value as StoredAdmissionV1;
}

function admissionKey(receiptId: string): string {
  return `${ADMISSION_PREFIX}${encodeURIComponent(receiptId)}`;
}

function bindingKey(bindingRef: string): string {
  return `${BINDING_PREFIX}${encodeURIComponent(bindingRef)}`;
}

function expiresAt(observedAt: string, durationMs: number): string {
  return new Date(Date.parse(observedAt) + durationMs).toISOString();
}

function requireCanonicalTimestamp(value: string, field: string): void {
  if (
    typeof value !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) ||
    !Number.isFinite(Date.parse(value)) ||
    new Date(Date.parse(value)).toISOString() !== value
  ) {
    throw new EvidenceRecheckStoreInvariantError(`${field} must be canonical UTC.`);
  }
}

function requireDigest(value: string, field: string): void {
  if (typeof value !== "string" || !/^sha256:[a-f0-9]{64}$/.test(value)) {
    throw new EvidenceRecheckStoreInvariantError(`${field} must be a SHA-256 digest.`);
  }
}

function requirePositiveInteger(value: number, field: string): void {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new EvidenceRecheckStoreInvariantError(`${field} must be a positive integer.`);
  }
}

function requireRef(value: string, field: string): void {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 2_048 ||
    value.trim() !== value ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw new EvidenceRecheckStoreInvariantError(`${field} must be a bounded opaque reference.`);
  }
}

function digest(value: unknown): string {
  return `sha256:${digestHex(value)}`;
}

function digestHex(value: unknown): string {
  return createHash("sha256").update(stableJson(value)).digest("hex");
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .filter(([, item]) => item !== undefined)
      .sort(([left], [right]) => compareOrdinal(left, right))
      .map(([key, item]) => `${JSON.stringify(key)}:${stableJson(item)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function compareOrdinal(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function clone<T>(value: T): T {
  return structuredClone(value);
}
