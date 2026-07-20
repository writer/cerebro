import type {
  DeliveryClaimRequest,
  DeliveryClaimResult,
  DeliveryCompletionRequest,
  DeliveryFailureRequest,
  DeliveryMaintenanceRequest,
  DeliveryPartClaim,
  DeliveryPlanResult,
  DeliveryReceiptV1,
  DeliveryRetryPolicyV1,
  DurableDeliveryPlan,
  WorkLeaseV1,
} from "./contracts.js";
import type { DurableDeliveryPort } from "./ports.js";

export class DeliveryConflictError extends Error {}
export class DeliveryFenceError extends Error {}
export class DeliveryNotFoundError extends Error {}

interface StoredDelivery {
  attempts: Map<string, number>;
  claims: Map<string, DeliveryPartClaim>;
  maxAttempts: number;
  nextAttemptAt: Map<string, string>;
  pausedStates: Map<string, DeliveryReceiptV1["parts"][number]["state"]>;
  payloadFingerprint: string;
  receipt: DeliveryReceiptV1;
  retryPolicy?: DeliveryRetryPolicyV1;
}

/** Conformance fixture only. Production adapters must use durable storage. */
export class ReferenceMemoryDeliveryStore implements DurableDeliveryPort {
  private activeGeneration: number;
  private readonly acceptedLeaseByRun = new Map<string, WorkLeaseV1>();
  private readonly deliveries = new Map<string, StoredDelivery>();
  private failPlan = false;
  private failCompletion = false;

  constructor(activeGeneration: number) {
    this.activeGeneration = activeGeneration;
  }

  plan(delivery: DurableDeliveryPlan): Promise<DeliveryPlanResult> {
    if (this.failPlan) {
      this.failPlan = false;
      return Promise.reject(new Error("injected delivery plan failure"));
    }
    const prior = this.deliveries.get(delivery.receipt.delivery_id);
    if (prior !== undefined) {
      if (prior.payloadFingerprint !== delivery.payload_fingerprint) {
        return Promise.reject(
          new DeliveryConflictError(
            "The delivery identity already has a different payload.",
          ),
        );
      }
      return Promise.resolve({ created: false, receipt: copy(prior.receipt) });
    }
    this.deliveries.set(delivery.receipt.delivery_id, {
      attempts: new Map(),
      claims: new Map(),
      maxAttempts: delivery.max_attempts,
      nextAttemptAt: new Map(),
      pausedStates: new Map(),
      payloadFingerprint: delivery.payload_fingerprint,
      receipt: copy(delivery.receipt),
      ...(delivery.retry_policy === undefined ? {} : { retryPolicy: copy(delivery.retry_policy) }),
    });
    return Promise.resolve({ created: true, receipt: copy(delivery.receipt) });
  }

  async claimNext(request: DeliveryClaimRequest): Promise<DeliveryClaimResult> {
    const stored = this.requireDelivery(request.delivery_id);
    if (request.lease.run_id !== stored.receipt.run_id) {
      throw new DeliveryFenceError("The lease belongs to another run.");
    }
    if (stored.receipt.state === "abandoned") {
      return {
        reason: "abandoned",
        receipt: copy(stored.receipt),
        status: "idle",
      };
    }
    if (stored.receipt.state === "paused") {
      return {
        reason: "paused",
        receipt: copy(stored.receipt),
        status: "idle",
      };
    }
    this.acceptLease(request.lease, request.now);

    const part = [...stored.receipt.parts].sort(
      (left, right) => left.sequence - right.sequence,
    ).find((candidate) => candidate.state !== "delivered");
    if (part === undefined) {
      stored.receipt.state = "completed";
      return {
        reason: "complete",
        receipt: copy(stored.receipt),
        status: "idle",
      };
    }
    if (part.state === "abandoned") {
      stored.receipt.state = "abandoned";
      return {
        reason: "abandoned",
        receipt: copy(stored.receipt),
        status: "idle",
      };
    }
    if (part.state === "paused") {
      stored.receipt.state = "paused";
      return {
        reason: "paused",
        receipt: copy(stored.receipt),
        status: "idle",
      };
    }

    const attempts = stored.attempts.get(part.part_id) ?? 0;
    if (attempts >= stored.maxAttempts) {
      stored.receipt.state = "failed";
      return {
        reason: "retry_exhausted",
        receipt: copy(stored.receipt),
        status: "idle",
      };
    }
    const nextAttemptAt = stored.nextAttemptAt.get(part.part_id);
    if (
      nextAttemptAt !== undefined
      && Date.parse(nextAttemptAt) > Date.parse(request.now)
    ) {
      return {
        next_attempt_at: nextAttemptAt,
        reason: "waiting_for_retry",
        receipt: copy(stored.receipt),
        status: "idle",
      };
    }
    const priorClaim = stored.claims.get(part.part_id);
    if (priorClaim !== undefined) {
      if (sameLease(priorClaim.lease, request.lease)) {
        return { claim: copy(priorClaim), status: "claimed" };
      }
      if (Date.parse(priorClaim.lease.lease_expires_at) > Date.parse(request.now)) {
        return {
          reason: "busy",
          receipt: copy(stored.receipt),
          status: "idle",
        };
      }
      if (request.lease.fencing_token <= priorClaim.lease.fencing_token) {
        throw new DeliveryFenceError(
          "Expired delivery claims require a newer fencing value.",
        );
      }
    }

    const claim: DeliveryPartClaim = {
      attempt: attempts + 1,
      client_message_id: part.idempotency_key,
      delivery_id: request.delivery_id,
      lease: copy(request.lease),
      part: copy({ ...part, state: "delivering" }),
    };
    stored.attempts.set(part.part_id, claim.attempt);
    stored.claims.set(part.part_id, copy(claim));
    stored.nextAttemptAt.delete(part.part_id);
    part.state = "delivering";
    stored.receipt.state = "delivering";
    stored.receipt.updated_at = request.now;
    return { claim: copy(claim), status: "claimed" };
  }

  async pause(request: DeliveryMaintenanceRequest): Promise<DeliveryReceiptV1> {
    const stored = this.requireDelivery(request.delivery_id);
    if (["abandoned", "completed"].includes(stored.receipt.state)) {
      return copy(stored.receipt);
    }
    this.requireRun(stored, request.lease);
    this.acceptLease(request.lease, request.occurred_at);
    for (const part of stored.receipt.parts) {
      if (
        part.state === "delivered" ||
        part.state === "abandoned" ||
        part.state === "paused"
      ) {
        continue;
      }
      stored.pausedStates.set(
        part.part_id,
        part.state === "delivering" ? "pending" : part.state,
      );
      part.state = "paused";
    }
    stored.claims.clear();
    stored.receipt.state = "paused";
    stored.receipt.updated_at = request.occurred_at;
    return copy(stored.receipt);
  }

  async resume(request: DeliveryMaintenanceRequest): Promise<DeliveryReceiptV1> {
    const stored = this.requireDelivery(request.delivery_id);
    if (stored.receipt.state === "abandoned") {
      throw new DeliveryConflictError("An abandoned delivery cannot resume.");
    }
    if (stored.receipt.state === "completed") {
      return copy(stored.receipt);
    }
    this.requireRun(stored, request.lease);
    this.acceptLease(request.lease, request.occurred_at);
    if (stored.receipt.state !== "paused") {
      return copy(stored.receipt);
    }
    for (const part of stored.receipt.parts) {
      if (part.state !== "paused") {
        continue;
      }
      part.state = stored.pausedStates.get(part.part_id) ?? "pending";
    }
    stored.pausedStates.clear();
    stored.receipt.state = aggregate(stored);
    stored.receipt.updated_at = request.occurred_at;
    return copy(stored.receipt);
  }

  async abandon(request: DeliveryMaintenanceRequest): Promise<DeliveryReceiptV1> {
    const stored = this.requireDelivery(request.delivery_id);
    if (stored.receipt.state === "abandoned") {
      return copy(stored.receipt);
    }
    if (stored.receipt.state === "completed") {
      return copy(stored.receipt);
    }
    this.requireRun(stored, request.lease);
    this.acceptLease(request.lease, request.occurred_at);
    for (const part of stored.receipt.parts) {
      if (part.state !== "delivered") {
        part.state = "abandoned";
      }
    }
    stored.claims.clear();
    stored.pausedStates.clear();
    stored.receipt.state = "abandoned";
    stored.receipt.updated_at = request.occurred_at;
    return copy(stored.receipt);
  }

  async completePart(
    request: DeliveryCompletionRequest,
  ): Promise<DeliveryReceiptV1> {
    if (this.failCompletion) {
      this.failCompletion = false;
      return Promise.reject(new Error("injected completion failure"));
    }
    const stored = this.requireDelivery(request.delivery_id);
    if (!request.destination_receipt) {
      throw new DeliveryConflictError("A destination receipt is required.");
    }
    const part = requirePart(stored.receipt, request.part_id);
    if (part.state === "delivered") {
      if (part.destination_receipt !== request.destination_receipt) {
        return Promise.reject(
          new DeliveryConflictError(
            "The part already has a different destination receipt.",
          ),
        );
      }
      return Promise.resolve(copy(stored.receipt));
    }
    this.requireClaim(stored, request.part_id, request.lease, request.accepted_at);
    part.delivered_at = request.accepted_at;
    part.destination_receipt = request.destination_receipt;
    part.state = "delivered";
    stored.claims.delete(request.part_id);
    stored.receipt.updated_at = request.accepted_at;
    stored.receipt.state = aggregate(stored);
    return Promise.resolve(copy(stored.receipt));
  }

  async recordFailure(request: DeliveryFailureRequest): Promise<DeliveryReceiptV1> {
    const stored = this.requireDelivery(request.delivery_id);
    const part = requirePart(stored.receipt, request.part_id);
    this.requireClaim(stored, request.part_id, request.lease, request.failed_at);
    part.state = "failed";
    stored.claims.delete(request.part_id);
    if ((stored.attempts.get(part.part_id) ?? 0) < stored.maxAttempts) {
      const nextAttemptAt = nextDeliveryAttemptAt(stored, part.part_id, request.failed_at);
      if (nextAttemptAt !== undefined) {
        stored.nextAttemptAt.set(part.part_id, nextAttemptAt);
      }
    }
    stored.receipt.updated_at = request.failed_at;
    stored.receipt.state = aggregate(stored);
    return Promise.resolve(copy(stored.receipt));
  }

  read(deliveryId: string): Promise<DeliveryReceiptV1 | undefined> {
    const stored = this.deliveries.get(deliveryId);
    return Promise.resolve(stored === undefined ? undefined : copy(stored.receipt));
  }

  failNextCompletion(): void {
    this.failCompletion = true;
  }

  failNextPlan(): void {
    this.failPlan = true;
  }

  claimCount(deliveryId: string): number {
    return this.requireDelivery(deliveryId).claims.size;
  }

  setActiveGeneration(generation: number): void {
    this.activeGeneration = generation;
  }

  private acceptLease(lease: WorkLeaseV1, now: string): void {
    if (lease.generation !== this.activeGeneration) {
      throw new DeliveryFenceError("The lease generation is not active.");
    }
    if (Date.parse(lease.lease_expires_at) <= Date.parse(now)) {
      throw new DeliveryFenceError("The delivery lease has expired.");
    }
    const prior = this.acceptedLeaseByRun.get(lease.run_id);
    if (prior !== undefined) {
      if (lease.fencing_token < prior.fencing_token) {
        throw new DeliveryFenceError("The fencing value is stale.");
      }
      if (
        lease.fencing_token === prior.fencing_token &&
        !sameLease(lease, prior)
      ) {
        throw new DeliveryFenceError(
          "A fencing value cannot be reused by another lease.",
        );
      }
    }
    this.acceptedLeaseByRun.set(lease.run_id, copy(lease));
  }

  private requireClaim(
    stored: StoredDelivery,
    partId: string,
    lease: WorkLeaseV1,
    occurredAt: string,
  ): DeliveryPartClaim {
    if (lease.generation !== this.activeGeneration) {
      throw new DeliveryFenceError("The lease generation is not active.");
    }
    const accepted = this.acceptedLeaseByRun.get(lease.run_id);
    if (accepted === undefined || !sameLease(accepted, lease)) {
      throw new DeliveryFenceError("A newer lease owns this delivery.");
    }
    const claim = stored.claims.get(partId);
    if (claim === undefined || !sameLease(claim.lease, lease)) {
      throw new DeliveryFenceError("The lease does not own this delivery part.");
    }
    if (Date.parse(lease.lease_expires_at) <= Date.parse(occurredAt)) {
      throw new DeliveryFenceError("The delivery lease expired before this update.");
    }
    return claim;
  }

  private requireRun(stored: StoredDelivery, lease: WorkLeaseV1): void {
    if (lease.run_id !== stored.receipt.run_id) {
      throw new DeliveryFenceError("The lease belongs to another run.");
    }
  }

  private requireDelivery(deliveryId: string): StoredDelivery {
    const delivery = this.deliveries.get(deliveryId);
    if (delivery === undefined) {
      throw new DeliveryNotFoundError("The delivery does not exist.");
    }
    return delivery;
  }
}

function nextDeliveryAttemptAt(
  stored: StoredDelivery,
  partId: string,
  failedAt: string,
): string | undefined {
  const policy = stored.retryPolicy;
  if (policy === undefined) return undefined;
  const attempts = stored.attempts.get(partId) ?? 0;
  const delaySeconds = Math.min(
    policy.max_delay_seconds,
    policy.initial_delay_seconds * Math.pow(policy.multiplier, Math.max(0, attempts - 1)),
  );
  return new Date(Date.parse(failedAt) + delaySeconds * 1_000).toISOString();
}

function aggregate(stored: StoredDelivery): DeliveryReceiptV1["state"] {
  if (stored.receipt.parts.every((part) => part.state === "delivered")) {
    return "completed";
  }
  if (stored.receipt.parts.some((part) => part.state === "abandoned")) {
    return "abandoned";
  }
  if (stored.receipt.parts.some((part) => part.state === "paused")) {
    return "paused";
  }
  if (
    stored.receipt.parts.some(
      (part) =>
        part.state === "failed" &&
        (stored.attempts.get(part.part_id) ?? 0) >= stored.maxAttempts,
    )
  ) {
    return "failed";
  }
  if (
    stored.receipt.parts.some((part) =>
      ["delivering", "delivered", "failed"].includes(part.state)
    )
  ) {
    return "delivering";
  }
  return "pending";
}

function requirePart(
  receipt: DeliveryReceiptV1,
  partId: string,
): DeliveryReceiptV1["parts"][number] {
  const part = receipt.parts.find((candidate) => candidate.part_id === partId);
  if (part === undefined) {
    throw new DeliveryNotFoundError("The delivery part does not exist.");
  }
  return part;
}

function sameLease(left: WorkLeaseV1, right: WorkLeaseV1): boolean {
  return (
    left.fencing_token === right.fencing_token &&
    left.generation === right.generation &&
    left.heartbeat_at === right.heartbeat_at &&
    left.lease_expires_at === right.lease_expires_at &&
    left.lease_token === right.lease_token &&
    left.owner_id === right.owner_id &&
    left.run_id === right.run_id &&
    left.schema_version === right.schema_version
  );
}

function copy<T>(value: T): T {
  return structuredClone(value);
}
