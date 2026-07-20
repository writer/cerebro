import {
  CapacityIdempotencyConflictError,
  CapacityInvariantError,
  StaleCapacityPermitError,
  assertCapacityAcquireRequest,
  assertCapacityCooldown,
  assertCapacityCooldownRequest,
  assertCapacityPermit,
  assertCapacityPool,
  assertCapacityReleaseReceipt,
  assertCapacityReleaseRequest,
  requireCanonicalTime,
  requireOpaque,
  sameCapacityAcquireRequest,
  sameCapacityCooldownRequest,
  sameCapacityReleaseRequest,
} from "./capacity.js";
import type {
  CapacityAcquireRequest,
  CapacityAcquireResult,
  CapacityCooldownRequest,
  CapacityCooldownResult,
  CapacityCooldownV1,
  CapacityPermitV1,
  CapacityPoolV1,
  CapacityReclaimResult,
  CapacityReleaseReceiptV1,
  CapacityReleaseRequest,
  CapacityReleaseResult,
  CapacityUnavailableReason,
} from "./capacity.js";
import type { DurableCapacityPort } from "./capacity-ports.js";

export type CapacityAcquireAttemptV1 =
  | {
      permit_id: string;
      request: CapacityAcquireRequest;
      schema_version: "capacity-acquire-attempt/v1";
      status: "acquired";
    }
  | {
      next_available_at?: string;
      reason: CapacityUnavailableReason;
      request: CapacityAcquireRequest;
      schema_version: "capacity-acquire-attempt/v1";
      status: "unavailable";
    };

export interface CapacityReleaseAttemptV1 {
  receipt: CapacityReleaseReceiptV1;
  request: CapacityReleaseRequest;
  schema_version: "capacity-release-attempt/v1";
}

export interface CapacityCooldownAttemptV1 {
  cooldown: CapacityCooldownV1;
  request: CapacityCooldownRequest;
  schema_version: "capacity-cooldown-attempt/v1";
}

export interface CapacityReferenceSnapshotV1 {
  acquire_attempts: CapacityAcquireAttemptV1[];
  cooldown_attempts: CapacityCooldownAttemptV1[];
  permits: CapacityPermitV1[];
  pools: CapacityPoolV1[];
  release_attempts: CapacityReleaseAttemptV1[];
  schema_version: "capacity-reference-snapshot/v1";
}

/** Conformance fixture only. Production adapters must use durable storage. */
export class ReferenceMemoryCapacityStore implements DurableCapacityPort {
  private readonly acquireAttempts = new Map<string, CapacityAcquireAttemptV1>();
  private readonly cooldownAttempts = new Map<
    string,
    CapacityCooldownAttemptV1
  >();
  private readonly permits = new Map<string, CapacityPermitV1>();
  private readonly pools = new Map<string, CapacityPoolV1>();
  private readonly releaseAttempts = new Map<string, CapacityReleaseAttemptV1>();

  constructor(snapshot?: CapacityReferenceSnapshotV1) {
    if (snapshot !== undefined) {
      this.restore(snapshot);
    }
  }

  async acquire(request: CapacityAcquireRequest): Promise<CapacityAcquireResult> {
    assertCapacityAcquireRequest(request);
    const prior = this.acquireAttempts.get(request.acquisition_key);
    if (prior !== undefined) {
      if (!sameCapacityAcquireRequest(prior.request, request)) {
        throw new CapacityIdempotencyConflictError();
      }
      if (prior.status === "unavailable") {
        return {
          next_available_at: prior.next_available_at,
          reason: prior.reason,
          replayed: true,
          status: "unavailable",
        };
      }
      return {
        permit: structuredClone(this.requirePermit(prior.permit_id)),
        replayed: true,
        status: "acquired",
      };
    }
    if (this.permits.has(request.permit_id)) {
      throw new CapacityIdempotencyConflictError(
        "permit_id already belongs to another acquisition",
      );
    }

    const pool = this.ensurePool(request.resource_ref, request.permit_limit);
    this.rejectGenerationRegression(request);
    const expired = this.activePermits(request.resource_ref).filter(
      (permit) =>
        Date.parse(permit.expires_at) <= Date.parse(request.acquired_at),
    );
    if (expired.length > 0) {
      return this.recordUnavailable(
        request,
        "reconciliation_required",
        earliest(expired.map((permit) => permit.expires_at)),
      );
    }

    const cooldown = this.effectiveCooldown(request.resource_ref);
    if (
      cooldown !== undefined &&
      Date.parse(cooldown.cooldown_until) > Date.parse(request.acquired_at)
    ) {
      return this.recordUnavailable(
        request,
        "cooldown",
        cooldown.cooldown_until,
      );
    }

    const active = this.activePermits(request.resource_ref);
    const occupied = new Set(active.map((permit) => permit.slot));
    const slot = firstFreeSlot(occupied, pool.permit_limit);
    if (slot === undefined) {
      return this.recordUnavailable(
        request,
        "capacity",
        earliest(active.map((permit) => permit.expires_at)),
      );
    }

    const permit: CapacityPermitV1 = {
      acquired_at: request.acquired_at,
      acquisition_key: request.acquisition_key,
      expires_at: request.expires_at,
      fencing_token: this.nextFencingToken(request.resource_ref),
      generation: request.generation,
      owner_id: request.owner_id,
      permit_id: request.permit_id,
      resource_ref: request.resource_ref,
      run_id: request.run_id,
      schema_version: "capacity-permit/v1",
      slot,
      state: "active",
    };
    const attempt: CapacityAcquireAttemptV1 = {
      permit_id: permit.permit_id,
      request: structuredClone(request),
      schema_version: "capacity-acquire-attempt/v1",
      status: "acquired",
    };

    // These mutations model one atomic permit acquisition.
    this.permits.set(permit.permit_id, permit);
    this.acquireAttempts.set(request.acquisition_key, attempt);
    return {
      permit: structuredClone(permit),
      replayed: false,
      status: "acquired",
    };
  }

  async release(request: CapacityReleaseRequest): Promise<CapacityReleaseResult> {
    assertCapacityReleaseRequest(request);
    const prior = this.releaseAttempts.get(request.release_key);
    if (prior !== undefined) {
      if (!sameCapacityReleaseRequest(prior.request, request)) {
        throw new CapacityIdempotencyConflictError();
      }
      return {
        permit: structuredClone(this.requirePermit(request.permit_id)),
        receipt: structuredClone(prior.receipt),
        replayed: true,
      };
    }

    const permit = this.requirePermit(request.permit_id);
    this.assertCurrentProof(permit, request);
    if (
      permit.state !== "active" ||
      Date.parse(request.released_at) >= Date.parse(permit.expires_at)
    ) {
      throw new StaleCapacityPermitError();
    }

    const receipt: CapacityReleaseReceiptV1 = {
      fencing_token: request.fencing_token,
      generation: request.generation,
      owner_id: request.owner_id,
      permit_id: request.permit_id,
      release_key: request.release_key,
      released_at: request.released_at,
      resource_ref: request.resource_ref,
      run_id: request.run_id,
      schema_version: "capacity-release/v1",
    };
    const released: CapacityPermitV1 = {
      ...permit,
      release_key: request.release_key,
      released_at: request.released_at,
      state: "released",
    };
    const attempt: CapacityReleaseAttemptV1 = {
      receipt,
      request: structuredClone(request),
      schema_version: "capacity-release-attempt/v1",
    };

    // These mutations model one atomic, owner-fenced release.
    this.permits.set(permit.permit_id, released);
    this.releaseAttempts.set(request.release_key, attempt);
    return {
      permit: structuredClone(released),
      receipt: structuredClone(receipt),
      replayed: false,
    };
  }

  async recordCooldown(
    request: CapacityCooldownRequest,
  ): Promise<CapacityCooldownResult> {
    assertCapacityCooldownRequest(request);
    const prior = this.cooldownAttempts.get(request.cooldown_key);
    if (prior !== undefined) {
      if (!sameCapacityCooldownRequest(prior.request, request)) {
        throw new CapacityIdempotencyConflictError();
      }
      return {
        cooldown: structuredClone(prior.cooldown),
        effective_cooldown_until:
          this.effectiveCooldown(request.resource_ref)?.cooldown_until ??
          prior.cooldown.cooldown_until,
        replayed: true,
      };
    }

    const cooldown: CapacityCooldownV1 = {
      ...request,
      schema_version: "capacity-cooldown/v1",
    };
    const attempt: CapacityCooldownAttemptV1 = {
      cooldown,
      request: structuredClone(request),
      schema_version: "capacity-cooldown-attempt/v1",
    };
    this.cooldownAttempts.set(request.cooldown_key, attempt);
    return {
      cooldown: structuredClone(cooldown),
      effective_cooldown_until:
        this.effectiveCooldown(request.resource_ref)?.cooldown_until ??
        cooldown.cooldown_until,
      replayed: false,
    };
  }

  async readCooldown(
    resourceRef: string,
  ): Promise<CapacityCooldownV1 | undefined> {
    requireOpaque(resourceRef, "resource_ref");
    const cooldown = this.effectiveCooldown(resourceRef);
    return cooldown === undefined ? undefined : structuredClone(cooldown);
  }

  async readPermit(permitId: string): Promise<CapacityPermitV1 | undefined> {
    requireOpaque(permitId, "permit_id");
    const permit = this.permits.get(permitId);
    return permit === undefined ? undefined : structuredClone(permit);
  }

  async reclaimExpired(
    resourceRef: string,
    observedAt: string,
  ): Promise<CapacityReclaimResult[]> {
    requireOpaque(resourceRef, "resource_ref");
    requireCanonicalTime(observedAt, "observed_at");
    const reclaimed: CapacityReclaimResult[] = [];
    for (const permit of this.activePermits(resourceRef)) {
      if (Date.parse(permit.expires_at) > Date.parse(observedAt)) {
        continue;
      }
      const expired: CapacityPermitV1 = {
        ...permit,
        expired_at: permit.expires_at,
        state: "expired",
      };
      this.permits.set(permit.permit_id, expired);
      reclaimed.push({ permit: structuredClone(expired), reclaimed: true });
    }
    return reclaimed;
  }

  snapshot(): CapacityReferenceSnapshotV1 {
    return structuredClone({
      acquire_attempts: [...this.acquireAttempts.values()],
      cooldown_attempts: [...this.cooldownAttempts.values()],
      permits: [...this.permits.values()],
      pools: [...this.pools.values()],
      release_attempts: [...this.releaseAttempts.values()],
      schema_version: "capacity-reference-snapshot/v1",
    });
  }

  private restore(snapshot: CapacityReferenceSnapshotV1): void {
    if (snapshot.schema_version !== "capacity-reference-snapshot/v1") {
      throw new CapacityInvariantError("capacity snapshot schema is unsupported");
    }
    if (
      !Array.isArray(snapshot.acquire_attempts) ||
      !Array.isArray(snapshot.cooldown_attempts) ||
      !Array.isArray(snapshot.permits) ||
      !Array.isArray(snapshot.pools) ||
      !Array.isArray(snapshot.release_attempts)
    ) {
      throw new CapacityInvariantError("capacity snapshot arrays are required");
    }

    for (const pool of snapshot.pools) {
      assertCapacityPool(pool);
      if (this.pools.has(pool.resource_ref)) {
        throw new CapacityInvariantError("capacity snapshot has duplicate pool");
      }
      this.pools.set(pool.resource_ref, structuredClone(pool));
    }
    const activeSlots = new Set<string>();
    const fencingTokens = new Set<string>();
    for (const permit of snapshot.permits) {
      assertCapacityPermit(permit);
      const pool = this.pools.get(permit.resource_ref);
      if (pool === undefined || permit.slot >= pool.permit_limit) {
        throw new CapacityInvariantError("capacity permit has no valid pool slot");
      }
      if (this.permits.has(permit.permit_id)) {
        throw new CapacityInvariantError("capacity snapshot has duplicate permit");
      }
      const fenceKey = `${permit.resource_ref}\u0000${permit.fencing_token}`;
      if (fencingTokens.has(fenceKey)) {
        throw new CapacityInvariantError("capacity fencing token is not unique");
      }
      fencingTokens.add(fenceKey);
      if (permit.state === "active") {
        const slotKey = `${permit.resource_ref}\u0000${permit.slot}`;
        if (activeSlots.has(slotKey)) {
          throw new CapacityInvariantError("capacity slot has multiple owners");
        }
        activeSlots.add(slotKey);
      }
      this.permits.set(permit.permit_id, structuredClone(permit));
    }

    const acquiredPermitIds = new Set<string>();
    const referencedPools = new Set<string>();
    for (const attempt of snapshot.acquire_attempts) {
      if (attempt.schema_version !== "capacity-acquire-attempt/v1") {
        throw new CapacityInvariantError("capacity acquire attempt is unsupported");
      }
      assertCapacityAcquireRequest(attempt.request);
      if (this.acquireAttempts.has(attempt.request.acquisition_key)) {
        throw new CapacityInvariantError(
          "capacity snapshot has duplicate acquisition key",
        );
      }
      const pool = this.pools.get(attempt.request.resource_ref);
      if (pool?.permit_limit !== attempt.request.permit_limit) {
        throw new CapacityInvariantError("capacity acquire attempt changed its pool");
      }
      referencedPools.add(attempt.request.resource_ref);
      if (attempt.status === "acquired") {
        const permit = this.permits.get(attempt.permit_id);
        if (
          permit === undefined ||
          permit.permit_id !== attempt.request.permit_id ||
          permit.acquisition_key !== attempt.request.acquisition_key ||
          permit.acquired_at !== attempt.request.acquired_at ||
          permit.expires_at !== attempt.request.expires_at ||
          permit.resource_ref !== attempt.request.resource_ref ||
          permit.run_id !== attempt.request.run_id ||
          permit.owner_id !== attempt.request.owner_id ||
          permit.generation !== attempt.request.generation ||
          acquiredPermitIds.has(permit.permit_id)
        ) {
          throw new CapacityInvariantError(
            "capacity acquisition does not match its permit",
          );
        }
        acquiredPermitIds.add(permit.permit_id);
      } else {
        assertUnavailableAttempt(attempt);
      }
      this.acquireAttempts.set(
        attempt.request.acquisition_key,
        structuredClone(attempt),
      );
    }
    if (
      acquiredPermitIds.size !== this.permits.size ||
      referencedPools.size !== this.pools.size
    ) {
      throw new CapacityInvariantError(
        "capacity snapshot contains unreferenced durable state",
      );
    }

    const releasedPermitIds = new Set<string>();
    for (const attempt of snapshot.release_attempts) {
      if (attempt.schema_version !== "capacity-release-attempt/v1") {
        throw new CapacityInvariantError("capacity release attempt is unsupported");
      }
      assertCapacityReleaseRequest(attempt.request);
      assertCapacityReleaseReceipt(attempt.receipt);
      if (
        this.releaseAttempts.has(attempt.request.release_key) ||
        !sameCapacityReleaseRequest(attempt.request, attempt.receipt)
      ) {
        throw new CapacityInvariantError("capacity release attempt is inconsistent");
      }
      const permit = this.permits.get(attempt.request.permit_id);
      if (
        permit?.state !== "released" ||
        permit.release_key !== attempt.request.release_key
      ) {
        throw new CapacityInvariantError("capacity release has no released permit");
      }
      releasedPermitIds.add(permit.permit_id);
      this.releaseAttempts.set(
        attempt.request.release_key,
        structuredClone(attempt),
      );
    }
    for (const permit of this.permits.values()) {
      if (
        permit.state === "released" &&
        !releasedPermitIds.has(permit.permit_id)
      ) {
        throw new CapacityInvariantError(
          "released capacity permit has no release receipt",
        );
      }
    }

    for (const attempt of snapshot.cooldown_attempts) {
      if (attempt.schema_version !== "capacity-cooldown-attempt/v1") {
        throw new CapacityInvariantError(
          "capacity cooldown attempt is unsupported",
        );
      }
      assertCapacityCooldownRequest(attempt.request);
      assertCapacityCooldown(attempt.cooldown);
      if (
        this.cooldownAttempts.has(attempt.request.cooldown_key) ||
        !sameCapacityCooldownRequest(attempt.request, attempt.cooldown)
      ) {
        throw new CapacityInvariantError(
          "capacity cooldown attempt is inconsistent",
        );
      }
      this.cooldownAttempts.set(
        attempt.request.cooldown_key,
        structuredClone(attempt),
      );
    }
  }

  private ensurePool(resourceRef: string, permitLimit: number): CapacityPoolV1 {
    const existing = this.pools.get(resourceRef);
    if (existing !== undefined) {
      if (existing.permit_limit !== permitLimit) {
        throw new CapacityInvariantError(
          "capacity limit changed for an established resource",
        );
      }
      return existing;
    }
    const pool: CapacityPoolV1 = {
      permit_limit: permitLimit,
      resource_ref: resourceRef,
      schema_version: "capacity-pool/v1",
    };
    this.pools.set(resourceRef, pool);
    return pool;
  }

  private recordUnavailable(
    request: CapacityAcquireRequest,
    reason: CapacityUnavailableReason,
    nextAvailableAt?: string,
  ): CapacityAcquireResult {
    const attempt: CapacityAcquireAttemptV1 = {
      next_available_at: nextAvailableAt,
      reason,
      request: structuredClone(request),
      schema_version: "capacity-acquire-attempt/v1",
      status: "unavailable",
    };
    this.acquireAttempts.set(request.acquisition_key, attempt);
    return {
      next_available_at: nextAvailableAt,
      reason,
      replayed: false,
      status: "unavailable",
    };
  }

  private activePermits(resourceRef: string): CapacityPermitV1[] {
    return [...this.permits.values()].filter(
      (permit) =>
        permit.resource_ref === resourceRef && permit.state === "active",
    );
  }

  private effectiveCooldown(resourceRef: string): CapacityCooldownV1 | undefined {
    let selected: CapacityCooldownV1 | undefined;
    for (const attempt of this.cooldownAttempts.values()) {
      const cooldown = attempt.cooldown;
      if (
        cooldown.resource_ref === resourceRef &&
        (selected === undefined ||
          Date.parse(cooldown.cooldown_until) >
            Date.parse(selected.cooldown_until))
      ) {
        selected = cooldown;
      }
    }
    return selected;
  }

  private nextFencingToken(resourceRef: string): number {
    let highest = 0;
    for (const permit of this.permits.values()) {
      if (permit.resource_ref === resourceRef) {
        highest = Math.max(highest, permit.fencing_token);
      }
    }
    const next = highest + 1;
    if (!Number.isSafeInteger(next)) {
      throw new CapacityInvariantError("capacity fencing token is exhausted");
    }
    return next;
  }

  private rejectGenerationRegression(request: CapacityAcquireRequest): void {
    let highest = 0;
    for (const permit of this.permits.values()) {
      if (
        permit.resource_ref === request.resource_ref &&
        permit.run_id === request.run_id
      ) {
        highest = Math.max(highest, permit.generation);
      }
    }
    if (request.generation < highest) {
      throw new StaleCapacityPermitError("capacity generation regressed");
    }
  }

  private assertCurrentProof(
    permit: CapacityPermitV1,
    request: CapacityReleaseRequest,
  ): void {
    if (
      permit.fencing_token !== request.fencing_token ||
      permit.generation !== request.generation ||
      permit.owner_id !== request.owner_id ||
      permit.resource_ref !== request.resource_ref ||
      permit.run_id !== request.run_id
    ) {
      throw new StaleCapacityPermitError();
    }
  }

  private requirePermit(permitId: string): CapacityPermitV1 {
    const permit = this.permits.get(permitId);
    if (permit === undefined) {
      throw new CapacityInvariantError("capacity permit does not exist");
    }
    return permit;
  }
}

function firstFreeSlot(
  occupied: ReadonlySet<number>,
  permitLimit: number,
): number | undefined {
  let candidate = 0;
  for (const slot of [...occupied].sort((left, right) => left - right)) {
    if (slot === candidate) {
      candidate += 1;
    } else if (slot > candidate) {
      break;
    }
  }
  return candidate < permitLimit ? candidate : undefined;
}

function earliest(values: readonly string[]): string | undefined {
  return values.length === 0
    ? undefined
    : [...values].sort((left, right) => Date.parse(left) - Date.parse(right))[0];
}

function assertUnavailableAttempt(
  attempt: Extract<CapacityAcquireAttemptV1, { status: "unavailable" }>,
): void {
  if (
    attempt.reason !== "capacity" &&
    attempt.reason !== "cooldown" &&
    attempt.reason !== "reconciliation_required"
  ) {
    throw new CapacityInvariantError("capacity unavailable reason is unsupported");
  }
  if (attempt.next_available_at !== undefined) {
    requireCanonicalTime(attempt.next_available_at, "next_available_at");
  }
}
