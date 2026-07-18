export type CapacityPermitState = "active" | "expired" | "released";

export interface CapacityPoolV1 {
  permit_limit: number;
  resource_ref: string;
  schema_version: "capacity-pool/v1";
}

export interface CapacityPermitV1 {
  acquired_at: string;
  acquisition_key: string;
  expired_at?: string;
  expires_at: string;
  fencing_token: number;
  generation: number;
  owner_id: string;
  permit_id: string;
  release_key?: string;
  released_at?: string;
  resource_ref: string;
  run_id: string;
  schema_version: "capacity-permit/v1";
  slot: number;
  state: CapacityPermitState;
}

export interface CapacityAcquireRequest {
  acquired_at: string;
  acquisition_key: string;
  expires_at: string;
  generation: number;
  owner_id: string;
  permit_id: string;
  permit_limit: number;
  resource_ref: string;
  run_id: string;
}

export type CapacityUnavailableReason =
  | "capacity"
  | "cooldown"
  | "reconciliation_required";

export type CapacityAcquireResult =
  | {
      permit: CapacityPermitV1;
      replayed: boolean;
      status: "acquired";
    }
  | {
      next_available_at?: string;
      reason: CapacityUnavailableReason;
      replayed: boolean;
      status: "unavailable";
    };

export interface CapacityReleaseRequest {
  fencing_token: number;
  generation: number;
  owner_id: string;
  permit_id: string;
  release_key: string;
  released_at: string;
  resource_ref: string;
  run_id: string;
}

export interface CapacityReleaseReceiptV1 {
  fencing_token: number;
  generation: number;
  owner_id: string;
  permit_id: string;
  release_key: string;
  released_at: string;
  resource_ref: string;
  run_id: string;
  schema_version: "capacity-release/v1";
}

export interface CapacityReleaseResult {
  permit: CapacityPermitV1;
  receipt: CapacityReleaseReceiptV1;
  replayed: boolean;
}

export interface CapacityCooldownRequest {
  cooldown_key: string;
  cooldown_until: string;
  observed_at: string;
  resource_ref: string;
}

export interface CapacityCooldownV1 extends CapacityCooldownRequest {
  schema_version: "capacity-cooldown/v1";
}

export interface CapacityCooldownResult {
  cooldown: CapacityCooldownV1;
  effective_cooldown_until: string;
  replayed: boolean;
}

export interface CapacityReclaimResult {
  permit: CapacityPermitV1;
  reclaimed: boolean;
}

export interface CapacityReleaseFailure {
  error: unknown;
  permit: CapacityPermitV1;
}

export class CapacityInvariantError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CapacityInvariantError";
  }
}

export class CapacityIdempotencyConflictError extends CapacityInvariantError {
  constructor(message = "capacity idempotency key has different input") {
    super(message);
    this.name = "CapacityIdempotencyConflictError";
  }
}

export class StaleCapacityPermitError extends CapacityInvariantError {
  constructor(message = "capacity permit proof is stale") {
    super(message);
    this.name = "StaleCapacityPermitError";
  }
}

/**
 * Runs work under an already-acquired permit without allowing cleanup failure
 * to replace the work outcome. A durable permit that cannot be released stays
 * fenced and is recovered through its expiry path.
 */
export async function runWithCapacityPermit<T>(
  permit: CapacityPermitV1,
  work: () => Promise<T>,
  release: () => Promise<unknown>,
  onReleaseFailure?: (failure: CapacityReleaseFailure) => void | Promise<void>,
): Promise<T> {
  let result: T;
  let workError: unknown;
  let workFailed = false;

  try {
    result = await work();
  } catch (error) {
    workFailed = true;
    workError = error;
  }

  try {
    await release();
  } catch (error) {
    try {
      await onReleaseFailure?.({ error, permit: structuredClone(permit) });
    } catch {
      // Reporting must not replace either the work result or work failure.
    }
  }

  if (workFailed) {
    throw workError;
  }
  return result!;
}

export function assertCapacityPool(pool: CapacityPoolV1): void {
  if (pool.schema_version !== "capacity-pool/v1") {
    throw new CapacityInvariantError("capacity pool schema is unsupported");
  }
  requireOpaque(pool.resource_ref, "resource_ref");
  requirePositiveInteger(pool.permit_limit, "permit_limit");
}

export function assertCapacityAcquireRequest(
  request: CapacityAcquireRequest,
): void {
  requireOpaque(request.acquisition_key, "acquisition_key");
  requireOpaque(request.owner_id, "owner_id");
  requireOpaque(request.permit_id, "permit_id");
  requireOpaque(request.resource_ref, "resource_ref");
  requireOpaque(request.run_id, "run_id");
  requirePositiveInteger(request.generation, "generation");
  requirePositiveInteger(request.permit_limit, "permit_limit");
  requireCanonicalTime(request.acquired_at, "acquired_at");
  requireCanonicalTime(request.expires_at, "expires_at");
  if (Date.parse(request.expires_at) <= Date.parse(request.acquired_at)) {
    throw new CapacityInvariantError("expires_at must be after acquired_at");
  }
}

export function assertCapacityReleaseRequest(
  request: CapacityReleaseRequest,
): void {
  requireOpaque(request.owner_id, "owner_id");
  requireOpaque(request.permit_id, "permit_id");
  requireOpaque(request.release_key, "release_key");
  requireOpaque(request.resource_ref, "resource_ref");
  requireOpaque(request.run_id, "run_id");
  requirePositiveInteger(request.fencing_token, "fencing_token");
  requirePositiveInteger(request.generation, "generation");
  requireCanonicalTime(request.released_at, "released_at");
}

export function assertCapacityCooldownRequest(
  request: CapacityCooldownRequest,
): void {
  requireOpaque(request.cooldown_key, "cooldown_key");
  requireOpaque(request.resource_ref, "resource_ref");
  requireCanonicalTime(request.observed_at, "observed_at");
  requireCanonicalTime(request.cooldown_until, "cooldown_until");
  if (Date.parse(request.cooldown_until) <= Date.parse(request.observed_at)) {
    throw new CapacityInvariantError(
      "cooldown_until must be after observed_at",
    );
  }
}

export function assertCapacityPermit(permit: CapacityPermitV1): void {
  if (permit.schema_version !== "capacity-permit/v1") {
    throw new CapacityInvariantError("capacity permit schema is unsupported");
  }
  assertCapacityAcquireRequest({
    acquired_at: permit.acquired_at,
    acquisition_key: permit.acquisition_key,
    expires_at: permit.expires_at,
    generation: permit.generation,
    owner_id: permit.owner_id,
    permit_id: permit.permit_id,
    permit_limit: permit.slot + 1,
    resource_ref: permit.resource_ref,
    run_id: permit.run_id,
  });
  requireNonNegativeInteger(permit.slot, "slot");
  requirePositiveInteger(permit.fencing_token, "fencing_token");

  if (permit.state === "active") {
    if (
      permit.expired_at !== undefined ||
      permit.release_key !== undefined ||
      permit.released_at !== undefined
    ) {
      throw new CapacityInvariantError("active permit cannot be terminal");
    }
    return;
  }
  if (permit.state === "expired") {
    requireCanonicalTime(permit.expired_at ?? "", "expired_at");
    if (
      permit.expired_at !== permit.expires_at ||
      permit.release_key !== undefined ||
      permit.released_at !== undefined
    ) {
      throw new CapacityInvariantError("expired permit is inconsistent");
    }
    return;
  }
  if (permit.state === "released") {
    requireOpaque(permit.release_key ?? "", "release_key");
    requireCanonicalTime(permit.released_at ?? "", "released_at");
    if (
      permit.expired_at !== undefined ||
      Date.parse(permit.released_at!) < Date.parse(permit.acquired_at) ||
      Date.parse(permit.released_at!) >= Date.parse(permit.expires_at)
    ) {
      throw new CapacityInvariantError("released permit is inconsistent");
    }
    return;
  }
  throw new CapacityInvariantError("capacity permit state is unsupported");
}

export function assertCapacityReleaseReceipt(
  receipt: CapacityReleaseReceiptV1,
): void {
  if (receipt.schema_version !== "capacity-release/v1") {
    throw new CapacityInvariantError("capacity release schema is unsupported");
  }
  assertCapacityReleaseRequest(receipt);
}

export function assertCapacityCooldown(cooldown: CapacityCooldownV1): void {
  if (cooldown.schema_version !== "capacity-cooldown/v1") {
    throw new CapacityInvariantError("capacity cooldown schema is unsupported");
  }
  assertCapacityCooldownRequest(cooldown);
}

export function sameCapacityAcquireRequest(
  left: CapacityAcquireRequest,
  right: CapacityAcquireRequest,
): boolean {
  return (
    left.acquired_at === right.acquired_at &&
    left.acquisition_key === right.acquisition_key &&
    left.expires_at === right.expires_at &&
    left.generation === right.generation &&
    left.owner_id === right.owner_id &&
    left.permit_id === right.permit_id &&
    left.permit_limit === right.permit_limit &&
    left.resource_ref === right.resource_ref &&
    left.run_id === right.run_id
  );
}

export function sameCapacityReleaseRequest(
  left: CapacityReleaseRequest,
  right: CapacityReleaseRequest,
): boolean {
  return (
    left.fencing_token === right.fencing_token &&
    left.generation === right.generation &&
    left.owner_id === right.owner_id &&
    left.permit_id === right.permit_id &&
    left.release_key === right.release_key &&
    left.released_at === right.released_at &&
    left.resource_ref === right.resource_ref &&
    left.run_id === right.run_id
  );
}

export function sameCapacityCooldownRequest(
  left: CapacityCooldownRequest,
  right: CapacityCooldownRequest,
): boolean {
  return (
    left.cooldown_key === right.cooldown_key &&
    left.cooldown_until === right.cooldown_until &&
    left.observed_at === right.observed_at &&
    left.resource_ref === right.resource_ref
  );
}

export function requireCanonicalTime(value: string, field: string): void {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    throw new CapacityInvariantError(
      `${field} must be a canonical ISO-8601 timestamp`,
    );
  }
}

export function requireOpaque(value: string, field: string): void {
  if (
    value.length === 0 ||
    value.trim() !== value ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw new CapacityInvariantError(`${field} must be a non-empty opaque value`);
  }
}

function requirePositiveInteger(value: number, field: string): void {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new CapacityInvariantError(`${field} must be a positive integer`);
  }
}

function requireNonNegativeInteger(value: number, field: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new CapacityInvariantError(
      `${field} must be a non-negative integer`,
    );
  }
}
