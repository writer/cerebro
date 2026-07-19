import {
  assertCapacityCooldown,
  requireCanonicalTime,
  requireOpaque,
  type CapacityCooldownV1,
} from "./capacity.js";
import {
  emptyConsecutiveFailureState,
  recordConsecutiveFailure,
  resetConsecutiveFailures,
  type ConsecutiveFailurePolicy,
  type ConsecutiveFailureStateV1,
} from "./repeated-failure-policy.js";

const SOURCE_HEALTH_FAILURE_FINGERPRINT = "source-health-failure/v1";
const MAX_DATE_TIMESTAMP = 8_640_000_000_000_000;

export type SourceHealthStatus = "cooldown" | "degraded" | "healthy";

export interface SourceHealthPolicy {
  cooldown_ms: number;
  failure_policy: ConsecutiveFailurePolicy;
  slow_threshold_ms: number;
}

export interface SourceHealthObservationInputV1 {
  idempotency_key: string;
  kind: "failure" | "success";
  latency_ms: number;
  observed_at: string;
}

export interface SourceHealthObservationReceiptV1
  extends SourceHealthObservationInputV1 {
  schema_version: "source-health-observation/v1";
}

export interface SourceHealthStateV1 {
  cooldown?: CapacityCooldownV1;
  failure_state: ConsecutiveFailureStateV1;
  observation_receipts: SourceHealthObservationReceiptV1[];
  schema_version: "source-health-state/v1";
  source_ref: string;
}

export interface SourceHealthSnapshotV1 {
  allowed: boolean;
  attempts: number;
  average_latency_ms: number;
  consecutive_failures: number;
  retry_after_ms?: number;
  schema_version: "source-health-snapshot/v1";
  slow: boolean;
  source_ref: string;
  status: SourceHealthStatus;
  success_rate: number;
}

export interface SourceHealthObservationResult {
  receipt: SourceHealthObservationReceiptV1;
  replayed: boolean;
  state: SourceHealthStateV1;
}

export class SourceHealthPolicyInvariantError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SourceHealthPolicyInvariantError";
  }
}

export class SourceHealthObservationConflictError extends Error {
  constructor() {
    super("idempotency key belongs to a different source health observation");
    this.name = "SourceHealthObservationConflictError";
  }
}

export function emptySourceHealthState(
  sourceRef: string,
  inputPolicy: SourceHealthPolicy,
): SourceHealthStateV1 {
  requireOpaque(sourceRef, "source_ref");
  const policy = validatePolicy(inputPolicy);
  return {
    failure_state: emptyConsecutiveFailureState(policy.failure_policy),
    observation_receipts: [],
    schema_version: "source-health-state/v1",
    source_ref: sourceRef,
  };
}

export function assertSourceHealthState(
  state: SourceHealthStateV1,
  inputPolicy: SourceHealthPolicy,
): void {
  const policy = validatePolicy(inputPolicy);
  validateState(state, policy);
}

export function recordSourceHealthObservation(input: {
  observation: SourceHealthObservationInputV1;
  policy: SourceHealthPolicy;
  state: SourceHealthStateV1;
}): SourceHealthObservationResult {
  const policy = validatePolicy(input.policy);
  const state = validateState(input.state, policy);
  const receipt = observationReceipt(input.observation);
  const prior = state.observation_receipts.find(
    (candidate) => candidate.idempotency_key === receipt.idempotency_key,
  );
  if (prior !== undefined) {
    if (!sameObservation(prior, receipt)) {
      throw new SourceHealthObservationConflictError();
    }
    return { receipt: prior, replayed: true, state };
  }

  assertObservationOrder(state.observation_receipts, receipt);
  const failureResult = applyFailureObservation(
    state.failure_state,
    receipt,
    policy.failure_policy,
  );
  const cooldown = nextCooldown(
    state.source_ref,
    state.cooldown,
    receipt,
    failureResult.status,
    policy,
  );
  const next: SourceHealthStateV1 = {
    cooldown,
    failure_state: failureResult.state,
    observation_receipts: [...state.observation_receipts, receipt],
    schema_version: "source-health-state/v1",
    source_ref: state.source_ref,
  };
  validateState(next, policy);
  return { receipt, replayed: false, state: next };
}

export function snapshotSourceHealth(input: {
  observed_at: string;
  policy: SourceHealthPolicy;
  state: SourceHealthStateV1;
}): SourceHealthSnapshotV1 {
  const policy = validatePolicy(input.policy);
  const state = validateState(input.state, policy);
  requireCanonicalTime(input.observed_at, "observed_at");
  const observedAt = Date.parse(input.observed_at);
  const attempts = state.observation_receipts.length;
  const successes = state.observation_receipts.filter(
    (receipt) => receipt.kind === "success",
  ).length;
  const totalLatency = state.observation_receipts.reduce(
    (sum, receipt) => sum + receipt.latency_ms,
    0,
  );
  if (!Number.isSafeInteger(totalLatency)) {
    throw new SourceHealthPolicyInvariantError(
      "total observation latency must be a safe integer",
    );
  }
  const averageLatency = attempts === 0 ? 0 : Math.round(totalLatency / attempts);
  const slow = averageLatency >= policy.slow_threshold_ms;
  const cooldownUntil = state.cooldown?.cooldown_until;
  const retryAfter =
    cooldownUntil === undefined ? 0 : Date.parse(cooldownUntil) - observedAt;
  const coolingDown = retryAfter > 0;
  const degraded = state.failure_state.consecutive_failures > 0 || slow;

  return {
    allowed: !coolingDown,
    attempts,
    average_latency_ms: averageLatency,
    consecutive_failures: state.failure_state.consecutive_failures,
    retry_after_ms: coolingDown ? retryAfter : undefined,
    schema_version: "source-health-snapshot/v1",
    slow,
    source_ref: state.source_ref,
    status: coolingDown ? "cooldown" : degraded ? "degraded" : "healthy",
    success_rate: attempts === 0 ? 0 : successes / attempts,
  };
}

export function rankSourceHealth(
  snapshots: readonly SourceHealthSnapshotV1[],
): SourceHealthSnapshotV1[] {
  const sourceRefs = new Set<string>();
  const indexed = snapshots.map((snapshot, index) => {
    validateSnapshot(snapshot);
    if (sourceRefs.has(snapshot.source_ref)) {
      throw new SourceHealthPolicyInvariantError(
        "source health ranking requires unique source references",
      );
    }
    sourceRefs.add(snapshot.source_ref);
    return { index, snapshot };
  });

  indexed.sort((left, right) => {
    const availability = Number(right.snapshot.allowed) - Number(left.snapshot.allowed);
    if (availability !== 0) return availability;

    const status = statusRank(left.snapshot.status) - statusRank(right.snapshot.status);
    if (status !== 0) return status;

    const success = right.snapshot.success_rate - left.snapshot.success_rate;
    if (success !== 0) return success;

    const latency =
      left.snapshot.average_latency_ms - right.snapshot.average_latency_ms;
    return latency !== 0 ? latency : left.index - right.index;
  });
  return indexed.map(({ snapshot }) => snapshot);
}

function validatePolicy(policy: SourceHealthPolicy): SourceHealthPolicy {
  emptyConsecutiveFailureState(policy.failure_policy);
  requirePositiveInteger(policy.cooldown_ms, "cooldown_ms");
  requirePositiveInteger(policy.slow_threshold_ms, "slow_threshold_ms");
  return policy;
}

function validateState(
  state: SourceHealthStateV1,
  policy: SourceHealthPolicy,
): SourceHealthStateV1 {
  if (state.schema_version !== "source-health-state/v1") {
    throw new SourceHealthPolicyInvariantError(
      "unsupported source health state schema",
    );
  }
  requireOpaque(state.source_ref, "source_ref");
  if (!Array.isArray(state.observation_receipts)) {
    throw new SourceHealthPolicyInvariantError(
      "observation_receipts must be an array",
    );
  }

  let expectedFailureState = emptyConsecutiveFailureState(
    policy.failure_policy,
  );
  let expectedCooldown: CapacityCooldownV1 | undefined;
  const idempotencyKeys = new Set<string>();
  let prior: SourceHealthObservationReceiptV1 | undefined;
  for (const receipt of state.observation_receipts) {
    validateObservationReceipt(receipt);
    if (idempotencyKeys.has(receipt.idempotency_key)) {
      throw new SourceHealthPolicyInvariantError(
        "source health observations require unique idempotency keys",
      );
    }
    idempotencyKeys.add(receipt.idempotency_key);
    if (prior !== undefined) assertObservationOrder([prior], receipt);

    const failureResult = applyFailureObservation(
      expectedFailureState,
      receipt,
      policy.failure_policy,
    );
    expectedFailureState = failureResult.state;
    expectedCooldown = nextCooldown(
      state.source_ref,
      expectedCooldown,
      receipt,
      failureResult.status,
      policy,
    );
    prior = receipt;
  }

  assertSameFailureState(state.failure_state, expectedFailureState);
  assertSameCooldown(state.cooldown, expectedCooldown);
  return state;
}

function observationReceipt(
  observation: SourceHealthObservationInputV1,
): SourceHealthObservationReceiptV1 {
  const receipt: SourceHealthObservationReceiptV1 = {
    ...observation,
    schema_version: "source-health-observation/v1",
  };
  validateObservationReceipt(receipt);
  return receipt;
}

function validateObservationReceipt(
  receipt: SourceHealthObservationReceiptV1,
): void {
  if (receipt.schema_version !== "source-health-observation/v1") {
    throw new SourceHealthPolicyInvariantError(
      "unsupported source health observation schema",
    );
  }
  requireOpaque(receipt.idempotency_key, "idempotency_key");
  requireCanonicalTime(receipt.observed_at, "observed_at");
  requireNonNegativeInteger(receipt.latency_ms, "latency_ms");
  if (receipt.kind !== "failure" && receipt.kind !== "success") {
    throw new SourceHealthPolicyInvariantError(
      "source health observation kind is unsupported",
    );
  }
}

function applyFailureObservation(
  state: ConsecutiveFailureStateV1,
  receipt: SourceHealthObservationReceiptV1,
  policy: ConsecutiveFailurePolicy,
) {
  if (receipt.kind === "failure") {
    return recordConsecutiveFailure({
      failure_fingerprint: SOURCE_HEALTH_FAILURE_FINGERPRINT,
      idempotency_key: receipt.idempotency_key,
      policy,
      state,
    });
  }
  return resetConsecutiveFailures({
    idempotency_key: receipt.idempotency_key,
    policy,
    state,
  });
}

function nextCooldown(
  sourceRef: string,
  current: CapacityCooldownV1 | undefined,
  receipt: SourceHealthObservationReceiptV1,
  failureStatus: "blocked" | "degraded" | "reset",
  policy: SourceHealthPolicy,
): CapacityCooldownV1 | undefined {
  if (receipt.kind === "success") return undefined;
  if (failureStatus !== "blocked") return current;

  const observedAt = Date.parse(receipt.observed_at);
  const cooldownUntil = observedAt + policy.cooldown_ms;
  if (
    !Number.isSafeInteger(cooldownUntil) ||
    cooldownUntil > MAX_DATE_TIMESTAMP
  ) {
    throw new SourceHealthPolicyInvariantError(
      "cooldown_until must be a safe timestamp",
    );
  }
  const cooldown: CapacityCooldownV1 = {
    cooldown_key: sourceHealthCooldownKey(
      sourceRef,
      receipt.idempotency_key,
    ),
    cooldown_until: new Date(cooldownUntil).toISOString(),
    observed_at: receipt.observed_at,
    resource_ref: sourceRef,
    schema_version: "capacity-cooldown/v1",
  };
  assertCapacityCooldown(cooldown);
  return cooldown;
}

function sourceHealthCooldownKey(
  sourceRef: string,
  idempotencyKey: string,
): string {
  return `source-health:${sourceRef.length}:${sourceRef}:${idempotencyKey}`;
}

function assertObservationOrder(
  observations: readonly SourceHealthObservationReceiptV1[],
  next: SourceHealthObservationReceiptV1,
): void {
  const prior = observations.at(-1);
  if (
    prior !== undefined &&
    Date.parse(next.observed_at) < Date.parse(prior.observed_at)
  ) {
    throw new SourceHealthPolicyInvariantError(
      "source health observations must be ordered by observed_at",
    );
  }
}

function sameObservation(
  left: SourceHealthObservationReceiptV1,
  right: SourceHealthObservationReceiptV1,
): boolean {
  return (
    left.schema_version === right.schema_version &&
    left.idempotency_key === right.idempotency_key &&
    left.kind === right.kind &&
    left.latency_ms === right.latency_ms &&
    left.observed_at === right.observed_at
  );
}

function assertSameFailureState(
  actual: ConsecutiveFailureStateV1,
  expected: ConsecutiveFailureStateV1,
): void {
  const sameReceipts =
    Array.isArray(actual.observation_receipts) &&
    actual.observation_receipts.length ===
      expected.observation_receipts.length &&
    actual.observation_receipts.every((receipt, index) => {
      const candidate = expected.observation_receipts[index];
      return (
        candidate !== undefined &&
        receipt.consecutive_failures === candidate.consecutive_failures &&
        receipt.failure_fingerprint === candidate.failure_fingerprint &&
        receipt.idempotency_key === candidate.idempotency_key &&
        receipt.kind === candidate.kind &&
        receipt.status === candidate.status
      );
    });
  if (
    actual.schema_version !== expected.schema_version ||
    actual.block_after_consecutive_failures !==
      expected.block_after_consecutive_failures ||
    actual.consecutive_failures !== expected.consecutive_failures ||
    actual.failure_fingerprint !== expected.failure_fingerprint ||
    actual.observation_receipt_limit !==
      expected.observation_receipt_limit ||
    !sameReceipts
  ) {
    throw new SourceHealthPolicyInvariantError(
      "failure state does not match source health observations",
    );
  }
}

function assertSameCooldown(
  actual: CapacityCooldownV1 | undefined,
  expected: CapacityCooldownV1 | undefined,
): void {
  if (actual === undefined && expected === undefined) return;
  if (actual === undefined || expected === undefined) {
    throw new SourceHealthPolicyInvariantError(
      "cooldown does not match source health observations",
    );
  }
  assertCapacityCooldown(actual);
  if (
    actual.cooldown_key !== expected.cooldown_key ||
    actual.cooldown_until !== expected.cooldown_until ||
    actual.observed_at !== expected.observed_at ||
    actual.resource_ref !== expected.resource_ref ||
    actual.schema_version !== expected.schema_version
  ) {
    throw new SourceHealthPolicyInvariantError(
      "cooldown does not match source health observations",
    );
  }
}

function validateSnapshot(snapshot: SourceHealthSnapshotV1): void {
  if (snapshot.schema_version !== "source-health-snapshot/v1") {
    throw new SourceHealthPolicyInvariantError(
      "unsupported source health snapshot schema",
    );
  }
  requireOpaque(snapshot.source_ref, "source_ref");
  requireNonNegativeInteger(snapshot.attempts, "attempts");
  requireNonNegativeInteger(
    snapshot.consecutive_failures,
    "consecutive_failures",
  );
  requireNonNegativeInteger(
    snapshot.average_latency_ms,
    "average_latency_ms",
  );
  if (
    snapshot.consecutive_failures > snapshot.attempts ||
    !Number.isFinite(snapshot.success_rate) ||
    snapshot.success_rate < 0 ||
    snapshot.success_rate > 1 ||
    typeof snapshot.slow !== "boolean" ||
    typeof snapshot.allowed !== "boolean"
  ) {
    throw new SourceHealthPolicyInvariantError(
      "source health snapshot metrics are inconsistent",
    );
  }
  if (snapshot.status === "cooldown") {
    requirePositiveInteger(snapshot.retry_after_ms ?? 0, "retry_after_ms");
    if (snapshot.allowed || snapshot.consecutive_failures === 0) {
      throw new SourceHealthPolicyInvariantError(
        "cooldown source health snapshots require an active failure streak",
      );
    }
    return;
  }
  if (snapshot.status !== "degraded" && snapshot.status !== "healthy") {
    throw new SourceHealthPolicyInvariantError(
      "source health snapshot status is unsupported",
    );
  }
  if (!snapshot.allowed || snapshot.retry_after_ms !== undefined) {
    throw new SourceHealthPolicyInvariantError(
      "available source health snapshots cannot carry retry_after_ms",
    );
  }
  const degraded = snapshot.slow || snapshot.consecutive_failures > 0;
  if (
    (snapshot.status === "degraded") !== degraded ||
    (snapshot.attempts === 0 && snapshot.success_rate !== 0)
  ) {
    throw new SourceHealthPolicyInvariantError(
      "source health snapshot status does not match its metrics",
    );
  }
}

function statusRank(status: SourceHealthStatus): number {
  switch (status) {
    case "healthy":
      return 0;
    case "degraded":
      return 1;
    case "cooldown":
      return 2;
  }
}

function requirePositiveInteger(value: number, field: string): void {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new SourceHealthPolicyInvariantError(
      `${field} must be a positive integer`,
    );
  }
}

function requireNonNegativeInteger(value: number, field: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new SourceHealthPolicyInvariantError(
      `${field} must be a non-negative integer`,
    );
  }
}
