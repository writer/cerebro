import type {
  ScheduleMisfirePolicy,
  ScheduledOccurrenceState,
  ScheduledOccurrenceV1,
} from "@writer/cerebro-sdk";

export interface ScheduledOccurrenceInput {
  due_at: string;
  generation: number;
  misfire_policy: ScheduleMisfirePolicy;
  schedule_id: string;
  schedule_revision: number;
}

export interface ScheduledOccurrenceCommitResult {
  created: boolean;
  occurrence: ScheduledOccurrenceV1;
}

/**
 * Durable scheduled-occurrence state. Production adapters must make create and
 * compare-and-set atomic; a process-local timer is not a valid implementation.
 */
export interface ScheduledOccurrenceStorePort {
  compareAndSet(
    expected: ScheduledOccurrenceV1,
    next: ScheduledOccurrenceV1,
  ): Promise<ScheduledOccurrenceV1>;
  putIfAbsent(
    occurrence: ScheduledOccurrenceV1,
  ): Promise<ScheduledOccurrenceCommitResult>;
  read(occurrenceId: string): Promise<ScheduledOccurrenceV1 | undefined>;
}

export interface MisfirePlan {
  enqueue: string[];
  pending: string[];
  skip: string[];
}

export interface ScheduledLeaseRequest {
  fencing_token: number;
  generation: number;
  lease_expires_at: string;
  lease_token: string;
  now: string;
  owner_id: string;
}

export type ScheduledLeaseDecision =
  | { acquired: true; occurrence: ScheduledOccurrenceV1 }
  | {
      acquired: false;
      reason:
        | "active_lease"
        | "invalid_expiry"
        | "invalid_fencing_token"
        | "invalid_generation"
        | "invalid_lease_identity"
        | "not_queueable"
        | "stale_fencing_token"
        | "stale_generation";
    };

export interface ScheduledLeaseClaim {
  fencing_token: number;
  generation: number;
  lease_token: string;
  owner_id: string;
}

export function scheduledOccurrenceIdentity(
  scheduleId: string,
  dueAt: string,
  scheduleRevision: number,
): string {
  if (scheduleId.length === 0) {
    throw new Error("schedule_id is required");
  }
  if (!Number.isSafeInteger(scheduleRevision) || scheduleRevision < 1) {
    throw new Error("schedule_revision must be a positive integer");
  }

  const normalizedDueAt = normalizeTime(dueAt, "due_at");
  return `schedule/${encodeURIComponent(scheduleId)}/due/${encodeURIComponent(normalizedDueAt)}/revision/${scheduleRevision}`;
}

export function createScheduledOccurrence(
  input: ScheduledOccurrenceInput,
  createdAt: string,
): ScheduledOccurrenceV1 {
  requirePositiveInteger(input.generation, "generation");
  const normalizedCreatedAt = normalizeTime(createdAt, "created_at");
  const normalizedDueAt = normalizeTime(input.due_at, "due_at");
  const occurrenceId = scheduledOccurrenceIdentity(
    input.schedule_id,
    normalizedDueAt,
    input.schedule_revision,
  );

  return {
    created_at: normalizedCreatedAt,
    due_at: normalizedDueAt,
    generation: input.generation,
    idempotency_key: occurrenceId,
    misfire_policy: input.misfire_policy,
    occurrence_id: occurrenceId,
    run_id: `run/${occurrenceId}`,
    schedule_id: input.schedule_id,
    schedule_revision: input.schedule_revision,
    schema_version: "scheduled-occurrence/v1",
    state: "queued",
    updated_at: normalizedCreatedAt,
  };
}

export function planMisfires(
  dueTimes: readonly string[],
  now: string,
  policy: ScheduleMisfirePolicy,
  runAllLimit = 1,
): MisfirePlan {
  if (!Number.isSafeInteger(runAllLimit) || runAllLimit < 1) {
    throw new Error("runAllLimit must be a positive integer");
  }

  const normalizedNow = normalizeTime(now, "now");
  const ordered = [...new Set(dueTimes.map((dueAt) => normalizeTime(dueAt, "due_at")))]
    .sort((left, right) => Date.parse(left) - Date.parse(right));
  const due = ordered.filter((dueAt) => dueAt <= normalizedNow);
  const pending = ordered.filter((dueAt) => dueAt > normalizedNow);

  if (policy === "skip") {
    return { enqueue: [], pending, skip: due };
  }
  if (policy === "coalesce_once") {
    const latest = due.at(-1);
    return {
      enqueue: latest === undefined ? [] : [latest],
      pending,
      skip: latest === undefined ? [] : due.slice(0, -1),
    };
  }

  return {
    enqueue: due.slice(0, runAllLimit),
    pending: [...due.slice(runAllLimit), ...pending],
    skip: [],
  };
}

export function acquireScheduledOccurrence(
  occurrence: ScheduledOccurrenceV1,
  request: ScheduledLeaseRequest,
): ScheduledLeaseDecision {
  if (!isPositiveInteger(request.generation)) {
    return { acquired: false, reason: "invalid_generation" };
  }
  if (!isPositiveInteger(request.fencing_token)) {
    return { acquired: false, reason: "invalid_fencing_token" };
  }
  if (
    request.owner_id.trim().length === 0 ||
    request.lease_token.trim().length === 0
  ) {
    return { acquired: false, reason: "invalid_lease_identity" };
  }
  const now = normalizeTime(request.now, "now");
  const leaseExpiresAt = normalizeTime(
    request.lease_expires_at,
    "lease_expires_at",
  );
  if (leaseExpiresAt <= now) {
    return { acquired: false, reason: "invalid_expiry" };
  }
  if (request.generation < occurrence.generation) {
    return { acquired: false, reason: "stale_generation" };
  }

  const leaseIsActive =
    occurrence.lease_expires_at !== undefined &&
    normalizeTime(occurrence.lease_expires_at, "lease_expires_at") > now;
  if (leaseIsActive) {
    return { acquired: false, reason: "active_lease" };
  }

  if (occurrence.state !== "queued" && occurrence.state !== "leased" && occurrence.state !== "running") {
    return { acquired: false, reason: "not_queueable" };
  }
  if (
    occurrence.fencing_token !== undefined &&
    request.fencing_token <= occurrence.fencing_token
  ) {
    return { acquired: false, reason: "stale_fencing_token" };
  }

  return {
    acquired: true,
    occurrence: {
      ...occurrence,
      fencing_token: request.fencing_token,
      generation: request.generation,
      heartbeat_at: now,
      lease_expires_at: leaseExpiresAt,
      lease_token: request.lease_token,
      owner_id: request.owner_id,
      state: "leased",
      updated_at: now,
    },
  };
}

export function updateScheduledOccurrence(
  occurrence: ScheduledOccurrenceV1,
  claim: ScheduledLeaseClaim,
  state: Extract<ScheduledOccurrenceState, "running" | "completed" | "failed">,
  now: string,
): ScheduledOccurrenceV1 | undefined {
  const normalizedNow = normalizeTime(now, "now");
  if (!ownsActiveLease(occurrence, claim, normalizedNow)) {
    return undefined;
  }

  return {
    ...occurrence,
    heartbeat_at: normalizedNow,
    state,
    updated_at: normalizedNow,
  };
}

function ownsActiveLease(
  occurrence: ScheduledOccurrenceV1,
  claim: ScheduledLeaseClaim,
  now: string,
): boolean {
  return (
    occurrence.fencing_token === claim.fencing_token &&
    occurrence.generation === claim.generation &&
    occurrence.lease_token === claim.lease_token &&
    occurrence.owner_id === claim.owner_id &&
    occurrence.lease_expires_at !== undefined &&
    normalizeTime(occurrence.lease_expires_at, "lease_expires_at") > now
  );
}

function normalizeTime(value: string, field: string): string {
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) {
    throw new Error(`${field} must be an ISO-8601 timestamp`);
  }
  return new Date(timestamp).toISOString();
}

function requirePositiveInteger(value: number, field: string): void {
  if (!isPositiveInteger(value)) {
    throw new Error(`${field} must be a positive integer`);
  }
}

function isPositiveInteger(value: number): boolean {
  return Number.isSafeInteger(value) && value > 0;
}
