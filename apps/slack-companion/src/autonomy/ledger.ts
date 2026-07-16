import { createHash } from "node:crypto";
import type {
  LifecycleEventV1,
  RunReceiptV1,
  ScheduleMisfirePolicy,
  ScheduledOccurrenceV1,
  WorkState,
} from "@writer/cerebro-sdk";
import {
  acquireScheduledOccurrence,
  createScheduledOccurrence,
  scheduledOccurrenceIdentity,
} from "../operations/schedules.js";
import type {
  ScheduledLeaseClaim,
  ScheduledLeaseDecision,
  ScheduledLeaseRequest,
} from "../operations/schedules.js";
import type {
  DueMissionRecord,
  InitializeMissionInput,
  MissionLedgerEventContext,
  MissionPromotionResult,
  MissionSnapshotSeed,
  MissionSnapshotV1,
  MissionStoredCommit,
  MissionTransitionResult,
  MissionWakeInput,
  PromoteLegacyMissionInput,
  TransitionMissionInput,
} from "./contracts.js";
import { MISSION_SNAPSHOT_SCHEMA_VERSION } from "./contracts.js";
import type { DurableMissionLedgerPort } from "./ports.js";
import {
  NATIVE_MISSION_CONTRACT_ID,
  NATIVE_MISSION_SCHEMA_VERSION,
} from "../mission/model.js";

export const DEFAULT_MISSION_SNAPSHOT_EVENT_REF_LIMIT = 32;

export interface MissionLedgerOptions {
  recent_event_ref_limit?: number;
  store: DurableMissionLedgerPort;
}

export interface CreateMissionWakeInput {
  created_at: string;
  due_at: string;
  generation: number;
  misfire_policy: ScheduleMisfirePolicy;
  mission_ref: string;
  mission_revision: number;
  wake_condition_ref: string;
}

export type MissionWorkDispatchDecision =
  | { disposition: "claim" }
  | { disposition: "execute" }
  | {
      disposition: "consume_stale";
      reason:
        | "mission_missing"
        | "occurrence_terminal"
        | "revision_superseded"
        | "wake_superseded";
    }
  | { disposition: "retry_claimed"; reason: "active_lease" };

export type MissionOccurrenceClaimResult =
  | { acquired: true; created: boolean; occurrence: ScheduledOccurrenceV1 }
  | Extract<ScheduledLeaseDecision, { acquired: false }>;

export class MissionLedger {
  private readonly recentEventRefLimit: number;
  private readonly store: DurableMissionLedgerPort;

  constructor(options: MissionLedgerOptions) {
    requirePositiveInteger(
      options.recent_event_ref_limit ?? DEFAULT_MISSION_SNAPSHOT_EVENT_REF_LIMIT,
      "recent_event_ref_limit",
    );
    this.recentEventRefLimit =
      options.recent_event_ref_limit ?? DEFAULT_MISSION_SNAPSHOT_EVENT_REF_LIMIT;
    this.store = options.store;
  }

  async initialize(
    input: InitializeMissionInput,
  ): Promise<MissionTransitionResult> {
    validateSeed(input.seed);
    const subjectRef = input.seed.run.subject_ref;
    const idempotencyKey = missionLedgerIdempotencyKey(
      subjectRef,
      input.operation_id,
    );
    const intentDigest = missionIntentDigest({ kind: "initialize", input });
    const replay = await this.replayedCommit(idempotencyKey, intentDigest);
    if (replay !== undefined) return replay;

    const event = createMissionLifecycleEvent({
      attempt: 1,
      context: input.event,
      from: null,
      idempotency_key: idempotencyKey,
      mission_ref: input.seed.plan.mission_ref,
      revision: 1,
      run: input.seed.run,
    });
    const snapshot = initialSnapshot(
      input.seed,
      event,
      this.recentEventRefLimit,
    );
    return this.store.commitTransition({
      event,
      expected_revision: 0,
      idempotency_key: idempotencyKey,
      intent_digest: intentDigest,
      occurrence: input.seed.wake?.occurrence,
      snapshot,
    });
  }

  async transition(
    input: TransitionMissionInput,
  ): Promise<MissionTransitionResult> {
    requirePositiveInteger(input.attempt, "attempt");
    requirePositiveInteger(input.expected_revision, "expected_revision");
    validateLeaseSession(input.session);
    const subjectRef = input.session.run.subject_ref;
    const idempotencyKey = missionLedgerIdempotencyKey(
      subjectRef,
      input.operation_id,
    );
    const intentDigest = missionIntentDigest({ kind: "transition", input });
    const replay = await this.replayedCommit(idempotencyKey, intentDigest);
    if (replay !== undefined) return replay;

    const current = await this.store.readBySubject(subjectRef);
    if (current === undefined) {
      throw new MissionLedgerInvariantError("mission snapshot does not exist");
    }
    if (current.revision !== input.expected_revision) {
      throw new MissionLedgerStaleRevisionError(
        input.expected_revision,
        current.revision,
      );
    }

    const nextRun = input.next_run ?? input.session.run;
    const nextPlan = input.plan ?? current.plan;
    validateSeed({ plan: nextPlan, run: nextRun });
    if (
      nextRun.subject_ref !== current.subject_ref ||
      nextRun.run_id !== current.run.run_id ||
      nextPlan.mission_ref !== current.mission_ref
    ) {
      throw new MissionLedgerInvariantError(
        "mission transition cannot change stable mission identity",
      );
    }

    const revision = current.revision + 1;
    const event = createMissionLifecycleEvent({
      attempt: input.attempt,
      context: input.event,
      from: current.run.state,
      idempotency_key: idempotencyKey,
      mission_ref: current.mission_ref,
      revision,
      run: nextRun,
    });
    const wake = nextWake(current, input.wake);
    if (input.wake !== undefined && input.wake !== null) {
      validateWake(nextPlan, input.wake);
    }
    const eventRef = lifecycleEventReference(event);
    const snapshot: MissionSnapshotV1 = {
      ...current,
      last_execution_lease: structuredClone(input.session.lease),
      latest_event_ref: eventRef,
      plan: structuredClone(nextPlan),
      recent_event_refs: boundedAppend(
        current.recent_event_refs,
        eventRef,
        this.recentEventRefLimit,
      ),
      revision,
      run: structuredClone(nextRun),
      updated_at: event.occurred_at,
      wake,
    };
    return this.store.commitTransition({
      event,
      expected_revision: input.expected_revision,
      idempotency_key: idempotencyKey,
      intent_digest: intentDigest,
      lease: structuredClone(input.session.lease),
      occurrence:
        input.wake === undefined || input.wake === null
          ? undefined
          : structuredClone(input.wake.occurrence),
      snapshot,
    });
  }

  async promoteLegacy(
    input: PromoteLegacyMissionInput,
  ): Promise<MissionPromotionResult> {
    validateSeed(input.candidate.seed);
    requireRef(input.candidate.adapter_ref, "adapter_ref");
    requireRef(input.candidate.source_ref, "source_ref");
    const subjectRef = input.candidate.seed.run.subject_ref;
    const idempotencyKey = missionLedgerIdempotencyKey(
      subjectRef,
      input.operation_id,
    );
    const intentDigest = missionIntentDigest({ kind: "legacy-promotion", input });
    const replay = await this.replayedCommit(idempotencyKey, intentDigest);
    if (replay !== undefined) {
      return { ...replay, created: false };
    }

    const event = createMissionLifecycleEvent({
      attempt: 1,
      context: input.event,
      from: null,
      idempotency_key: idempotencyKey,
      mission_ref: input.candidate.seed.plan.mission_ref,
      revision: 1,
      run: input.candidate.seed.run,
    });
    const snapshot = initialSnapshot(
      input.candidate.seed,
      event,
      this.recentEventRefLimit,
    );
    return this.store.promoteLegacy({
      adapter_ref: input.candidate.adapter_ref,
      event,
      expected_revision: 0,
      idempotency_key: idempotencyKey,
      intent_digest: intentDigest,
      occurrence: input.candidate.seed.wake?.occurrence,
      snapshot,
      source_ref: input.candidate.source_ref,
    });
  }

  readByMissionRef(missionRef: string): Promise<MissionSnapshotV1 | undefined> {
    requireRef(missionRef, "mission_ref");
    return this.store.readByMissionRef(missionRef);
  }

  readBySubject(subjectRef: string): Promise<MissionSnapshotV1 | undefined> {
    requireRef(subjectRef, "subject_ref");
    return this.store.readBySubject(subjectRef);
  }

  listDue(observedAt: string, limit: number): Promise<DueMissionRecord[]> {
    normalizeTime(observedAt, "observed_at");
    requirePositiveInteger(limit, "limit");
    return this.store.listDue(observedAt, limit);
  }

  listEvents(
    subjectRef: string,
    afterSequence: number,
    limit: number,
  ): Promise<LifecycleEventV1[]> {
    requireRef(subjectRef, "subject_ref");
    requireNonNegativeInteger(afterSequence, "after_sequence");
    requirePositiveInteger(limit, "limit");
    return this.store.listEvents(subjectRef, {
      after_sequence: afterSequence,
      limit,
    });
  }

  async claimDue(
    due: DueMissionRecord,
    request: ScheduledLeaseRequest,
  ): Promise<MissionOccurrenceClaimResult> {
    requireRef(due.snapshot.subject_ref, "subject_ref");
    requireRef(due.occurrence.occurrence_id, "occurrence_id");

    for (let attempt = 0; attempt < 2; attempt += 1) {
      const snapshot = await this.store.readBySubject(due.snapshot.subject_ref);
      const occurrence = await this.store.readOccurrence(
        due.occurrence.occurrence_id,
      );
      if (snapshot === undefined || occurrence === undefined) {
        throw new MissionLedgerInvariantError(
          "mission wake is no longer durable",
        );
      }

      const dispatch = decideMissionWorkDispatch(
        snapshot,
        occurrence,
        request.now,
        request,
      );
      if (dispatch.disposition === "consume_stale") {
        throw new MissionLedgerInvariantError(
          `mission wake is stale: ${dispatch.reason}`,
        );
      }
      if (dispatch.disposition === "retry_claimed") {
        return { acquired: false, reason: "active_lease" };
      }
      if (dispatch.disposition === "execute") {
        return { acquired: true, created: false, occurrence };
      }

      const acquired = acquireScheduledOccurrence(occurrence, request);
      if (!acquired.acquired) return acquired;
      try {
        const committed = await this.store.compareAndSetOccurrence({
          expected: occurrence,
          expected_snapshot_revision: snapshot.revision,
          next: acquired.occurrence,
          subject_ref: snapshot.subject_ref,
        });
        return { acquired: true, created: true, occurrence: committed };
      } catch (error) {
        if (!(error instanceof MissionLedgerOccurrenceConflictError)) {
          throw error;
        }
      }
    }

    throw new MissionLedgerOccurrenceConflictError();
  }

  private async replayedCommit(
    idempotencyKey: string,
    intentDigest: string,
  ): Promise<MissionTransitionResult | undefined> {
    const stored = await this.store.readByIdempotencyKey(idempotencyKey);
    if (stored === undefined) return undefined;
    assertMatchingIntent(stored, intentDigest);
    return {
      created: false,
      event: stored.event,
      occurrence: stored.occurrence,
      snapshot: stored.snapshot,
    };
  }
}

export function createMissionWake(
  input: CreateMissionWakeInput,
): MissionWakeInput {
  requireRef(input.mission_ref, "mission_ref");
  requireRef(input.wake_condition_ref, "wake_condition_ref");
  requirePositiveInteger(input.mission_revision, "mission_revision");
  return {
    occurrence: createScheduledOccurrence(
      {
        due_at: input.due_at,
        generation: input.generation,
        misfire_policy: input.misfire_policy,
        schedule_id: missionWakeScheduleId(
          input.mission_ref,
          input.wake_condition_ref,
        ),
        schedule_revision: input.mission_revision,
      },
      input.created_at,
    ),
    wake_condition_ref: input.wake_condition_ref,
  };
}

/**
 * Fail-closed dispatch guidance for a durable mission wake. Queue adapters use
 * this after loading the current snapshot and occurrence. It deliberately
 * reuses scheduled-occurrence lease identity instead of creating another work
 * claim or mission state machine.
 */
export function decideMissionWorkDispatch(
  snapshot: MissionSnapshotV1 | undefined,
  occurrence: ScheduledOccurrenceV1,
  now: string,
  claim?: ScheduledLeaseClaim,
): MissionWorkDispatchDecision {
  const observedAt = normalizeTime(now, "now");
  if (snapshot === undefined) {
    return { disposition: "consume_stale", reason: "mission_missing" };
  }
  if (occurrence.schedule_revision !== snapshot.plan.mission_revision) {
    return {
      disposition: "consume_stale",
      reason: "revision_superseded",
    };
  }
  if (snapshot.wake?.occurrence_ref !== occurrence.occurrence_id) {
    return { disposition: "consume_stale", reason: "wake_superseded" };
  }
  if (
    occurrence.state === "completed" ||
    occurrence.state === "failed" ||
    occurrence.state === "cancelled" ||
    occurrence.state === "skipped"
  ) {
    return {
      disposition: "consume_stale",
      reason: "occurrence_terminal",
    };
  }

  const leaseIsActive =
    occurrence.lease_expires_at !== undefined &&
    normalizeTime(occurrence.lease_expires_at, "lease_expires_at") > observedAt;
  if (!leaseIsActive) return { disposition: "claim" };

  if (
    claim !== undefined &&
    occurrence.fencing_token === claim.fencing_token &&
    occurrence.generation === claim.generation &&
    occurrence.lease_token === claim.lease_token &&
    occurrence.owner_id === claim.owner_id
  ) {
    return { disposition: "execute" };
  }
  return { disposition: "retry_claimed", reason: "active_lease" };
}

export function missionWakeScheduleId(
  missionRef: string,
  wakeConditionRef: string,
): string {
  requireRef(missionRef, "mission_ref");
  requireRef(wakeConditionRef, "wake_condition_ref");
  return `mission/${encodeURIComponent(missionRef)}/wake/${encodeURIComponent(wakeConditionRef)}`;
}

export function missionLedgerIdempotencyKey(
  subjectRef: string,
  operationId: string,
): string {
  requireRef(subjectRef, "subject_ref");
  requireRef(operationId, "operation_id");
  return `mission/${encodeURIComponent(subjectRef)}/transition/${encodeURIComponent(operationId)}`;
}

export function missionSnapshotReference(
  subjectRef: string,
  revision: number,
): string {
  requireRef(subjectRef, "subject_ref");
  requirePositiveInteger(revision, "revision");
  return `mission-snapshot://${encodeURIComponent(subjectRef)}/revision/${revision}`;
}

export function lifecycleEventReference(event: LifecycleEventV1): string {
  return `lifecycle-event://${encodeURIComponent(event.event_id)}`;
}

export function missionIntentDigest(value: unknown): string {
  return `sha256:${createHash("sha256").update(stableStringify(value)).digest("hex")}`;
}

function initialSnapshot(
  seed: MissionSnapshotSeed,
  event: LifecycleEventV1,
  recentEventRefLimit: number,
): MissionSnapshotV1 {
  const eventRef = lifecycleEventReference(event);
  return {
    latest_event_ref: eventRef,
    mission_contract_id: NATIVE_MISSION_CONTRACT_ID,
    mission_ref: seed.plan.mission_ref,
    mission_schema_version: NATIVE_MISSION_SCHEMA_VERSION,
    plan: structuredClone(seed.plan),
    recent_event_refs: boundedAppend([], eventRef, recentEventRefLimit),
    revision: 1,
    run: structuredClone(seed.run),
    schema_version: MISSION_SNAPSHOT_SCHEMA_VERSION,
    subject_ref: seed.run.subject_ref,
    updated_at: event.occurred_at,
    wake:
      seed.wake === undefined
        ? undefined
        : {
            occurrence_ref: seed.wake.occurrence.occurrence_id,
            wake_condition_ref: seed.wake.wake_condition_ref,
          },
  };
}

function createMissionLifecycleEvent(input: {
  attempt: number;
  context: MissionLedgerEventContext;
  from: WorkState | null;
  idempotency_key: string;
  mission_ref: string;
  revision: number;
  run: RunReceiptV1;
}): LifecycleEventV1 {
  validateEventContext(input.context);
  requirePositiveInteger(input.attempt, "attempt");
  requirePositiveInteger(input.revision, "revision");
  const eventId = `mission-event/${encodeURIComponent(input.idempotency_key)}`;
  return {
    causation_id: input.context.causation_id,
    correlation_id: input.context.correlation_id,
    event_id: eventId,
    event_kind: "work.transition",
    idempotency_key: input.idempotency_key,
    observed_at: normalizeTime(input.context.observed_at, "observed_at"),
    occurred_at: normalizeTime(input.context.occurred_at, "occurred_at"),
    producer: structuredClone(input.context.producer),
    reason: structuredClone(input.context.reason),
    schema_version: "cerebro.agent-service-lifecycle/v1",
    scope: {
      service_id: input.context.service_id,
      subject_id: input.run.subject_ref,
      subject_type: "work",
      tenant_id: input.run.tenant_id,
    },
    sequence: input.revision,
    snapshot_ref: missionSnapshotReference(
      input.run.subject_ref,
      input.revision,
    ),
    trace_id: input.context.trace_id,
    transition: {
      attempt: input.attempt,
      axis: "work",
      from: input.from,
      to: input.run.state,
    },
  };
}

function nextWake(
  current: MissionSnapshotV1,
  wake: MissionWakeInput | null | undefined,
): MissionSnapshotV1["wake"] {
  if (wake === undefined) return structuredClone(current.wake);
  if (wake === null) return undefined;
  return {
    occurrence_ref: wake.occurrence.occurrence_id,
    wake_condition_ref: wake.wake_condition_ref,
  };
}

function validateSeed(seed: MissionSnapshotSeed): void {
  requireRef(seed.run.run_id, "run_id");
  requireRef(seed.run.subject_ref, "subject_ref");
  requireRef(seed.run.tenant_id, "tenant_id");
  requirePositiveInteger(seed.run.revision, "run.revision");
  if (seed.run.schema_version !== "run-receipt/v1") {
    throw new MissionLedgerInvariantError("run receipt schema is unsupported");
  }
  if (
    seed.plan.mission_contract_id !== NATIVE_MISSION_CONTRACT_ID ||
    seed.plan.mission_schema_version !== NATIVE_MISSION_SCHEMA_VERSION
  ) {
    throw new MissionLedgerInvariantError("mission contract is unsupported");
  }
  if (seed.plan.run_id !== seed.run.run_id) {
    throw new MissionLedgerInvariantError(
      "mission plan and run receipt do not match",
    );
  }
  requireRef(seed.plan.mission_ref, "mission_ref");
  requirePositiveInteger(seed.plan.mission_revision, "mission_revision");
  if (seed.wake !== undefined) validateWake(seed.plan, seed.wake);
}

function validateWake(
  plan: MissionSnapshotSeed["plan"],
  wake: MissionWakeInput,
): void {
  requireRef(wake.wake_condition_ref, "wake_condition_ref");
  const occurrence = wake.occurrence;
  if (occurrence.schema_version !== "scheduled-occurrence/v1") {
    throw new MissionLedgerInvariantError(
      "scheduled occurrence schema is unsupported",
    );
  }
  const expectedScheduleId = missionWakeScheduleId(
    plan.mission_ref,
    wake.wake_condition_ref,
  );
  const expectedOccurrenceId = scheduledOccurrenceIdentity(
    expectedScheduleId,
    occurrence.due_at,
    occurrence.schedule_revision,
  );
  if (
    occurrence.schedule_id !== expectedScheduleId ||
    occurrence.schedule_revision !== plan.mission_revision ||
    occurrence.occurrence_id !== expectedOccurrenceId ||
    occurrence.idempotency_key !== expectedOccurrenceId
  ) {
    throw new MissionLedgerInvariantError(
      "mission wake does not match its deterministic occurrence identity",
    );
  }
}

function validateLeaseSession(session: TransitionMissionInput["session"]): void {
  if (
    session.run.run_id !== session.lease.run_id ||
    session.run.state !== "running" ||
    session.lease.schema_version !== "work-lease/v1"
  ) {
    throw new MissionLedgerInvariantError(
      "mission transition requires a running execution session",
    );
  }
}

function validateEventContext(context: MissionLedgerEventContext): void {
  requireRef(context.service_id, "service_id");
  requireRef(context.producer.component, "producer.component");
  requireRef(context.producer.version, "producer.version");
  requireRef(context.reason.code, "reason.code");
  requireRef(context.reason.summary, "reason.summary");
  normalizeTime(context.occurred_at, "occurred_at");
  normalizeTime(context.observed_at, "observed_at");
}

function assertMatchingIntent(
  stored: MissionStoredCommit,
  intentDigest: string,
): void {
  if (stored.intent_digest !== intentDigest) {
    throw new MissionLedgerIdempotencyConflictError();
  }
}

function boundedAppend(
  values: readonly string[],
  next: string,
  limit: number,
): string[] {
  return [...values, next].slice(-limit);
}

function stableStringify(value: unknown): string {
  return JSON.stringify(stableValue(value));
}

function stableValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .filter(([, item]) => item !== undefined)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, item]) => [key, stableValue(item)]),
    );
  }
  return value;
}

function normalizeTime(value: string, field: string): string {
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) {
    throw new MissionLedgerInvariantError(
      `${field} must be an ISO-8601 timestamp`,
    );
  }
  return new Date(timestamp).toISOString();
}

function requireRef(value: string, field: string): void {
  if (value.trim().length === 0) {
    throw new MissionLedgerInvariantError(`${field} is required`);
  }
}

function requirePositiveInteger(value: number, field: string): void {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new MissionLedgerInvariantError(
      `${field} must be a positive integer`,
    );
  }
}

function requireNonNegativeInteger(value: number, field: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new MissionLedgerInvariantError(
      `${field} must be a non-negative integer`,
    );
  }
}

export class MissionLedgerInvariantError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MissionLedgerInvariantError";
  }
}

export class MissionLedgerIdempotencyConflictError extends Error {
  constructor() {
    super("mission operation identity has different intent");
    this.name = "MissionLedgerIdempotencyConflictError";
  }
}

export class MissionLedgerStaleRevisionError extends Error {
  constructor(expected: number, actual: number) {
    super(`mission revision is stale: expected ${expected}, current ${actual}`);
    this.name = "MissionLedgerStaleRevisionError";
  }
}

export class MissionLedgerStaleLeaseError extends Error {
  constructor(message = "mission execution lease is stale") {
    super(message);
    this.name = "MissionLedgerStaleLeaseError";
  }
}

export class MissionLedgerOccurrenceConflictError extends Error {
  constructor() {
    super("mission scheduled occurrence changed concurrently");
    this.name = "MissionLedgerOccurrenceConflictError";
  }
}
