import { isDeepStrictEqual } from "node:util";
import type {
  DueMissionRecord,
  LifecycleEventV1,
  MissionEventPageRequest,
  MissionPromotionResult,
  MissionSnapshotV1,
  MissionStoredCommit,
  MissionTransitionResult,
  ScheduledOccurrenceV1,
  WorkLeaseV1,
} from "./contracts.js";
import type {
  AuthoritativeMissionLeaseRead,
  DurableMissionLedgerPort,
  LegacyMissionAtomicCommit,
  MissionLeaseAuthorityPort,
  MissionAtomicCommit,
  MissionOccurrenceCompareAndSet,
} from "./ports.js";
import {
  lifecycleEventReference,
  MissionLedgerIdempotencyConflictError,
  MissionLedgerInvariantError,
  MissionLedgerOccurrenceConflictError,
  MissionLedgerStaleLeaseError,
  MissionLedgerStaleOccurrenceError,
  MissionLedgerStaleRevisionError,
  missionSnapshotReference,
} from "./ledger.js";
import {
  acquireScheduledOccurrence,
  updateScheduledOccurrence,
} from "../operations/schedules.js";

export interface ReferenceMemoryMissionLedgerStoreOptions {
  lease_authority?: MissionLeaseAuthorityPort;
}

/** Reference conformance adapter. Runtime datastore selection stays external. */
export class ReferenceMemoryMissionLedgerStore
  implements DurableMissionLedgerPort
{
  private readonly commits = new Map<string, MissionStoredCommit>();
  private readonly events = new Map<string, LifecycleEventV1[]>();
  private readonly missionSubjects = new Map<string, string>();
  private readonly occurrences = new Map<string, ScheduledOccurrenceV1>();
  private readonly snapshots = new Map<string, MissionSnapshotV1>();
  private readonly leaseAuthority: MissionLeaseAuthorityPort | undefined;

  constructor(options: ReferenceMemoryMissionLedgerStoreOptions = {}) {
    this.leaseAuthority = options.lease_authority;
  }

  async commitTransition(
    commit: MissionAtomicCommit,
  ): Promise<MissionTransitionResult> {
    const prior = this.requireIdempotentCommit(commit);
    if (prior !== undefined) {
      return {
        consumed_occurrence: prior.consumed_occurrence,
        created: false,
        event: prior.event,
        occurrence: prior.occurrence,
        snapshot: prior.snapshot,
      };
    }
    if (commit.lease === undefined) {
      return this.commitWithLeaseAuthority(commit, undefined);
    }
    if (this.leaseAuthority === undefined) {
      throw new MissionLedgerStaleLeaseError(
        "mission execution lease authority is unavailable",
      );
    }
    return this.leaseAuthority.withCurrentLease(
      commit.lease.run_id,
      (authoritative) => this.commitWithLeaseAuthority(commit, authoritative),
    );
  }

  async promoteLegacy(
    commit: LegacyMissionAtomicCommit,
  ): Promise<MissionPromotionResult> {
    requireRef(commit.adapter_ref, "adapter_ref");
    requireRef(commit.source_ref, "source_ref");
    if (commit.consumed_occurrence !== undefined) {
      throw new MissionLedgerInvariantError(
        "legacy promotion cannot consume scheduled mission work",
      );
    }
    const prior = this.requireIdempotentCommit(commit);
    if (prior !== undefined) {
      return {
        created: false,
        event: prior.event,
        occurrence: prior.occurrence,
        snapshot: prior.snapshot,
      };
    }

    const currentBySubject = this.snapshots.get(commit.snapshot.subject_ref);
    const currentSubject = this.missionSubjects.get(commit.snapshot.mission_ref);
    const currentByMission =
      currentSubject === undefined
        ? undefined
        : this.snapshots.get(currentSubject);
    const current = currentBySubject ?? currentByMission;
    if (current !== undefined) {
      return { created: false, snapshot: clone(current) };
    }

    const consumedOccurrence = this.validateCommit(
      commit,
      undefined,
      undefined,
    );
    this.applyCommit(commit, consumedOccurrence);
    return {
      created: true,
      event: clone(commit.event),
      occurrence: cloneOptional(commit.occurrence),
      snapshot: clone(commit.snapshot),
    };
  }

  readByIdempotencyKey(
    idempotencyKey: string,
  ): Promise<MissionStoredCommit | undefined> {
    return Promise.resolve(cloneOptional(this.commits.get(idempotencyKey)));
  }

  readByMissionRef(
    missionRef: string,
  ): Promise<MissionSnapshotV1 | undefined> {
    const subjectRef = this.missionSubjects.get(missionRef);
    return Promise.resolve(
      subjectRef === undefined
        ? undefined
        : cloneOptional(this.snapshots.get(subjectRef)),
    );
  }

  readBySubject(
    subjectRef: string,
  ): Promise<MissionSnapshotV1 | undefined> {
    return Promise.resolve(cloneOptional(this.snapshots.get(subjectRef)));
  }

  readEvent(
    subjectRef: string,
    sequence: number,
  ): Promise<LifecycleEventV1 | undefined> {
    return Promise.resolve(
      cloneOptional(
        (this.events.get(subjectRef) ?? []).find(
          (event) => event.sequence === sequence,
        ),
      ),
    );
  }

  readOccurrence(
    occurrenceRef: string,
  ): Promise<ScheduledOccurrenceV1 | undefined> {
    return Promise.resolve(cloneOptional(this.occurrences.get(occurrenceRef)));
  }

  compareAndSetOccurrence(
    request: MissionOccurrenceCompareAndSet,
  ): Promise<ScheduledOccurrenceV1> {
    const snapshot = this.snapshots.get(request.subject_ref);
    if (
      snapshot === undefined ||
      snapshot.revision !== request.expected_snapshot_revision ||
      snapshot.wake?.occurrence_ref !== request.expected.occurrence_id
    ) {
      throw new MissionLedgerStaleRevisionError(
        request.expected_snapshot_revision,
        snapshot?.revision ?? 0,
      );
    }
    const current = this.occurrences.get(request.expected.occurrence_id);
    if (current === undefined || !isDeepStrictEqual(current, request.expected)) {
      throw new MissionLedgerOccurrenceConflictError();
    }
    validateOccurrenceLeaseAdvance(request.expected, request.next);
    const committed = clone(request.next);
    this.occurrences.set(committed.occurrence_id, committed);
    return Promise.resolve(clone(committed));
  }

  listDue(observedAt: string, limit: number): Promise<DueMissionRecord[]> {
    const observed = normalizeTime(observedAt, "observed_at");
    requirePositiveInteger(limit, "limit");
    const due = [...this.snapshots.values()]
      .flatMap((snapshot): DueMissionRecord[] => {
        if (snapshot.wake === undefined) return [];
        const occurrence = this.occurrences.get(snapshot.wake.occurrence_ref);
        if (
          occurrence === undefined ||
          !isDueQueueable(occurrence, observed) ||
          normalizeTime(occurrence.due_at, "due_at") > observed
        ) {
          return [];
        }
        return [{ occurrence, snapshot }];
      })
      .sort(compareDueMissions)
      .slice(0, limit)
      .map(clone);
    return Promise.resolve(due);
  }

  listEvents(
    subjectRef: string,
    request: MissionEventPageRequest,
  ): Promise<LifecycleEventV1[]> {
    requirePositiveInteger(request.limit, "limit");
    const after = request.after_sequence ?? 0;
    requireNonNegativeInteger(after, "after_sequence");
    return Promise.resolve(
      (this.events.get(subjectRef) ?? [])
        .filter((event) => event.sequence > after)
        .slice(0, request.limit)
        .map(clone),
    );
  }

  private requireIdempotentCommit(
    commit: MissionAtomicCommit,
  ): MissionStoredCommit | undefined {
    const prior = this.commits.get(commit.idempotency_key);
    if (prior === undefined) return undefined;
    if (prior.intent_digest !== commit.intent_digest) {
      throw new MissionLedgerIdempotencyConflictError();
    }
    return clone(prior);
  }

  private commitWithLeaseAuthority(
    commit: MissionAtomicCommit,
    authoritative: AuthoritativeMissionLeaseRead | undefined,
  ): MissionTransitionResult {
    const prior = this.requireIdempotentCommit(commit);
    if (prior !== undefined) {
      return {
        consumed_occurrence: prior.consumed_occurrence,
        created: false,
        event: prior.event,
        occurrence: prior.occurrence,
        snapshot: prior.snapshot,
      };
    }
    const current = this.snapshots.get(commit.snapshot.subject_ref);
    const consumedOccurrence = this.validateCommit(
      commit,
      current,
      authoritative,
    );
    this.applyCommit(commit, consumedOccurrence);
    return {
      consumed_occurrence: cloneOptional(consumedOccurrence),
      created: true,
      event: clone(commit.event),
      occurrence: cloneOptional(commit.occurrence),
      snapshot: clone(commit.snapshot),
    };
  }

  private validateCommit(
    commit: MissionAtomicCommit,
    current: MissionSnapshotV1 | undefined,
    authoritative: AuthoritativeMissionLeaseRead | undefined,
  ): ScheduledOccurrenceV1 | undefined {
    const { event, snapshot } = commit;
    requireRef(commit.idempotency_key, "idempotency_key");
    requireRef(commit.intent_digest, "intent_digest");
    if (
      event.schema_version !== "cerebro.agent-service-lifecycle/v1" ||
      event.event_kind !== "work.transition" ||
      event.transition.axis !== "work"
    ) {
      throw new MissionLedgerInvariantError(
        "mission commits require a work lifecycle event",
      );
    }
    if (
      event.idempotency_key !== commit.idempotency_key ||
      snapshot.revision !== commit.expected_revision + 1 ||
      event.sequence !== snapshot.revision ||
      event.scope.subject_id !== snapshot.subject_ref ||
      event.scope.tenant_id !== snapshot.run.tenant_id ||
      event.transition.to !== snapshot.run.state ||
      event.snapshot_ref !==
        missionSnapshotReference(snapshot.subject_ref, snapshot.revision) ||
      snapshot.latest_event_ref !== lifecycleEventReference(event) ||
      snapshot.recent_event_refs.at(-1) !== snapshot.latest_event_ref ||
      snapshot.updated_at !== event.occurred_at ||
      snapshot.plan.mission_ref !== snapshot.mission_ref ||
      snapshot.plan.run_id !== snapshot.run.run_id ||
      snapshot.run.subject_ref !== snapshot.subject_ref
    ) {
      throw new MissionLedgerInvariantError(
        "mission snapshot and lifecycle event do not describe one transition",
      );
    }

    const actualRevision = current?.revision ?? 0;
    if (actualRevision !== commit.expected_revision) {
      throw new MissionLedgerStaleRevisionError(
        commit.expected_revision,
        actualRevision,
      );
    }
    if (current === undefined) {
      if (event.transition.from !== null || commit.lease !== undefined) {
        throw new MissionLedgerInvariantError(
          "initial mission commit cannot claim a prior transition",
        );
      }
    } else {
      if (
        event.transition.from !== current.run.state ||
        current.mission_ref !== snapshot.mission_ref ||
        current.subject_ref !== snapshot.subject_ref ||
        commit.lease === undefined ||
        !isDeepStrictEqual(snapshot.last_execution_lease, commit.lease)
      ) {
        throw new MissionLedgerInvariantError(
          "mission transition changed identity or omitted its lease proof",
        );
      }
      this.assertLeaseProof(current, commit.lease, authoritative);
    }

    const indexedSubject = this.missionSubjects.get(snapshot.mission_ref);
    if (
      indexedSubject !== undefined &&
      indexedSubject !== snapshot.subject_ref
    ) {
      throw new MissionLedgerInvariantError(
        "mission reference already belongs to another subject",
      );
    }
    this.validateOccurrence(commit);
    return this.validateConsumedOccurrence(commit, current, authoritative);
  }

  private validateConsumedOccurrence(
    commit: MissionAtomicCommit,
    current: MissionSnapshotV1 | undefined,
    authoritative: AuthoritativeMissionLeaseRead | undefined,
  ): ScheduledOccurrenceV1 | undefined {
    const outcome = commit.consumed_occurrence;
    if (outcome === undefined) return undefined;
    if (
      current === undefined ||
      authoritative === undefined ||
      current.wake?.occurrence_ref !== outcome.occurrence_id ||
      commit.occurrence?.occurrence_id === outcome.occurrence_id
    ) {
      throw new MissionLedgerStaleOccurrenceError();
    }

    const occurrence = this.occurrences.get(outcome.occurrence_id);
    if (occurrence === undefined) {
      throw new MissionLedgerStaleOccurrenceError();
    }
    const consumed = updateScheduledOccurrence(
      occurrence,
      outcome.claim,
      outcome.state,
      authoritative.observed_at,
    );
    if (consumed === undefined) {
      throw new MissionLedgerStaleOccurrenceError();
    }
    return consumed;
  }

  private validateOccurrence(commit: MissionAtomicCommit): void {
    const occurrence = commit.occurrence;
    if (occurrence !== undefined) {
      if (
        commit.snapshot.wake?.occurrence_ref !== occurrence.occurrence_id ||
        occurrence.schema_version !== "scheduled-occurrence/v1"
      ) {
        throw new MissionLedgerInvariantError(
          "mission wake and scheduled occurrence do not match",
        );
      }
      const prior = this.occurrences.get(occurrence.occurrence_id);
      if (prior !== undefined && !isDeepStrictEqual(prior, occurrence)) {
        throw new MissionLedgerIdempotencyConflictError();
      }
      return;
    }
    const occurrenceRef = commit.snapshot.wake?.occurrence_ref;
    if (
      occurrenceRef !== undefined &&
      !this.occurrences.has(occurrenceRef)
    ) {
      throw new MissionLedgerInvariantError(
        "mission wake occurrence is not durable",
      );
    }
  }

  private assertLeaseProof(
    current: MissionSnapshotV1,
    lease: WorkLeaseV1,
    authoritative: AuthoritativeMissionLeaseRead | undefined,
  ): void {
    if (
      lease.schema_version !== "work-lease/v1" ||
      lease.run_id !== current.run.run_id ||
      !Number.isSafeInteger(lease.generation) ||
      lease.generation < 1 ||
      !Number.isSafeInteger(lease.fencing_token) ||
      lease.fencing_token < 1
    ) {
      throw new MissionLedgerStaleLeaseError();
    }

    if (
      authoritative === undefined ||
      !isDeepStrictEqual(authoritative.lease, lease) ||
      normalizeTime(lease.lease_expires_at, "lease_expires_at") <=
        normalizeTime(authoritative.observed_at, "authority.observed_at")
    ) {
      throw new MissionLedgerStaleLeaseError();
    }

    const previous = current.last_execution_lease;
    if (previous === undefined) return;
    if (
      lease.generation < previous.generation ||
      lease.fencing_token < previous.fencing_token ||
      (lease.generation > previous.generation &&
        lease.fencing_token <= previous.fencing_token)
    ) {
      throw new MissionLedgerStaleLeaseError();
    }
    if (
      lease.generation === previous.generation &&
      lease.fencing_token === previous.fencing_token &&
      (lease.lease_token !== previous.lease_token ||
        lease.owner_id !== previous.owner_id ||
        lease.run_id !== previous.run_id)
    ) {
      throw new MissionLedgerStaleLeaseError();
    }
  }

  private applyCommit(
    commit: MissionAtomicCommit,
    consumedOccurrence: ScheduledOccurrenceV1 | undefined,
  ): void {
    const snapshot = clone(commit.snapshot);
    const event = clone(commit.event);
    const occurrence = cloneOptional(commit.occurrence);
    const consumed = cloneOptional(consumedOccurrence);
    if (consumed !== undefined) {
      this.occurrences.set(consumed.occurrence_id, consumed);
    }
    if (occurrence !== undefined) {
      this.occurrences.set(occurrence.occurrence_id, occurrence);
    }
    this.snapshots.set(snapshot.subject_ref, snapshot);
    this.missionSubjects.set(snapshot.mission_ref, snapshot.subject_ref);
    this.events.set(snapshot.subject_ref, [
      ...(this.events.get(snapshot.subject_ref) ?? []),
      event,
    ]);
    this.commits.set(commit.idempotency_key, {
      consumed_occurrence: consumed,
      event,
      intent_digest: commit.intent_digest,
      occurrence,
      snapshot,
    });
  }
}

function validateOccurrenceLeaseAdvance(
  expected: ScheduledOccurrenceV1,
  next: ScheduledOccurrenceV1,
): void {
  if (
    next.heartbeat_at === undefined ||
    next.lease_expires_at === undefined ||
    next.lease_token === undefined ||
    next.owner_id === undefined ||
    next.fencing_token === undefined
  ) {
    throw new MissionLedgerInvariantError(
      "scheduled occurrence lease proof is incomplete",
    );
  }
  const acquired = acquireScheduledOccurrence(expected, {
    fencing_token: next.fencing_token,
    generation: next.generation,
    lease_expires_at: next.lease_expires_at,
    lease_token: next.lease_token,
    now: next.heartbeat_at,
    owner_id: next.owner_id,
  });
  if (!acquired.acquired || !isDeepStrictEqual(acquired.occurrence, next)) {
    throw new MissionLedgerInvariantError(
      "scheduled occurrence lease transition is invalid",
    );
  }
}

function isDueQueueable(
  occurrence: ScheduledOccurrenceV1,
  observedAt: string,
): boolean {
  if (occurrence.state === "admitted" || occurrence.state === "queued") {
    return true;
  }
  return (
    (occurrence.state === "leased" || occurrence.state === "running") &&
    occurrence.lease_expires_at !== undefined &&
    normalizeTime(occurrence.lease_expires_at, "lease_expires_at") <= observedAt
  );
}

function compareDueMissions(
  left: DueMissionRecord,
  right: DueMissionRecord,
): number {
  return (
    left.occurrence.due_at.localeCompare(right.occurrence.due_at) ||
    left.occurrence.occurrence_id.localeCompare(
      right.occurrence.occurrence_id,
    ) ||
    left.snapshot.subject_ref.localeCompare(right.snapshot.subject_ref)
  );
}

function clone<T>(value: T): T {
  return structuredClone(value);
}

function cloneOptional<T>(value: T | undefined): T | undefined {
  return value === undefined ? undefined : clone(value);
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
