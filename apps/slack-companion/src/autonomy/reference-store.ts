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
  DurableMissionLedgerPort,
  LegacyMissionAtomicCommit,
  MissionAtomicCommit,
} from "./ports.js";
import {
  lifecycleEventReference,
  MissionLedgerIdempotencyConflictError,
  MissionLedgerInvariantError,
  MissionLedgerStaleLeaseError,
  MissionLedgerStaleRevisionError,
  missionSnapshotReference,
} from "./ledger.js";

/** Reference conformance adapter. Runtime datastore selection stays external. */
export class ReferenceMemoryMissionLedgerStore
  implements DurableMissionLedgerPort
{
  private readonly commits = new Map<string, MissionStoredCommit>();
  private readonly events = new Map<string, LifecycleEventV1[]>();
  private readonly missionSubjects = new Map<string, string>();
  private readonly occurrences = new Map<string, ScheduledOccurrenceV1>();
  private readonly snapshots = new Map<string, MissionSnapshotV1>();

  commitTransition(
    commit: MissionAtomicCommit,
  ): Promise<MissionTransitionResult> {
    const prior = this.requireIdempotentCommit(commit);
    if (prior !== undefined) {
      return Promise.resolve({
        created: false,
        event: prior.event,
        occurrence: prior.occurrence,
        snapshot: prior.snapshot,
      });
    }

    const current = this.snapshots.get(commit.snapshot.subject_ref);
    this.validateCommit(commit, current);
    this.applyCommit(commit);
    return Promise.resolve({
      created: true,
      event: clone(commit.event),
      occurrence: cloneOptional(commit.occurrence),
      snapshot: clone(commit.snapshot),
    });
  }

  promoteLegacy(
    commit: LegacyMissionAtomicCommit,
  ): Promise<MissionPromotionResult> {
    requireRef(commit.adapter_ref, "adapter_ref");
    requireRef(commit.source_ref, "source_ref");
    const prior = this.requireIdempotentCommit(commit);
    if (prior !== undefined) {
      return Promise.resolve({
        created: false,
        event: prior.event,
        occurrence: prior.occurrence,
        snapshot: prior.snapshot,
      });
    }

    const currentBySubject = this.snapshots.get(commit.snapshot.subject_ref);
    const currentSubject = this.missionSubjects.get(commit.snapshot.mission_ref);
    const currentByMission =
      currentSubject === undefined
        ? undefined
        : this.snapshots.get(currentSubject);
    const current = currentBySubject ?? currentByMission;
    if (current !== undefined) {
      return Promise.resolve({ created: false, snapshot: clone(current) });
    }

    this.validateCommit(commit, undefined);
    this.applyCommit(commit);
    return Promise.resolve({
      created: true,
      event: clone(commit.event),
      occurrence: cloneOptional(commit.occurrence),
      snapshot: clone(commit.snapshot),
    });
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

  listDue(observedAt: string, limit: number): Promise<DueMissionRecord[]> {
    const observed = normalizeTime(observedAt, "observed_at");
    requirePositiveInteger(limit, "limit");
    const due = [...this.snapshots.values()]
      .flatMap((snapshot): DueMissionRecord[] => {
        if (snapshot.wake === undefined) return [];
        const occurrence = this.occurrences.get(snapshot.wake.occurrence_ref);
        if (
          occurrence === undefined ||
          (occurrence.state !== "admitted" && occurrence.state !== "queued") ||
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

  private validateCommit(
    commit: MissionAtomicCommit,
    current: MissionSnapshotV1 | undefined,
  ): void {
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
      this.assertLeaseProof(current, commit.lease, event.occurred_at);
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
    occurredAt: string,
  ): void {
    if (
      lease.schema_version !== "work-lease/v1" ||
      lease.run_id !== current.run.run_id ||
      !Number.isSafeInteger(lease.generation) ||
      lease.generation < 1 ||
      !Number.isSafeInteger(lease.fencing_token) ||
      lease.fencing_token < 1 ||
      normalizeTime(lease.lease_expires_at, "lease_expires_at") <=
        normalizeTime(occurredAt, "occurred_at")
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

  private applyCommit(commit: MissionAtomicCommit): void {
    const snapshot = clone(commit.snapshot);
    const event = clone(commit.event);
    const occurrence = cloneOptional(commit.occurrence);
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
      event,
      intent_digest: commit.intent_digest,
      occurrence,
      snapshot,
    });
  }
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
