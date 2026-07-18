import type {
  DueMissionRecord,
  LifecycleEventV1,
  MissionEventPageRequest,
  MissionScheduledOccurrenceOutcome,
  MissionPromotionResult,
  MissionSnapshotV1,
  MissionStoredCommit,
  MissionTransitionResult,
  ScheduledOccurrenceV1,
  WorkLeaseV1,
} from "./contracts.js";

export interface MissionAtomicCommit {
  consumed_occurrence?: MissionScheduledOccurrenceOutcome;
  event: LifecycleEventV1;
  expected_revision: number;
  idempotency_key: string;
  intent_digest: string;
  lease?: WorkLeaseV1;
  occurrence?: ScheduledOccurrenceV1;
  snapshot: MissionSnapshotV1;
}

export interface AuthoritativeMissionLeaseRead {
  lease: WorkLeaseV1;
  observed_at: string;
}

/**
 * Portable read boundary for the execution lease that currently owns a run.
 * The adapter, not the mission event producer, owns `observed_at`.
 */
export interface MissionLeaseAuthorityPort {
  /** Keeps the authoritative lease stable until `operation` returns. */
  withCurrentLease<T>(
    runId: string,
    operation: (current: AuthoritativeMissionLeaseRead | undefined) => T,
  ): Promise<T>;
}

export interface MissionOccurrenceCompareAndSet {
  expected: ScheduledOccurrenceV1;
  expected_snapshot_revision: number;
  next: ScheduledOccurrenceV1;
  subject_ref: string;
}

export interface LegacyMissionAtomicCommit extends MissionAtomicCommit {
  adapter_ref: string;
  source_ref: string;
}

/**
 * Durable mission state. Production adapters must commit the snapshot,
 * lifecycle event, and optional scheduled work item atomically.
 */
export interface DurableMissionLedgerPort {
  /**
   * Atomically verifies the active execution lease and optional scheduled
   * occurrence claim at authority-owned time, then commits the consumed
   * occurrence, snapshot, event, and optional next scheduled work item.
   */
  commitTransition(
    commit: MissionAtomicCommit,
  ): Promise<MissionTransitionResult>;

  /**
   * Promotes only when no current record exists. A current subject or mission
   * record always wins and must remain unchanged.
   */
  promoteLegacy(
    commit: LegacyMissionAtomicCommit,
  ): Promise<MissionPromotionResult>;

  readByIdempotencyKey(
    idempotencyKey: string,
  ): Promise<MissionStoredCommit | undefined>;
  readByMissionRef(missionRef: string): Promise<MissionSnapshotV1 | undefined>;
  readBySubject(subjectRef: string): Promise<MissionSnapshotV1 | undefined>;
  readEvent(subjectRef: string, sequence: number): Promise<LifecycleEventV1 | undefined>;
  readOccurrence(
    occurrenceRef: string,
  ): Promise<ScheduledOccurrenceV1 | undefined>;

  /**
   * Atomically verifies the exact mission snapshot and occurrence before
   * installing a fenced scheduled-work lease.
   */
  compareAndSetOccurrence(
    request: MissionOccurrenceCompareAndSet,
  ): Promise<ScheduledOccurrenceV1>;
  listDue(observedAt: string, limit: number): Promise<DueMissionRecord[]>;
  listEvents(
    subjectRef: string,
    request: MissionEventPageRequest,
  ): Promise<LifecycleEventV1[]>;
}
