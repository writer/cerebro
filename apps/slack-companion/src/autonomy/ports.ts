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

export interface MissionAtomicCommit {
  event: LifecycleEventV1;
  expected_revision: number;
  idempotency_key: string;
  intent_digest: string;
  lease?: WorkLeaseV1;
  occurrence?: ScheduledOccurrenceV1;
  snapshot: MissionSnapshotV1;
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
  listDue(observedAt: string, limit: number): Promise<DueMissionRecord[]>;
  listEvents(
    subjectRef: string,
    request: MissionEventPageRequest,
  ): Promise<LifecycleEventV1[]>;
}
