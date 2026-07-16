import type {
  LifecycleEventV1,
  RunReceiptV1,
  ScheduledOccurrenceV1,
  WorkLeaseV1,
} from "@writer/cerebro-sdk";
import type { ExecutionSession } from "../execution/model.js";
import type { MissionPlanProjectionV1 } from "../mission/model.js";
import {
  NATIVE_MISSION_CONTRACT_ID,
  NATIVE_MISSION_SCHEMA_VERSION,
} from "../mission/model.js";

export type {
  LifecycleEventV1,
  RunReceiptV1,
  ScheduledOccurrenceV1,
  WorkLeaseV1,
};

export const MISSION_SNAPSHOT_SCHEMA_VERSION =
  "slack-companion-mission-snapshot/v1" as const;

/**
 * A bounded projection of the current durable mission. Lifecycle, execution,
 * and scheduling state remain represented by their existing public records.
 */
export interface MissionSnapshotV1 {
  last_execution_lease?: WorkLeaseV1;
  latest_event_ref: string;
  mission_contract_id: typeof NATIVE_MISSION_CONTRACT_ID;
  mission_ref: string;
  mission_schema_version: typeof NATIVE_MISSION_SCHEMA_VERSION;
  plan: MissionPlanProjectionV1;
  recent_event_refs: string[];
  revision: number;
  run: RunReceiptV1;
  schema_version: typeof MISSION_SNAPSHOT_SCHEMA_VERSION;
  subject_ref: string;
  updated_at: string;
  wake?: MissionWakeProjectionV1;
}

/** A mission wake points at the canonical scheduled-occurrence record. */
export interface MissionWakeProjectionV1 {
  occurrence_ref: string;
  wake_condition_ref: string;
}

export interface MissionWakeInput {
  occurrence: ScheduledOccurrenceV1;
  wake_condition_ref: string;
}

export interface MissionSnapshotSeed {
  plan: MissionPlanProjectionV1;
  run: RunReceiptV1;
  wake?: MissionWakeInput;
}

export interface MissionLedgerEventContext {
  causation_id?: string;
  correlation_id?: string;
  occurred_at: string;
  observed_at: string;
  producer: LifecycleEventV1["producer"];
  reason: LifecycleEventV1["reason"];
  service_id: string;
  trace_id?: string;
}

export interface InitializeMissionInput {
  event: MissionLedgerEventContext;
  operation_id: string;
  seed: MissionSnapshotSeed;
}

export interface TransitionMissionInput {
  attempt: number;
  event: MissionLedgerEventContext;
  expected_revision: number;
  next_run?: RunReceiptV1;
  operation_id: string;
  plan?: MissionPlanProjectionV1;
  session: ExecutionSession;
  wake?: MissionWakeInput | null;
}

/**
 * A legacy adapter must normalize its source into the current portable seed.
 * Provider or environment identities are deliberately outside this contract.
 */
export interface LegacyMissionCandidateV1 {
  adapter_ref: string;
  seed: MissionSnapshotSeed;
  source_ref: string;
}

export interface PromoteLegacyMissionInput {
  candidate: LegacyMissionCandidateV1;
  event: MissionLedgerEventContext;
  operation_id: string;
}

export interface MissionTransitionResult {
  created: boolean;
  event: LifecycleEventV1;
  occurrence?: ScheduledOccurrenceV1;
  snapshot: MissionSnapshotV1;
}

export interface MissionPromotionResult {
  created: boolean;
  event?: LifecycleEventV1;
  occurrence?: ScheduledOccurrenceV1;
  snapshot: MissionSnapshotV1;
}

export interface DueMissionRecord {
  occurrence: ScheduledOccurrenceV1;
  snapshot: MissionSnapshotV1;
}

export interface MissionEventPageRequest {
  after_sequence?: number;
  limit: number;
}

export interface MissionStoredCommit {
  event: LifecycleEventV1;
  intent_digest: string;
  occurrence?: ScheduledOccurrenceV1;
  snapshot: MissionSnapshotV1;
}
