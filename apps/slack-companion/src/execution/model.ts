import type {
  CheckpointV1,
  EffectReceiptV1,
  RunReceiptV1,
  ServiceAvailabilityState,
  WorkLeaseV1,
} from "@writer/cerebro-sdk";

export type {
  CheckpointV1,
  EffectReceiptV1,
  RunReceiptV1,
  ServiceAvailabilityState,
  WorkLeaseV1,
};

export interface LeaseClaim {
  generation: number;
  lease_token: string;
  owner_id: string;
  run_id: string;
}

export interface ExecutionSession {
  checkpoint?: CheckpointV1;
  lease: WorkLeaseV1;
  run: RunReceiptV1;
}

export interface CheckpointDraft {
  checkpoint_id: string;
  completed_step_ids: string[];
  effect_receipt_ids: string[];
  payload_digest: string;
  payload_ref: string;
  resume_cursor: string;
  sequence: number;
  waiting_on_ref?: string;
}

export interface EffectDraft {
  approval_ref?: string;
  approval_required: boolean;
  effect_id: string;
  idempotency_key: string;
  request_digest: string;
  rollback_plan_ref?: string;
  step_id: string;
  target_ref: string;
}

export interface EffectResolution {
  result_digest: string;
  result_ref: string;
  state: "succeeded" | "failed";
  verification_receipt_ref: string;
  verification_state: "verified" | "failed";
}

export interface LeaseAcquisition {
  created: boolean;
  lease: WorkLeaseV1;
  run: RunReceiptV1;
}

export interface RecoveredRun {
  recovered: boolean;
  run?: RunReceiptV1;
  uncertain_effect_ids: string[];
}

export type ExecutionStartResult =
  | { session: ExecutionSession; status: "started" | "resumed" }
  | { status: "not_runnable" };

export const mayAcquireNewLease = (
  state: ServiceAvailabilityState,
): boolean => state === "ready" || state === "degraded";
