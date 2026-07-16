import type {
  CheckpointV1,
  EffectReceiptV1,
  RunReceiptV1,
} from "@writer/cerebro-sdk";

export const NATIVE_MISSION_CONTRACT_ID =
  "native-mission-operating-contract" as const;
export const NATIVE_MISSION_SCHEMA_VERSION =
  "cerebro.control-kernel.v1" as const;

export interface ReceiptProofV1 {
  receipt_digest: string;
  receipt_ref: string;
}

export interface EvidenceProofV1 {
  evidence_digest: string;
  evidence_ref: string;
  source_revision: string;
}

export interface MissionStepProjectionV1 {
  approval_required: boolean;
  capability_ref: string;
  capability_version: string;
  effect_id: string;
  idempotency_key: string;
  request_digest: string;
  rollback_plan_ref?: string;
  step_id: string;
  target_ref: string;
}

/**
 * A transport-neutral projection of an immutable mission plan. The durable
 * mission record remains owned by the native mission contract referenced here.
 */
export interface MissionPlanProjectionV1 {
  mission_contract_id: typeof NATIVE_MISSION_CONTRACT_ID;
  mission_ref: string;
  mission_revision: number;
  mission_schema_version: typeof NATIVE_MISSION_SCHEMA_VERSION;
  plan_digest: string;
  plan_ref: string;
  plan_revision: number;
  run_id: string;
  schema_version: "mission-plan-projection/v1";
  steps: MissionStepProjectionV1[];
}

export type CapabilityBindingState = "bound" | "missing" | "incompatible";

export interface MissionCapabilityBindingV1 {
  binding_ref: string;
  capability_ref: string;
  capability_version: string;
  state: CapabilityBindingState;
}

export interface MissionReadinessInput {
  capability_bindings: MissionCapabilityBindingV1[];
  missing_input_refs: string[];
}

export type MissionReadinessDecision =
  | { status: "ready" }
  | {
      kind: "missing_input" | "missing_tool_binding";
      status: "waiting";
      waiting_on_ref: string;
    };

export type MissionWaitKind =
  | "missing_input"
  | "missing_tool_binding"
  | "decision_required";

export interface MissionCheckpointProjectionV1 {
  checkpoint_id: string;
  completed_step_ids: string[];
  effect_receipt_ids: string[];
  sequence: number;
  state_receipt: ReceiptProofV1;
}

export interface MissionWaitProjectionV1
  extends MissionCheckpointProjectionV1 {
  kind: MissionWaitKind;
  waiting_on_ref: string;
}

export interface MissionDecisionProjectionV1 {
  decision: "approved" | "rejected";
  evidence: EvidenceProofV1[];
  mission_ref: string;
  mission_revision: number;
  plan_digest: string;
  plan_ref: string;
  plan_revision: number;
  receipt: ReceiptProofV1;
  schema_version: "mission-decision-projection/v1";
}

export interface MissionEffectResolutionV1 {
  executor_ref: string;
  result: ReceiptProofV1;
  state: "succeeded" | "failed";
  verification: MissionVerificationProjectionV1;
}

export interface MissionVerificationProjectionV1 {
  evidence: EvidenceProofV1[];
  observed_source_revision: string;
  pre_action_source_revision: string;
  receipt: ReceiptProofV1;
  verifier_ref: string;
}

export interface MissionClosureProjectionV1 {
  armed_wake_condition_refs: string[];
  checkpoint_id: string;
  completed_step_ids: string[];
  desired_condition_verified: boolean;
  effect_receipt_ids: string[];
  executor_ref: string;
  sequence: number;
  verification: MissionVerificationProjectionV1;
}

export interface MissionWaitResult {
  checkpoint: CheckpointV1;
  run: RunReceiptV1;
}

export interface MissionClosureResult {
  checkpoint: CheckpointV1;
  run: RunReceiptV1;
}

export type MissionEffectReceipt = EffectReceiptV1;
