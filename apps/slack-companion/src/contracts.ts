import type {
  AgentServiceBindingV1,
  CapabilityCompatibilityDecision,
  CapabilityRequirement,
  InstallationLifecycleState,
  PresenceSnapshotV1,
  RunKind,
  RunReceiptV1,
  ServiceAvailabilityState,
} from "@writer/cerebro-sdk";

export type {
  AgentServiceBindingV1,
  CapabilityCompatibilityDecision,
  CapabilityRequirement,
  InstallationLifecycleState,
  PresenceSnapshotV1,
  RunKind,
  RunReceiptV1,
  ServiceAvailabilityState,
};

/** A verified Slack input. Transport authentication happens before this boundary. */
export interface SlackIngressEnvelope {
  app_id: string;
  binding_id: string;
  conversation_id: string;
  event_id: string;
  event_type: string;
  payload_digest: string;
  payload_ref: string;
  received_at: string;
  required_capabilities: CapabilityRequirement[];
  retention_policy_ref: string;
  run_kind: RunKind;
  subject_ref: string;
  tenant_id: string;
  thread_id: string;
}

export interface AdmissionContext {
  binding: AgentServiceBindingV1;
  presence: PresenceSnapshotV1;
}

export type AcceptedSlackStatus = "queued" | "degraded" | "recovering";

export interface AcceptedSlackAcknowledgement {
  acknowledgement_permitted: true;
  duplicate: boolean;
  message: string;
  retryable: false;
  run_id: string;
  status: AcceptedSlackStatus;
}

export interface RejectedSlackAcknowledgement {
  acknowledgement_permitted: false;
  duplicate: false;
  message: string;
  retryable: boolean;
  status: "rejected";
}

export type SlackAdmissionResult =
  | AcceptedSlackAcknowledgement
  | RejectedSlackAcknowledgement;

export interface AdmissionPolicy {
  admit_while_degraded: boolean;
  offline_behavior: "queue" | "reject";
}

export interface AdmissionCommit {
  envelope: SlackIngressEnvelope;
  receipt: RunReceiptV1;
  /**
   * The adapter commits these transitions with the receipt and queue entry.
   * They are append-only facts, not best-effort telemetry.
   */
  transitions: readonly [
    { from: "received"; to: "admitted" },
    { from: "admitted"; to: "queued" },
  ];
}

export interface AdmissionCommitResult {
  created: boolean;
  receipt: RunReceiptV1;
}

export interface InstallationTransition {
  binding_id: string;
  expected_generation: number;
  from: InstallationLifecycleState;
  reason_code: string;
  to: InstallationLifecycleState;
}

export interface InstallationTransitionResult {
  binding: AgentServiceBindingV1;
  changed: boolean;
}

export interface AdmissionStatus {
  accepted_status?: AcceptedSlackStatus;
  admit: boolean;
  message: string;
  retryable: boolean;
  service_state: ServiceAvailabilityState;
}
