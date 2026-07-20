import type {
  DeliveryPartV1,
  DeliveryReceiptV1,
  WorkLeaseV1,
} from "@writer/cerebro-sdk";

export type { DeliveryPartV1, DeliveryReceiptV1, WorkLeaseV1 };

export interface DeliveryPayloadPart {
  payload_digest: string;
  payload_ref: string;
}

/** One logical delivery. Reusing delivery_key with different content conflicts. */
export interface DeliveryPlanRequest {
  delivery_key: string;
  destination_ref: string;
  max_attempts: number;
  parts: readonly DeliveryPayloadPart[];
  run_id: string;
}

export interface DurableDeliveryPlan {
  max_attempts: number;
  payload_fingerprint: string;
  receipt: DeliveryReceiptV1;
}

export interface DeliveryPlanResult {
  created: boolean;
  receipt: DeliveryReceiptV1;
}

export interface DeliveryPartClaim {
  attempt: number;
  client_message_id: string;
  delivery_id: string;
  lease: WorkLeaseV1;
  part: DeliveryPartV1;
}

export type DeliveryClaimResult =
  | { claim: DeliveryPartClaim; status: "claimed" }
  | {
      reason: "abandoned" | "busy" | "complete" | "paused" | "retry_exhausted";
      receipt: DeliveryReceiptV1;
      status: "idle";
    };

export interface DeliveryClaimRequest {
  delivery_id: string;
  lease: WorkLeaseV1;
  now: string;
}

export interface DeliveryCompletionRequest {
  accepted_at: string;
  delivery_id: string;
  destination_receipt: string;
  lease: WorkLeaseV1;
  part_id: string;
}

export interface DeliveryFailureRequest {
  delivery_id: string;
  failed_at: string;
  lease: WorkLeaseV1;
  part_id: string;
}

export interface DeliveryMaintenanceRequest {
  delivery_id: string;
  lease: WorkLeaseV1;
  occurred_at: string;
}

export interface PlatformDeliveryRequest {
  client_message_id: string;
  destination_ref: string;
  payload_digest: string;
  payload_ref: string;
}

export interface PlatformAcceptanceReceipt {
  accepted_at: string;
  destination_receipt: string;
}

export type DeliveryStepResult =
  | {
      destination_receipt: string;
      part_id: string;
      receipt: DeliveryReceiptV1;
      status: "delivered";
    }
  | {
      receipt: DeliveryReceiptV1;
      status: "abandoned" | "busy" | "complete" | "paused" | "retry_exhausted";
    }
  | {
      receipt: DeliveryReceiptV1;
      status: "retry_scheduled";
    };
