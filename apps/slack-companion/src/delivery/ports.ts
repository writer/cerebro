import type {
  DeliveryClaimRequest,
  DeliveryClaimResult,
  DeliveryCompletionRequest,
  DeliveryFailureRequest,
  DeliveryMaintenanceRequest,
  DeliveryPlanResult,
  DeliveryReceiptV1,
  DurableDeliveryPlan,
  PlatformAcceptanceReceipt,
  PlatformDeliveryRequest,
} from "./contracts.js";

export interface DeliveryClockPort {
  now(): Date;
}

/**
 * A production adapter durably stores max_attempts and the payload fingerprint
 * with the receipt. Each operation is atomic with its generation and fencing
 * checks. Process-local queues are not a valid implementation.
 */
export interface DurableDeliveryPort {
  abandon(request: DeliveryMaintenanceRequest): Promise<DeliveryReceiptV1>;
  claimNext(request: DeliveryClaimRequest): Promise<DeliveryClaimResult>;
  completePart(request: DeliveryCompletionRequest): Promise<DeliveryReceiptV1>;
  pause(request: DeliveryMaintenanceRequest): Promise<DeliveryReceiptV1>;
  plan(delivery: DurableDeliveryPlan): Promise<DeliveryPlanResult>;
  read(deliveryId: string): Promise<DeliveryReceiptV1 | undefined>;
  recordFailure(request: DeliveryFailureRequest): Promise<DeliveryReceiptV1>;
  resume(request: DeliveryMaintenanceRequest): Promise<DeliveryReceiptV1>;
}

/** The transport must honor client_message_id as an idempotency identity. */
export interface PlatformDeliveryPort {
  send(request: PlatformDeliveryRequest): Promise<PlatformAcceptanceReceipt>;
}
