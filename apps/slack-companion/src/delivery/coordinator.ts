import { createHash } from "node:crypto";
import type {
  DeliveryPartV1,
  DeliveryPlanRequest,
  DeliveryPlanResult,
  DeliveryStepResult,
  WorkLeaseV1,
} from "./contracts.js";
import type {
  DeliveryClockPort,
  DurableDeliveryPort,
  PlatformDeliveryPort,
} from "./ports.js";

export class DeliveryInputError extends Error {}

export interface DeliveryCoordinatorOptions {
  clock: DeliveryClockPort;
  sender: PlatformDeliveryPort;
  store: DurableDeliveryPort;
}

export class DeliveryCoordinator {
  private readonly clock: DeliveryClockPort;
  private readonly sender: PlatformDeliveryPort;
  private readonly store: DurableDeliveryPort;

  constructor(options: DeliveryCoordinatorOptions) {
    this.clock = options.clock;
    this.sender = options.sender;
    this.store = options.store;
  }

  async plan(request: DeliveryPlanRequest): Promise<DeliveryPlanResult> {
    validatePlan(request);
    const now = this.clock.now().toISOString();
    const deliveryId = stableIdentity("delivery", [
      request.run_id,
      request.destination_ref,
      request.delivery_key,
    ]);
    const parts: DeliveryPartV1[] = request.parts.map((part, index) => {
      const sequence = index + 1;
      const partId = stableIdentity("part", [deliveryId, String(sequence)]);
      return {
        idempotency_key: stableIdentity("message", [deliveryId, partId]),
        part_id: partId,
        payload_digest: part.payload_digest,
        payload_ref: part.payload_ref,
        sequence,
        state: "pending",
      };
    });

    return this.store.plan({
      max_attempts: request.max_attempts,
      payload_fingerprint: payloadFingerprint(request),
      receipt: {
        created_at: now,
        delivery_id: deliveryId,
        destination_ref: request.destination_ref,
        parts,
        run_id: request.run_id,
        schema_version: "delivery-receipt/v1",
        state: "pending",
        updated_at: now,
      },
    });
  }

  async deliverNext(
    deliveryId: string,
    lease: WorkLeaseV1,
  ): Promise<DeliveryStepResult> {
    const claimResult = await this.store.claimNext({
      delivery_id: deliveryId,
      lease,
      now: this.clock.now().toISOString(),
    });
    if (claimResult.status === "idle") {
      return {
        receipt: claimResult.receipt,
        status: claimResult.reason,
      };
    }

    const { claim } = claimResult;
    const plannedReceipt = await this.requireReceipt(deliveryId);
    let acceptance;
    try {
      acceptance = await this.sender.send({
        client_message_id: claim.client_message_id,
        destination_ref: plannedReceipt.destination_ref,
        payload_digest: claim.part.payload_digest,
        payload_ref: claim.part.payload_ref,
      });
    } catch {
      const receipt = await this.store.recordFailure({
        delivery_id: deliveryId,
        failed_at: this.clock.now().toISOString(),
        lease,
        part_id: claim.part.part_id,
      });
      return {
        receipt,
        status: receipt.state === "failed"
          ? "retry_exhausted"
          : "retry_scheduled",
      };
    }
    if (!acceptance.destination_receipt) {
      const receipt = await this.store.recordFailure({
        delivery_id: deliveryId,
        failed_at: this.clock.now().toISOString(),
        lease,
        part_id: claim.part.part_id,
      });
      return {
        receipt,
        status: receipt.state === "failed"
          ? "retry_exhausted"
          : "retry_scheduled",
      };
    }

    // Once the destination accepts, never rewrite this as a send failure. If
    // persistence is interrupted, the stable client_message_id makes recovery
    // safe after the claim expires.
    const receipt = await this.store.completePart({
      accepted_at: acceptance.accepted_at,
      delivery_id: deliveryId,
      destination_receipt: acceptance.destination_receipt,
      lease,
      part_id: claim.part.part_id,
    });
    return {
      destination_receipt: acceptance.destination_receipt,
      part_id: claim.part.part_id,
      receipt,
      status: "delivered",
    };
  }

  abandon(deliveryId: string, lease: WorkLeaseV1) {
    return this.store.abandon({
      delivery_id: deliveryId,
      lease,
      occurred_at: this.clock.now().toISOString(),
    });
  }

  pause(deliveryId: string, lease: WorkLeaseV1) {
    return this.store.pause({
      delivery_id: deliveryId,
      lease,
      occurred_at: this.clock.now().toISOString(),
    });
  }

  resume(deliveryId: string, lease: WorkLeaseV1) {
    return this.store.resume({
      delivery_id: deliveryId,
      lease,
      occurred_at: this.clock.now().toISOString(),
    });
  }

  private async requireReceipt(deliveryId: string) {
    const receipt = await this.store.read(deliveryId);
    if (receipt === undefined) {
      throw new DeliveryInputError("The delivery does not exist.");
    }
    return receipt;
  }
}

function validatePlan(request: DeliveryPlanRequest): void {
  if (
    !request.delivery_key ||
    !request.destination_ref ||
    !request.run_id ||
    request.parts.length === 0
  ) {
    throw new DeliveryInputError(
      "Delivery key, destination, run, and at least one part are required.",
    );
  }
  if (!Number.isInteger(request.max_attempts) || request.max_attempts < 1) {
    throw new DeliveryInputError("max_attempts must be a positive integer.");
  }
  for (const part of request.parts) {
    if (!part.payload_digest || !part.payload_ref) {
      throw new DeliveryInputError(
        "Each delivery part requires a payload reference and digest.",
      );
    }
  }
}

function payloadFingerprint(request: DeliveryPlanRequest): string {
  return digest(
    JSON.stringify({
      delivery_key: request.delivery_key,
      destination_ref: request.destination_ref,
      max_attempts: request.max_attempts,
      parts: request.parts.map((part) => [part.payload_digest, part.payload_ref]),
      run_id: request.run_id,
    }),
  );
}

export function stableIdentity(namespace: string, fields: readonly string[]): string {
  return `${namespace}-${digest(JSON.stringify(fields)).slice(0, 32)}`;
}

function digest(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
