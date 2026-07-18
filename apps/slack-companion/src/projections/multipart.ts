import type { DeliveryPartV1, DeliveryReceiptV1 } from "../delivery/contracts.js";
import { SlackProjectionError } from "./status.js";

export interface SlackMultipartAcceptanceV1 {
  readonly accepted_at: string;
  readonly destination_receipt: string;
}

export interface SlackMultipartPartProjectionV1 {
  readonly acceptance?: SlackMultipartAcceptanceV1;
  readonly client_message_id: string;
  readonly part_id: string;
  readonly payload_digest: string;
  readonly payload_ref: string;
  readonly schema_version: "slack-multipart-part-projection/v1";
  readonly sequence: number;
  readonly state: DeliveryPartV1["state"];
}

export interface SlackMultipartProjectionV1 {
  readonly accepted_part_count: number;
  readonly delivery_id: string;
  readonly destination_ref: string;
  readonly part_count: number;
  readonly parts: readonly SlackMultipartPartProjectionV1[];
  readonly projection_id: string;
  readonly run_id: string;
  readonly schema_version: "slack-multipart-projection/v1";
  readonly state: DeliveryReceiptV1["state"];
  readonly undelivered_part_count: number;
  readonly updated_at: string;
}

export function projectSlackMultipartDelivery(
  receipt: DeliveryReceiptV1,
): SlackMultipartProjectionV1 {
  if (receipt.schema_version !== "delivery-receipt/v1") {
    throw new SlackProjectionError("Slack multipart delivery version is unsupported.");
  }
  if (!Array.isArray(receipt.parts) || receipt.parts.length === 0) {
    throw new SlackProjectionError("Slack multipart delivery requires at least one part.");
  }
  const deliveryId = requiredKey(receipt.delivery_id, "delivery_id");
  const runId = requiredKey(receipt.run_id, "run_id");
  const destinationRef = requiredRef(receipt.destination_ref, "destination_ref");
  const updatedAt = requiredTimestamp(receipt.updated_at, "updated_at");
  requiredTimestamp(receipt.created_at, "created_at");

  const partIds = new Set<string>();
  const messageIds = new Set<string>();
  const parts = [...receipt.parts]
    .sort((left, right) => left.sequence - right.sequence)
    .map((part, index) =>
      projectPart(part, index + 1, partIds, messageIds),
    );
  validateAggregateState(receipt.state, parts);
  const acceptedPartCount = parts.filter((part) => part.state === "delivered").length;
  return Object.freeze({
    accepted_part_count: acceptedPartCount,
    delivery_id: deliveryId,
    destination_ref: destinationRef,
    part_count: parts.length,
    parts: Object.freeze(parts),
    projection_id: `${deliveryId}:${updatedAt}`,
    run_id: runId,
    schema_version: "slack-multipart-projection/v1",
    state: receipt.state,
    undelivered_part_count: parts.length - acceptedPartCount,
    updated_at: updatedAt,
  });
}

function projectPart(
  part: DeliveryPartV1,
  expectedSequence: number,
  partIds: Set<string>,
  messageIds: Set<string>,
): SlackMultipartPartProjectionV1 {
  if (part.sequence !== expectedSequence) {
    throw new SlackProjectionError("Slack multipart part sequences must be contiguous.");
  }
  const partId = uniqueKey(part.part_id, "part_id", partIds);
  const clientMessageId = uniqueKey(
    part.idempotency_key,
    "idempotency_key",
    messageIds,
  );
  const payloadDigest = requiredKey(part.payload_digest, "payload_digest");
  const payloadRef = requiredRef(part.payload_ref, "payload_ref");
  let acceptance: SlackMultipartAcceptanceV1 | undefined;
  if (part.state === "delivered") {
    if (part.destination_receipt === undefined || part.delivered_at === undefined) {
      throw new SlackProjectionError(
        "Delivered Slack multipart parts require an acceptance receipt.",
      );
    }
    acceptance = Object.freeze({
      accepted_at: requiredTimestamp(part.delivered_at, "delivered_at"),
      destination_receipt: requiredKey(
        part.destination_receipt,
        "destination_receipt",
      ),
    });
  } else if (part.destination_receipt !== undefined || part.delivered_at !== undefined) {
    throw new SlackProjectionError(
      "Undelivered Slack multipart parts cannot carry an acceptance receipt.",
    );
  }
  return Object.freeze({
    ...(acceptance === undefined ? {} : { acceptance }),
    client_message_id: clientMessageId,
    part_id: partId,
    payload_digest: payloadDigest,
    payload_ref: payloadRef,
    schema_version: "slack-multipart-part-projection/v1",
    sequence: part.sequence,
    state: part.state,
  });
}

function validateAggregateState(
  state: DeliveryReceiptV1["state"],
  parts: readonly SlackMultipartPartProjectionV1[],
): void {
  if (state === "pending" && parts.some((part) => part.state !== "pending")) {
    throw new SlackProjectionError(
      "Pending Slack multipart delivery requires every part to be pending.",
    );
  }
  if (state === "delivering") {
    if (
      parts.some((part) =>
        !["pending", "sending", "delivered"].includes(part.state)
      )
    ) {
      throw new SlackProjectionError(
        "Delivering Slack multipart delivery cannot contain terminal or paused parts.",
      );
    }
    if (parts.every((part) => part.state === "pending")) {
      throw new SlackProjectionError(
        "Delivering Slack multipart delivery requires a started part.",
      );
    }
    if (parts.every((part) => part.state === "delivered")) {
      throw new SlackProjectionError(
        "Delivering Slack multipart delivery requires an unfinished part.",
      );
    }
  }
  if (state === "completed" && parts.some((part) => part.state !== "delivered")) {
    throw new SlackProjectionError(
      "Completed Slack multipart delivery requires every part acceptance.",
    );
  }
  if (state === "paused" && parts.every((part) => part.state !== "paused")) {
    throw new SlackProjectionError("Paused Slack multipart delivery requires a paused part.");
  }
  if (state === "abandoned" && parts.every((part) => part.state !== "abandoned")) {
    throw new SlackProjectionError(
      "Abandoned Slack multipart delivery requires an abandoned part.",
    );
  }
  if (state === "failed" && parts.every((part) => part.state !== "failed")) {
    throw new SlackProjectionError("Failed Slack multipart delivery requires a failed part.");
  }
}

function uniqueKey(value: string, field: string, seen: Set<string>): string {
  const normalized = requiredKey(value, field);
  if (seen.has(normalized)) {
    throw new SlackProjectionError(`Slack multipart delivery repeats ${field}.`);
  }
  seen.add(normalized);
  return normalized;
}

function requiredTimestamp(value: string, field: string): string {
  const normalized = requiredText(value, field, 64);
  const parsed = Date.parse(normalized);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== normalized) {
    throw new SlackProjectionError(
      `Slack multipart ${field} must be a canonical ISO-8601 timestamp.`,
    );
  }
  return normalized;
}

function requiredRef(value: string, field: string): string {
  const normalized = requiredText(value, field, 2_048);
  if (!/^[a-z][a-z0-9+.-]*:\/\/\S+$/.test(normalized)) {
    throw new SlackProjectionError(
      `Slack multipart ${field} must be an opaque reference.`,
    );
  }
  return normalized;
}

function requiredKey(value: string, field: string): string {
  const normalized = requiredText(value, field, 512);
  if (/\s/.test(normalized)) {
    throw new SlackProjectionError(
      `Slack multipart ${field} must not contain whitespace.`,
    );
  }
  return normalized;
}

function requiredText(value: string, field: string, maximum: number): string {
  if (
    typeof value !== "string"
    || value.length === 0
    || value.length > maximum
    || /[\u0000-\u001f\u007f]/.test(value)
  ) {
    throw new SlackProjectionError(`Slack multipart ${field} is invalid.`);
  }
  return value;
}
