import assert from "node:assert/strict";
import test from "node:test";
import type {
  DeliveryPartWithRetryV1,
  DeliveryReceiptV1,
} from "../src/delivery/contracts.js";
import {
  MAX_SLACK_MULTIPART_PARTS,
  projectSlackMultipartDelivery,
  SlackMultipartProjectionError,
} from "../src/index.js";

test("multipart projections preserve exact acceptance and partial progress", () => {
  const projection = projectSlackMultipartDelivery(deliveryReceipt());

  assert.equal(projection.accepted_part_count, 1);
  assert.equal(projection.undelivered_part_count, 1);
  assert.equal(projection.parts[0]?.client_message_id, "delivery-1:part:1");
  assert.deepEqual(projection.parts[0]?.acceptance, {
    accepted_at: "2026-07-18T10:00:02.000Z",
    destination_receipt: "slack-receipt://message/one",
  });
  assert.equal(projection.parts[1]?.state, "pending");
  assert.match(
    projection.projection_id,
    /^delivery-1:sha256:[0-9a-f]{64}$/,
  );
  assert.equal(
    projection.projection_id,
    projectSlackMultipartDelivery(deliveryReceipt()).projection_id,
  );
  assert.equal(Object.isFrozen(projection), true);
  assert.equal(Object.isFrozen(projection.parts), true);
});

test("multipart projections accept the canonical delivering part state", () => {
  const receipt = deliveryReceipt();
  const projection = projectSlackMultipartDelivery({
    ...receipt,
    parts: [
      receipt.parts[0]!,
      { ...receipt.parts[1]!, state: "delivering" },
    ],
  });

  assert.equal(projection.state, "delivering");
  assert.equal(projection.parts[1]?.state, "delivering");
});

test("multipart projections preserve retryable failed parts", () => {
  const receipt = deliveryReceipt();
  const projection = projectSlackMultipartDelivery({
    ...receipt,
    parts: [
      receipt.parts[0]!,
      { ...receipt.parts[1]!, state: "failed" },
    ],
  });

  assert.equal(projection.state, "delivering");
  assert.equal(projection.parts[1]?.state, "failed");
  assert.equal(projection.undelivered_part_count, 1);
});

test("multipart projections expose retry timing for failed parts only", () => {
  const receipt = deliveryReceipt();
  const projection = projectSlackMultipartDelivery({
    ...receipt,
    parts: [
      receipt.parts[0]!,
      {
        ...receipt.parts[1]!,
        next_attempt_at: "2026-07-18T10:00:07.000Z",
        state: "failed",
      } as DeliveryPartWithRetryV1,
    ],
  });

  assert.equal(projection.parts[1]?.state, "failed");
  assert.equal(projection.parts[1]?.next_attempt_at, "2026-07-18T10:00:07.000Z");
  assert.throws(
    () =>
      projectSlackMultipartDelivery({
        ...receipt,
        parts: [
          receipt.parts[0]!,
          {
            ...receipt.parts[1]!,
            next_attempt_at: "2026-07-18T10:00:07.000Z",
          } as DeliveryPartWithRetryV1,
        ],
      }),
    /Only failed Slack multipart parts can carry retry timing/,
  );
});

test("multipart projection identities distinguish same-time state changes", () => {
  const receipt = deliveryReceipt();
  const paused = projectSlackMultipartDelivery({
    ...receipt,
    parts: [
      receipt.parts[0]!,
      { ...receipt.parts[1]!, state: "paused" },
    ],
    state: "paused",
  });
  const delivering = projectSlackMultipartDelivery(receipt);

  assert.equal(paused.updated_at, delivering.updated_at);
  assert.notEqual(paused.projection_id, delivering.projection_id);
});

test("multipart projections reject gaps and duplicate durable identities", () => {
  const receipt = deliveryReceipt();
  assert.throws(
    () =>
      projectSlackMultipartDelivery({
        ...receipt,
        parts: [
          receipt.parts[0]!,
          { ...receipt.parts[1]!, sequence: 3 },
        ],
      }),
    /sequences must be contiguous/,
  );
  assert.throws(
    () =>
      projectSlackMultipartDelivery({
        ...receipt,
        parts: [
          receipt.parts[0]!,
          { ...receipt.parts[1]!, part_id: "part-1" },
        ],
      }),
    /repeats part_id/,
  );
  assert.throws(
    () =>
      projectSlackMultipartDelivery({
        ...receipt,
        parts: [
          receipt.parts[0]!,
          {
            ...receipt.parts[1]!,
            idempotency_key: "delivery-1:part:1",
          },
        ],
      }),
    /repeats idempotency_key/,
  );
});

test("multipart projections reject contradictory acceptance receipts", () => {
  const receipt = deliveryReceipt();
  assert.throws(
    () =>
      projectSlackMultipartDelivery({
        ...receipt,
        parts: [
          { ...receipt.parts[0]!, destination_receipt: undefined },
          receipt.parts[1]!,
        ],
      }),
    SlackMultipartProjectionError,
  );
  assert.throws(
    () =>
      projectSlackMultipartDelivery({
        ...receipt,
        parts: [
          receipt.parts[0]!,
          {
            ...receipt.parts[1]!,
            delivered_at: "2026-07-18T10:00:03.000Z",
          },
        ],
      }),
    /cannot carry an acceptance receipt/,
  );
});

test("multipart projections enforce truthful aggregate states", () => {
  const receipt = deliveryReceipt();
  assert.throws(
    () => projectSlackMultipartDelivery({ ...receipt, state: "completed" }),
    /completed Slack multipart delivery contains a contradictory part state/,
  );
  assert.throws(
    () => projectSlackMultipartDelivery({ ...receipt, state: "pending" }),
    /pending Slack multipart delivery contains a contradictory part state/,
  );
  assert.throws(
    () =>
      projectSlackMultipartDelivery({
        ...receipt,
        parts: receipt.parts.map((part) => ({
          ...part,
          delivered_at: undefined,
          destination_receipt: undefined,
          state: "pending" as const,
        })),
      }),
    /requires a started part/,
  );
  assert.throws(
    () =>
      projectSlackMultipartDelivery({
        ...receipt,
        state: "paused",
      }),
    /requires a paused part/,
  );
  assert.throws(
    () =>
      projectSlackMultipartDelivery({
        ...receipt,
        parts: [
          receipt.parts[0]!,
          { ...receipt.parts[1]!, state: "abandoned" },
        ],
        state: "failed",
      }),
    /contains a contradictory part state/,
  );
});

test("multipart projections support paused, abandoned, and failed truth", () => {
  const receipt = deliveryReceipt();
  for (const state of ["paused", "abandoned", "failed"] as const) {
    const projection = projectSlackMultipartDelivery({
      ...receipt,
      parts: [
        receipt.parts[0]!,
        { ...receipt.parts[1]!, state },
      ],
      state,
    });
    assert.equal(projection.state, state);
    assert.equal(projection.parts[1]?.state, state);
  }
});

test("multipart projections require canonical timestamps and opaque refs", () => {
  const receipt = deliveryReceipt();
  assert.throws(
    () =>
      projectSlackMultipartDelivery({
        ...receipt,
        updated_at: "2026-07-18T10:00:02Z",
      }),
    /canonical ISO-8601 timestamp/,
  );
  assert.throws(
    () =>
      projectSlackMultipartDelivery({
        ...receipt,
        destination_ref: "channel-and-thread",
      }),
    /must be an opaque reference/,
  );
});

test("multipart projections reject oversized and sparse part arrays before sorting", () => {
  const receipt = deliveryReceipt();
  const oversized = Array.from(
    { length: MAX_SLACK_MULTIPART_PARTS + 1 },
    () => receipt.parts[0]!,
  );
  assert.throws(
    () => projectSlackMultipartDelivery({ ...receipt, parts: oversized }),
    /requires between 1 and 40 parts/,
  );

  const sparse = new Array<DeliveryReceiptV1["parts"][number]>(
    MAX_SLACK_MULTIPART_PARTS + 1,
  );
  assert.throws(
    () => projectSlackMultipartDelivery({ ...receipt, parts: sparse }),
    /requires between 1 and 40 parts/,
  );
});

function deliveryReceipt(): DeliveryReceiptV1 {
  return {
    created_at: "2026-07-18T10:00:00.000Z",
    delivery_id: "delivery-1",
    destination_ref: "slack-thread://channel/thread",
    parts: [
      {
        delivered_at: "2026-07-18T10:00:02.000Z",
        destination_receipt: "slack-receipt://message/one",
        idempotency_key: "delivery-1:part:1",
        part_id: "part-1",
        payload_digest: "sha256:one",
        payload_ref: "payload://delivery/one",
        sequence: 1,
        state: "delivered",
      },
      {
        idempotency_key: "delivery-1:part:2",
        part_id: "part-2",
        payload_digest: "sha256:two",
        payload_ref: "payload://delivery/two",
        sequence: 2,
        state: "pending",
      },
    ],
    run_id: "run-1",
    schema_version: "delivery-receipt/v1",
    state: "delivering",
    updated_at: "2026-07-18T10:00:02.000Z",
  };
}
