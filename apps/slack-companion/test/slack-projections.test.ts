import assert from "node:assert/strict";
import test from "node:test";
import type { DeliveryReceiptV1 } from "../src/delivery/contracts.js";
import {
  projectAssistantTurnProgress,
  projectSlackMultipartDelivery,
  projectSlackVisibleStatus,
  SlackProjectionError,
} from "../src/index.js";

test("status projections keep stable ids without choosing a Slack transport", () => {
  const status = projectSlackVisibleStatus({
    code: "queued",
    expires_at: "2026-07-18T10:05:00.000Z",
    idempotency_key: "run-1:queued:1",
    message: "Cerebro saved this request. It is queued for execution.",
    observed_at: "2026-07-18T10:00:00.000Z",
    run_id: "run-1",
  });
  assert.deepEqual(status, {
    code: "queued",
    expires_at: "2026-07-18T10:05:00.000Z",
    kind: "run_status",
    observed_at: "2026-07-18T10:00:00.000Z",
    operation: "upsert",
    projection_id: "run-1:queued:1",
    run_id: "run-1",
    schema_version: "slack-status-projection/v1",
    text: "Cerebro saved this request. It is queued for execution.",
  });

  const progress = projectAssistantTurnProgress("run-1", {
    execution_lane: "investigate",
    occurred_at: "2026-07-18T10:00:01.000Z",
    phase: "checking",
    schema_version: "assistant-turn-progress/v1",
    sequence: 2,
    status: "Checking the available evidence",
  });
  assert.equal(progress.code, "assistant_checking");
  assert.equal(progress.projection_id, "run-1:assistant-progress:2");
  assert.equal(progress.operation, "upsert");
});

test("multipart projections preserve exact part acceptance and partial state", () => {
  const receipt = deliveryReceipt();
  const projection = projectSlackMultipartDelivery(receipt);

  assert.equal(projection.accepted_part_count, 1);
  assert.equal(projection.undelivered_part_count, 1);
  assert.equal(projection.parts[0]?.client_message_id, "delivery-1:part:1");
  assert.deepEqual(projection.parts[0]?.acceptance, {
    accepted_at: "2026-07-18T10:00:02.000Z",
    destination_receipt: "slack-receipt://message/one",
  });
  assert.equal(projection.parts[1]?.state, "pending");
  assert.equal(projection.projection_id, "delivery-1:2026-07-18T10:00:02.000Z");
});

test("multipart projections reject contradictory or duplicate receipts", () => {
  const receipt = deliveryReceipt();
  assert.throws(
    () => projectSlackMultipartDelivery({ ...receipt, state: "completed" }),
    /requires every part acceptance/,
  );
  assert.throws(
    () =>
      projectSlackMultipartDelivery({
        ...receipt,
        parts: [receipt.parts[0]!, { ...receipt.parts[1]!, part_id: "part-1" }],
      }),
    /repeats part_id/,
  );
  assert.throws(
    () =>
      projectSlackMultipartDelivery({
        ...receipt,
        parts: [
          { ...receipt.parts[0]!, destination_receipt: undefined },
          receipt.parts[1]!,
        ],
      }),
    SlackProjectionError,
  );
});

test("multipart projections reject false pending and delivering aggregates", () => {
  const receipt = deliveryReceipt();
  assert.throws(
    () => projectSlackMultipartDelivery({ ...receipt, state: "pending" }),
    /every part to be pending/,
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
        parts: receipt.parts.map((part, index) => ({
          ...part,
          delivered_at: `2026-07-18T10:00:0${index + 2}.000Z`,
          destination_receipt: `slack-receipt://message/${index + 1}`,
          state: "delivered" as const,
        })),
      }),
    /requires an unfinished part/,
  );
  for (const state of ["paused", "failed", "abandoned"] as const) {
    assert.throws(
      () =>
        projectSlackMultipartDelivery({
          ...receipt,
          parts: [
            receipt.parts[0]!,
            { ...receipt.parts[1]!, state },
          ],
        }),
      /cannot contain terminal or paused parts/,
    );
  }
});

test("Slack projections reject equivalent non-canonical timestamps", () => {
  assert.throws(
    () =>
      projectSlackVisibleStatus({
        code: "queued",
        expires_at: "2026-07-18T10:05:00.000Z",
        idempotency_key: "run-1:queued:1",
        message: "Cerebro saved this request. It is queued for execution.",
        observed_at: "2026-07-18T10:00:00Z",
        run_id: "run-1",
      }),
    /canonical ISO-8601 timestamp/,
  );
  assert.throws(
    () =>
      projectAssistantTurnProgress("run-1", {
        occurred_at: "2026-07-18T10:00:01Z",
        phase: "checking",
        schema_version: "assistant-turn-progress/v1",
        sequence: 2,
        status: "Checking the available evidence",
      }),
    /canonical ISO-8601 timestamp/,
  );
  const receipt = deliveryReceipt();
  assert.throws(
    () =>
      projectSlackMultipartDelivery({
        ...receipt,
        updated_at: "2026-07-18T10:00:02Z",
      }),
    /canonical ISO-8601 timestamp/,
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
