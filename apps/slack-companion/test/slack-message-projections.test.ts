import assert from "node:assert/strict";
import test from "node:test";
import type { DeliveryReceiptV1 } from "../src/delivery/contracts.js";
import {
  MAX_SLACK_MESSAGE_PART_LENGTH,
  MAX_SLACK_MESSAGE_SOURCE_LENGTH,
  planSlackMessage,
  projectSlackMessages,
  projectSlackMultipartDelivery,
  SlackMessageProjectionError,
  type SlackMessagePlanV1,
  type SlackMultipartProjectionV1,
} from "../src/index.js";

test("message plans split deterministically without activating untrusted text", () => {
  const source = `${"a".repeat(2_790)}\n${"🙂".repeat(50)} <@U123> *literal*`;
  const first = planSlackMessage("run-one:answer", source);
  const retry = planSlackMessage("run-one:answer", source);

  assert.deepEqual(retry, first);
  assert.equal(first.parts.length, 2);
  assert.equal(
    first.parts.map((part) => part.payload.text).join(""),
    source,
  );
  for (const part of first.parts) {
    assert.ok(Array.from(part.payload.text).length <= MAX_SLACK_MESSAGE_PART_LENGTH);
    assert.equal(part.payload.mrkdwn, false);
    assert.equal(part.payload.link_names, false);
    assert.equal(part.payload.unfurl_links, false);
    assert.equal(part.payload.unfurl_media, false);
    assert.equal(part.payload.blocks[0]?.type, "section");
    assert.equal(JSON.stringify(part.payload).includes('"type":"mrkdwn"'), false);
    assert.match(part.payload_digest, /^sha256:[0-9a-f]{64}$/);
  }
  assert.equal(Object.isFrozen(first.parts), true);

  const normalizedRetry = planSlackMessage(
    "run-one:normalized",
    "line one\r\nline two",
  );
  assert.equal(normalizedRetry.parts[0]?.payload.text, "line one\nline two");
});

test("message projections preserve multipart retry and resume identities", () => {
  const plan = planSlackMessage(
    "run-one:answer",
    `${"answer ".repeat(500)}complete`,
  );
  assert.equal(plan.parts.length, 2);
  const delivery = projectSlackMultipartDelivery(
    receiptForPlan(plan, ["delivered", "paused"], "paused"),
  );

  const first = projectSlackMessages(delivery, plan);
  const retry = projectSlackMessages(delivery, planSlackMessage(
    "run-one:answer",
    `${"answer ".repeat(500)}complete`,
  ));

  assert.deepEqual(retry, first);
  assert.equal(first.state, "paused");
  assert.equal(first.parts[0]?.state, "delivered");
  assert.deepEqual(first.parts[0]?.acceptance, {
    accepted_at: "2026-07-18T10:00:02.000Z",
    destination_receipt: "slack-receipt://message/one",
  });
  assert.equal(first.parts[1]?.state, "paused");
  assert.equal(first.parts[1]?.client_message_id, "message-part-2");
  assert.match(first.projection_id, /^cerebro\.message\.[0-9a-f]{32}:sha256:[0-9a-f]{64}$/);
});

test("message projections reject changed payloads and contradictory receipts", () => {
  const plan = planSlackMessage("run-one:answer", "A durable answer");
  const delivery = projectSlackMultipartDelivery(
    receiptForPlan(plan, ["pending"], "pending"),
  );
  const changedPlan = planSlackMessage("run-one:answer", "A changed durable answer");

  assert.throws(
    () => projectSlackMessages(delivery, changedPlan),
    /payload digest does not match durable delivery truth/,
  );
  assert.throws(
    () =>
      projectSlackMessages(
        { ...delivery, part_count: 2 },
        plan,
      ),
    /part counts must match/,
  );
  assert.throws(
    () =>
      projectSlackMessages(
        {
          ...delivery,
          schema_version: "slack-multipart-projection/v2",
        } as unknown as SlackMultipartProjectionV1,
        plan,
      ),
    SlackMessageProjectionError,
  );
  assert.throws(
    () =>
      projectSlackMessages(
        delivery,
        {
          ...plan,
          source_digest: `sha256:${"0".repeat(64)}`,
        },
      ),
    /source digest does not match/,
  );
});

test("message planning rejects controls and oversize source text", () => {
  assert.throws(
    () => planSlackMessage("run-one:answer", "unsafe\u0000answer"),
    /message source text is invalid/,
  );
  assert.throws(
    () =>
      planSlackMessage(
        "run-one:answer",
        "x".repeat(MAX_SLACK_MESSAGE_SOURCE_LENGTH + 1),
      ),
    /message source text is invalid/,
  );
});

function receiptForPlan(
  plan: SlackMessagePlanV1,
  states: readonly ("delivered" | "paused" | "pending")[],
  state: DeliveryReceiptV1["state"],
): DeliveryReceiptV1 {
  assert.equal(states.length, plan.parts.length);
  return {
    created_at: "2026-07-18T10:00:00.000Z",
    delivery_id: "delivery-one",
    destination_ref: "slack-thread://channel/thread",
    parts: plan.parts.map((part, index) => {
      const partState = states[index]!;
      return {
        ...(partState === "delivered"
          ? {
              delivered_at: "2026-07-18T10:00:02.000Z",
              destination_receipt: "slack-receipt://message/one",
            }
          : {}),
        idempotency_key: `message-part-${index + 1}`,
        part_id: `part-${index + 1}`,
        payload_digest: part.payload_digest,
        payload_ref: `payload://message/${index + 1}`,
        sequence: index + 1,
        state: partState,
      };
    }),
    run_id: "run-one",
    schema_version: "delivery-receipt/v1",
    state,
    updated_at: "2026-07-18T10:00:02.000Z",
  };
}
