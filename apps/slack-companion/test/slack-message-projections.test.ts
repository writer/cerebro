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
    assert.equal(part.payload.parse, "none");
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

test("message plans keep raw URLs inert in canonical payloads", () => {
  const plan = planSlackMessage(
    "run-one:url",
    "Read https://example.com/results?run=one",
  );

  assert.equal(plan.parts[0]?.payload.parse, "none");
  assert.equal(plan.parts[0]?.payload.link_names, false);
  assert.equal(plan.parts[0]?.payload.unfurl_links, false);
  assert.equal(plan.parts[0]?.payload.unfurl_media, false);
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

test("message projections snapshot mutable stored plans", () => {
  const storedPlan = JSON.parse(JSON.stringify(
    planSlackMessage("run-one:answer", "A durable answer"),
  )) as SlackMessagePlanV1;
  const delivery = projectSlackMultipartDelivery(
    receiptForPlan(storedPlan, ["pending"], "pending"),
  );
  const projection = projectSlackMessages(delivery, storedPlan);
  const originalProjectionId = projection.projection_id;
  const originalPayloadDigest = projection.parts[0]?.payload_digest;
  const originalText = projection.parts[0]?.payload.text;
  const mutablePayload = storedPlan.parts[0]?.payload as unknown as {
    blocks: Array<{ text: { text: string } }>;
    text: string;
  };

  mutablePayload.text = "Changed after projection";
  mutablePayload.blocks[0]!.text.text = "Changed after projection";

  assert.equal(projection.parts[0]?.payload.text, originalText);
  assert.equal(projection.parts[0]?.payload.blocks[0]?.type, "section");
  assert.equal(
    (projection.parts[0]?.payload.blocks[0] as { text: { text: string } }).text.text,
    originalText,
  );
  assert.equal(projection.parts[0]?.payload_digest, originalPayloadDigest);
  assert.equal(projection.projection_id, originalProjectionId);
});

test("message projections bound stored text before reconstruction", () => {
  const validPlan = planSlackMessage("run-one:bounded", "A bounded answer");
  const delivery = projectSlackMultipartDelivery(
    receiptForPlan(validPlan, ["pending"], "pending"),
  );
  const storedPlan = JSON.parse(JSON.stringify(validPlan)) as SlackMessagePlanV1;
  const mutablePayload = storedPlan.parts[0]?.payload as unknown as {
    text: string;
  };
  mutablePayload.text = "x".repeat(MAX_SLACK_MESSAGE_PART_LENGTH * 2 + 1);

  assert.throws(
    () => projectSlackMessages(delivery, storedPlan),
    /message payload text is invalid/,
  );
  assert.deepEqual(projectSlackMessages(delivery, validPlan).parts[0]?.payload, {
    blocks: validPlan.parts[0]?.payload.blocks,
    link_names: false,
    mrkdwn: false,
    parse: "none",
    text: "A bounded answer",
    unfurl_links: false,
    unfurl_media: false,
  });
});

test("message projections reject nested block growth before serialization", () => {
  const validPlan = planSlackMessage("run-one:nested", "A bounded answer");
  const delivery = projectSlackMultipartDelivery(
    receiptForPlan(validPlan, ["pending"], "pending"),
  );
  const oversized = JSON.parse(JSON.stringify(validPlan)) as SlackMessagePlanV1;
  const oversizedPayload = oversized.parts[0]?.payload as unknown as {
    blocks: unknown[] & { toJSON?: () => never };
  };
  let serialized = false;
  oversizedPayload.blocks = new Array(51);
  oversizedPayload.blocks.toJSON = () => {
    serialized = true;
    throw new Error("caller payload was serialized");
  };
  assert.throws(
    () => projectSlackMessages(delivery, oversized),
    /exactly one section block/,
  );
  assert.equal(serialized, false);

  const actionShaped = JSON.parse(JSON.stringify(validPlan)) as SlackMessagePlanV1;
  const actionPayload = actionShaped.parts[0]?.payload as unknown as {
    blocks: unknown[];
  };
  actionPayload.blocks = [{
    block_id: "caller-action-block",
    elements: new Array(6),
    type: "actions",
  }];
  assert.throws(
    () => projectSlackMessages(delivery, actionShaped),
    /unsupported fields/,
  );

  const extraNested = JSON.parse(JSON.stringify(validPlan)) as SlackMessagePlanV1;
  const nestedText = (extraNested.parts[0]?.payload.blocks[0] as unknown as {
    text: Record<string, unknown>;
  }).text;
  nestedText.unexpected = { value: "caller-owned" };
  assert.throws(
    () => projectSlackMessages(delivery, extraNested),
    /section text contains unsupported fields/,
  );
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
  assert.throws(
    () =>
      planSlackMessage(
        "run-one:answer",
        "x".repeat(MAX_SLACK_MESSAGE_SOURCE_LENGTH * 2 + 1),
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
