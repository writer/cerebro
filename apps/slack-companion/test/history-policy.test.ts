import assert from "node:assert/strict";
import { describe, test } from "node:test";

import type { SlackHistoryRetrievalRequestV1 } from "../src/history/contracts.js";
import { SLACK_HISTORY_LIMITS } from "../src/history/contracts.js";
import {
  planSlackHistoryRetrieval,
  slackHistoryRetrievalIdentity,
  slackHistoryRetrievalReceiptIdentity,
} from "../src/history/policy.js";

function request(
  overrides: Partial<SlackHistoryRetrievalRequestV1> = {},
): SlackHistoryRetrievalRequestV1 {
  return {
    anchor: { before_sequence: 42, kind: "before" },
    request_key: "history-request-1",
    requested_items: 30,
    schema_version: "slack-history-retrieval-request/v1",
    thread_ref: "thread:sample-1",
    ...overrides,
  };
}

function missingLookup(value = request()) {
  const retrievalId = slackHistoryRetrievalIdentity(value.thread_ref, value.request_key);
  return {
    found: false as const,
    receipt_id: slackHistoryRetrievalReceiptIdentity(retrievalId),
    schema_version: "slack-history-retrieval-receipt-lookup/v1" as const,
  };
}

describe("bounded Slack history retrieval", () => {
  test("creates one deterministic immutable window within policy bounds", () => {
    const first = planSlackHistoryRetrieval(request(), missingLookup(), {
      default_items: 10,
      max_items: 12,
      schema_version: "slack-history-window-policy/v1",
    });
    const second = planSlackHistoryRetrieval(request(), missingLookup(), {
      default_items: 10,
      max_items: 12,
      schema_version: "slack-history-window-policy/v1",
    });

    assert.deepEqual(second, first);
    assert.equal(first.disposition, "retrieve");
    if (first.disposition !== "retrieve") assert.fail("expected retrieval");
    assert.equal(first.receipt.window.item_limit, 12);
    assert.deepEqual(first.receipt.window.anchor, { before_sequence: 42, kind: "before" });
    assert.match(first.receipt.request_digest, /^sha256:[a-f0-9]{64}$/);
    assert.match(first.receipt.receipt_digest, /^sha256:[a-f0-9]{64}$/);
    assert.equal(Object.isFrozen(first), true);
    assert.equal(Object.isFrozen(first.receipt), true);
    assert.equal(Object.isFrozen(first.receipt.window), true);
    assert.equal(Object.isFrozen(first.receipt.window.anchor), true);
  });

  test("replays the durable original window after policy changes", () => {
    const created = planSlackHistoryRetrieval(request(), missingLookup());
    assert.equal(created.disposition, "retrieve");
    if (created.disposition !== "retrieve") assert.fail("expected retrieval");

    const replay = planSlackHistoryRetrieval(request(), {
      found: true,
      receipt: created.receipt,
      schema_version: "slack-history-retrieval-receipt-lookup/v1",
    }, {
      default_items: 1,
      max_items: 1,
      schema_version: "slack-history-window-policy/v1",
    });
    assert.equal(replay.disposition, "replay");
    if (replay.disposition !== "replay") assert.fail("expected replay");
    assert.deepEqual(replay.receipt, created.receipt);
    assert.equal(replay.receipt.window.item_limit, 30);
  });

  test("rejects a changed request under the same idempotency identity", () => {
    const original = planSlackHistoryRetrieval(request(), missingLookup());
    assert.equal(original.disposition, "retrieve");
    if (original.disposition !== "retrieve") assert.fail("expected retrieval");
    const changed = request({ anchor: { kind: "latest" } });

    assert.deepEqual(planSlackHistoryRetrieval(changed, {
      found: true,
      receipt: original.receipt,
      schema_version: "slack-history-retrieval-receipt-lookup/v1",
    }), {
      disposition: "reject",
      reason_code: "idempotency_conflict",
      receipt_ref: original.receipt.receipt_id,
      schema_version: "slack-history-retrieval-decision/v1",
    });
  });

  test("rejects tampered receipts, invalid windows, and UTF-8 overflow", () => {
    const created = planSlackHistoryRetrieval(request(), missingLookup());
    assert.equal(created.disposition, "retrieve");
    if (created.disposition !== "retrieve") assert.fail("expected retrieval");
    assert.throws(() => planSlackHistoryRetrieval(request(), {
      found: true,
      receipt: {
        ...created.receipt,
        window: { ...created.receipt.window, item_limit: 29 },
      },
      schema_version: "slack-history-retrieval-receipt-lookup/v1",
    }), /receipt digest/);
    assert.throws(() => planSlackHistoryRetrieval(
      request({ requested_items: SLACK_HISTORY_LIMITS.max_items + 1 }),
      missingLookup(),
    ), /out of bounds/);
    const unicodeKey = "é".repeat(SLACK_HISTORY_LIMITS.request_key_utf8_bytes / 2 + 1);
    assert.throws(() => planSlackHistoryRetrieval(
      request({ request_key: unicodeKey }),
      missingLookup(request({ request_key: "safe" })),
    ), /request_key is invalid/);
    assert.throws(() => planSlackHistoryRetrieval(
      request({ anchor: { before_sequence: 0, kind: "before" } }),
      missingLookup(),
    ), /anchor sequence/);
  });
});
