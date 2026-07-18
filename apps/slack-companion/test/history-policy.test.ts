import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { describe, test } from "node:test";

import type {
  SlackHistoryRetrievalReceiptV1,
  SlackHistoryRetrievalRequestV1,
} from "../src/history/contracts.js";
import { SLACK_HISTORY_LIMITS } from "../src/history/contracts.js";
import {
  planSlackHistoryRetrieval,
  SlackHistoryPolicyError,
  slackHistoryRetrievalIdentity,
  slackHistoryRetrievalReceiptIdentity,
} from "../src/history/policy.js";

function request(
  overrides: Partial<SlackHistoryRetrievalRequestV1> = {},
): SlackHistoryRetrievalRequestV1 {
  return {
    anchor: { high_water_sequence: 42, kind: "snapshot" },
    request_key: "history-request-1",
    requested_items: 30,
    schema_version: "slack-history-retrieval-request/v1",
    thread_ref: "thread:sample-1",
    ...overrides,
  };
}

function receiptDigest(
  receipt: Omit<SlackHistoryRetrievalReceiptV1, "receipt_digest">,
): string {
  const { window } = receipt;
  const values = [
    receipt.schema_version,
    receipt.receipt_id,
    receipt.request_digest,
    receipt.request_key,
    receipt.retrieval_id,
    window.schema_version,
    window.thread_ref,
    window.retrieval_id,
    window.anchor.kind,
    window.anchor.kind === "before"
      ? String(window.anchor.before_sequence)
      : String(window.anchor.high_water_sequence),
    String(window.item_limit),
  ];
  return `sha256:${createHash("sha256").update(JSON.stringify(values), "utf8").digest("hex")}`;
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
    assert.deepEqual(first.receipt.window.anchor, {
      high_water_sequence: 42,
      kind: "snapshot",
    });
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
    const changed = request({
      anchor: { high_water_sequence: 43, kind: "snapshot" },
    });

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
    assert.throws(() => planSlackHistoryRetrieval(
      request({ anchor: { high_water_sequence: -1, kind: "snapshot" } }),
      missingLookup(),
    ), /snapshot sequence/);
  });

  test("rejects a receipt whose embedded window belongs to another retrieval", () => {
    const created = planSlackHistoryRetrieval(request(), missingLookup());
    assert.equal(created.disposition, "retrieve");
    if (created.disposition !== "retrieve") assert.fail("expected retrieval");
    const withoutDigest = {
      ...created.receipt,
      window: {
        ...created.receipt.window,
        retrieval_id: "slack-history:another-window",
      },
    };
    const tampered = {
      ...withoutDigest,
      receipt_digest: receiptDigest(withoutDigest),
    };
    assert.throws(() => planSlackHistoryRetrieval(request(), {
      found: true,
      receipt: tampered,
      schema_version: "slack-history-retrieval-receipt-lookup/v1",
    }), /window retrieval identity/);
  });

  test("rejects every non-plain top-level and nested record", () => {
    const invalidRecords = [null, [], 7, () => undefined, new Date()];
    for (const invalid of invalidRecords) {
      assert.throws(
        () => planSlackHistoryRetrieval(invalid as never, missingLookup()),
        SlackHistoryPolicyError,
      );
      assert.throws(
        () => planSlackHistoryRetrieval(
          request({ anchor: invalid as never }),
          missingLookup(),
        ),
        SlackHistoryPolicyError,
      );
      assert.throws(
        () => planSlackHistoryRetrieval(request(), {
          found: true,
          receipt: invalid,
          schema_version: "slack-history-retrieval-receipt-lookup/v1",
        } as never),
        SlackHistoryPolicyError,
      );
    }
  });
});
