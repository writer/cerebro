import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";

import {
  SLACK_HISTORY_LIMITS,
  type SlackHistoryAnchorV1,
  type SlackHistoryRetrievalDecisionV1,
  type SlackHistoryRetrievalReceiptLookupV1,
  type SlackHistoryRetrievalReceiptV1,
  type SlackHistoryRetrievalRequestV1,
  type SlackHistoryWindowPolicyV1,
  type SlackHistoryWindowV1,
} from "./contracts.js";

const SHA256_DIGEST = /^sha256:[a-f0-9]{64}$/;
const UNSAFE_CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/;

export const DEFAULT_SLACK_HISTORY_WINDOW_POLICY: SlackHistoryWindowPolicyV1 =
  Object.freeze({
    default_items: SLACK_HISTORY_LIMITS.default_items,
    max_items: SLACK_HISTORY_LIMITS.max_items,
    schema_version: "slack-history-window-policy/v1",
  });

export class SlackHistoryPolicyError extends Error {}

export function slackHistoryRetrievalIdentity(
  threadRef: string,
  requestKey: string,
): string {
  requireRef(threadRef, "thread_ref");
  requireRequestKey(requestKey);
  return `slack-history:${stableDigest([threadRef, requestKey]).slice(0, 32)}`;
}

export function slackHistoryRetrievalReceiptIdentity(
  retrievalId: string,
): string {
  requireRef(retrievalId, "retrieval_id");
  return `slack-history-receipt:${stableDigest([retrievalId])}`;
}

/**
 * Plans one bounded history window. The host supplies a durable receipt lookup;
 * exact retries replay the original window even if later policy is narrower.
 */
export function planSlackHistoryRetrieval(
  request: SlackHistoryRetrievalRequestV1,
  receiptLookup: SlackHistoryRetrievalReceiptLookupV1,
  policy: SlackHistoryWindowPolicyV1 = DEFAULT_SLACK_HISTORY_WINDOW_POLICY,
): SlackHistoryRetrievalDecisionV1 {
  const normalized = normalizeRequest(request);
  const normalizedPolicy = normalizePolicy(policy);
  const retrievalId = slackHistoryRetrievalIdentity(
    normalized.thread_ref,
    normalized.request_key,
  );
  const receiptId = slackHistoryRetrievalReceiptIdentity(retrievalId);
  const requestDigest = historyRequestDigest(normalized);
  validateLookup(receiptLookup, receiptId);

  if (receiptLookup.found) {
    const receipt = snapshotReceipt(receiptLookup.receipt);
    if (
      receipt.retrieval_id !== retrievalId
      || receipt.request_key !== normalized.request_key
      || receipt.window.thread_ref !== normalized.thread_ref
    ) {
      throw new SlackHistoryPolicyError(
        "The history receipt does not match its retrieval identity.",
      );
    }
    if (receipt.request_digest !== requestDigest) {
      return Object.freeze({
        disposition: "reject",
        reason_code: "idempotency_conflict",
        receipt_ref: receipt.receipt_id,
        schema_version: "slack-history-retrieval-decision/v1",
      });
    }
    return Object.freeze({
      created: false,
      disposition: "replay",
      receipt,
      schema_version: "slack-history-retrieval-decision/v1",
    });
  }

  const requestedItems = normalized.requested_items
    ?? normalizedPolicy.default_items;
  const window = freezeWindow({
    anchor: normalized.anchor,
    item_limit: Math.min(requestedItems, normalizedPolicy.max_items),
    retrieval_id: retrievalId,
    schema_version: "slack-history-window/v1",
    thread_ref: normalized.thread_ref,
  });
  const receiptWithoutDigest = {
    receipt_id: receiptId,
    request_digest: requestDigest,
    request_key: normalized.request_key,
    retrieval_id: retrievalId,
    schema_version: "slack-history-retrieval-receipt/v1" as const,
    window,
  };
  const receipt = Object.freeze({
    ...receiptWithoutDigest,
    receipt_digest: historyReceiptDigest(receiptWithoutDigest),
  });
  return Object.freeze({
    created: true,
    disposition: "retrieve",
    receipt,
    schema_version: "slack-history-retrieval-decision/v1",
  });
}

function normalizeRequest(
  request: SlackHistoryRetrievalRequestV1,
): SlackHistoryRetrievalRequestV1 {
  exactKeys(
    request,
    ["anchor", "request_key", "requested_items", "schema_version", "thread_ref"],
    "history retrieval request",
  );
  if (request.schema_version !== "slack-history-retrieval-request/v1") {
    throw new SlackHistoryPolicyError("The history retrieval request version is unsupported.");
  }
  requireRef(request.thread_ref, "thread_ref");
  requireRequestKey(request.request_key);
  const anchor = normalizeAnchor(request.anchor);
  if (
    request.requested_items !== undefined
    && (
      !Number.isSafeInteger(request.requested_items)
      || request.requested_items < 1
      || request.requested_items > SLACK_HISTORY_LIMITS.max_items
    )
  ) {
    throw new SlackHistoryPolicyError("The requested history item count is out of bounds.");
  }
  return Object.freeze({
    anchor,
    request_key: request.request_key,
    ...(request.requested_items === undefined
      ? {}
      : { requested_items: request.requested_items }),
    schema_version: "slack-history-retrieval-request/v1",
    thread_ref: request.thread_ref,
  });
}

function normalizeAnchor(anchor: SlackHistoryAnchorV1): SlackHistoryAnchorV1 {
  if (anchor === null || typeof anchor !== "object") {
    throw new SlackHistoryPolicyError("The history anchor is invalid.");
  }
  if (anchor.kind === "latest") {
    exactKeys(anchor, ["kind"], "latest history anchor");
    return Object.freeze({ kind: "latest" });
  }
  if (anchor.kind !== "before") {
    throw new SlackHistoryPolicyError("The history anchor kind is unsupported.");
  }
  exactKeys(anchor, ["before_sequence", "kind"], "before history anchor");
  if (!Number.isSafeInteger(anchor.before_sequence) || anchor.before_sequence < 1) {
    throw new SlackHistoryPolicyError("The history anchor sequence is invalid.");
  }
  return Object.freeze({
    before_sequence: anchor.before_sequence,
    kind: "before",
  });
}

function normalizePolicy(
  policy: SlackHistoryWindowPolicyV1,
): SlackHistoryWindowPolicyV1 {
  exactKeys(policy, ["default_items", "max_items", "schema_version"], "history policy");
  if (policy.schema_version !== "slack-history-window-policy/v1") {
    throw new SlackHistoryPolicyError("The history policy version is unsupported.");
  }
  if (
    !Number.isSafeInteger(policy.default_items)
    || !Number.isSafeInteger(policy.max_items)
    || policy.default_items < 1
    || policy.max_items < policy.default_items
    || policy.max_items > SLACK_HISTORY_LIMITS.max_items
  ) {
    throw new SlackHistoryPolicyError("The history policy bounds are invalid.");
  }
  return Object.freeze({ ...policy });
}

function validateLookup(
  lookup: SlackHistoryRetrievalReceiptLookupV1,
  receiptId: string,
): void {
  if (lookup.schema_version !== "slack-history-retrieval-receipt-lookup/v1") {
    throw new SlackHistoryPolicyError("The history receipt lookup version is unsupported.");
  }
  if (lookup.found) {
    exactKeys(lookup, ["found", "receipt", "schema_version"], "history receipt lookup");
    if (lookup.receipt.receipt_id !== receiptId) {
      throw new SlackHistoryPolicyError("The history receipt lookup returned a different receipt.");
    }
    return;
  }
  exactKeys(lookup, ["found", "receipt_id", "schema_version"], "history receipt lookup");
  if (lookup.receipt_id !== receiptId) {
    throw new SlackHistoryPolicyError("The history receipt lookup key is invalid.");
  }
}

function snapshotReceipt(
  receipt: SlackHistoryRetrievalReceiptV1,
): SlackHistoryRetrievalReceiptV1 {
  exactKeys(receipt, [
    "receipt_digest",
    "receipt_id",
    "request_digest",
    "request_key",
    "retrieval_id",
    "schema_version",
    "window",
  ], "history receipt");
  if (receipt.schema_version !== "slack-history-retrieval-receipt/v1") {
    throw new SlackHistoryPolicyError("The history receipt version is unsupported.");
  }
  requireRef(receipt.retrieval_id, "retrieval_id");
  requireRequestKey(receipt.request_key);
  if (!SHA256_DIGEST.test(receipt.request_digest)) {
    throw new SlackHistoryPolicyError("The history request digest is invalid.");
  }
  const window = validateWindow(receipt.window);
  const expectedId = slackHistoryRetrievalReceiptIdentity(receipt.retrieval_id);
  if (receipt.receipt_id !== expectedId) {
    throw new SlackHistoryPolicyError("The history receipt identity is invalid.");
  }
  const snapshot = {
    receipt_id: receipt.receipt_id,
    request_digest: receipt.request_digest,
    request_key: receipt.request_key,
    retrieval_id: receipt.retrieval_id,
    schema_version: "slack-history-retrieval-receipt/v1" as const,
    window,
  };
  const digest = historyReceiptDigest(snapshot);
  if (receipt.receipt_digest !== digest) {
    throw new SlackHistoryPolicyError("The history receipt digest is invalid.");
  }
  return Object.freeze({ ...snapshot, receipt_digest: digest });
}

function validateWindow(window: SlackHistoryWindowV1): SlackHistoryWindowV1 {
  exactKeys(
    window,
    ["anchor", "item_limit", "retrieval_id", "schema_version", "thread_ref"],
    "history window",
  );
  if (window.schema_version !== "slack-history-window/v1") {
    throw new SlackHistoryPolicyError("The history window version is unsupported.");
  }
  requireRef(window.retrieval_id, "retrieval_id");
  requireRef(window.thread_ref, "thread_ref");
  if (
    !Number.isSafeInteger(window.item_limit)
    || window.item_limit < 1
    || window.item_limit > SLACK_HISTORY_LIMITS.max_items
  ) {
    throw new SlackHistoryPolicyError("The history window item limit is invalid.");
  }
  return freezeWindow({ ...window, anchor: normalizeAnchor(window.anchor) });
}

function freezeWindow(window: SlackHistoryWindowV1): SlackHistoryWindowV1 {
  return Object.freeze({ ...window, anchor: normalizeAnchor(window.anchor) });
}

function historyRequestDigest(request: SlackHistoryRetrievalRequestV1): string {
  return sha256([
    request.schema_version,
    request.thread_ref,
    request.request_key,
    request.anchor.kind,
    request.anchor.kind === "before" ? String(request.anchor.before_sequence) : "",
    request.requested_items === undefined ? "" : String(request.requested_items),
  ]);
}

function historyReceiptDigest(
  receipt: Omit<SlackHistoryRetrievalReceiptV1, "receipt_digest">,
): string {
  return sha256([
    receipt.schema_version,
    receipt.receipt_id,
    receipt.request_digest,
    receipt.request_key,
    receipt.retrieval_id,
    receipt.window.schema_version,
    receipt.window.thread_ref,
    receipt.window.retrieval_id,
    receipt.window.anchor.kind,
    receipt.window.anchor.kind === "before"
      ? String(receipt.window.anchor.before_sequence)
      : "",
    String(receipt.window.item_limit),
  ]);
}

function requireRef(value: unknown, label: string): asserts value is string {
  requireText(value, SLACK_HISTORY_LIMITS.ref_utf8_bytes, label);
}

function requireRequestKey(value: unknown): asserts value is string {
  requireText(value, SLACK_HISTORY_LIMITS.request_key_utf8_bytes, "request_key");
  if (/\s/.test(value)) {
    throw new SlackHistoryPolicyError("The history request key cannot contain whitespace.");
  }
}

function requireText(
  value: unknown,
  maximumBytes: number,
  label: string,
): asserts value is string {
  if (
    typeof value !== "string"
    || value.length === 0
    || Buffer.byteLength(value, "utf8") > maximumBytes
    || UNSAFE_CONTROL_CHARACTERS.test(value)
  ) {
    throw new SlackHistoryPolicyError(`The ${label} is invalid.`);
  }
}

function exactKeys(value: object, allowed: readonly string[], label: string): void {
  const allowedKeys = new Set(allowed);
  if (Object.keys(value).some((key) => !allowedKeys.has(key))) {
    throw new SlackHistoryPolicyError(`The ${label} contains unknown fields.`);
  }
}

function stableDigest(values: readonly string[]): string {
  return createHash("sha256").update(JSON.stringify(values), "utf8").digest("hex");
}

function sha256(values: readonly string[]): string {
  return `sha256:${stableDigest(values)}`;
}
