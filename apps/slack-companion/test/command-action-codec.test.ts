import assert from "node:assert/strict";
import test from "node:test";
import {
  decodeSlackActionEnvelope,
  decodeSlackCommandEnvelope,
  encodeSlackActionEnvelope,
  encodeSlackCommandEnvelope,
  SlackCommandCodecError,
  type SlackActionEnvelopeV1,
} from "../src/index.js";

test("command and action envelopes round trip through bounded Slack values", () => {
  const command = {
    arguments: ["case://canonical/123", "approve"],
    command: "case.command",
    issued_at: "2026-07-18T10:00:00.000Z",
    request_id: "request-123",
    schema_version: "slack-command-envelope/v1" as const,
  };
  assert.deepEqual(decodeSlackCommandEnvelope(encodeSlackCommandEnvelope(command)), command);

  const action: SlackActionEnvelopeV1 = {
    action: "execute",
    command: "case.command",
    idempotency_key: "action-123",
    issued_at: "2026-07-18T10:00:01.000Z",
    parameters: { revision: "7", result: "approved" },
    schema_version: "slack-action-envelope/v1",
    subject_ref: "case://canonical/123",
  };
  const encoded = encodeSlackActionEnvelope(action);
  assert.deepEqual(decodeSlackActionEnvelope(encoded), action);
  assert.equal(encodeSlackActionEnvelope(action), encoded);
});

test("action codec rejects unknown, malformed, and oversized values", () => {
  const raw = (value: unknown) => Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
  assert.throws(() => decodeSlackActionEnvelope(""), SlackCommandCodecError);
  assert.throws(() => decodeSlackActionEnvelope("not+base64url"), SlackCommandCodecError);
  assert.throws(
    () =>
      decodeSlackActionEnvelope(
        raw({
          action: "execute",
          command: "case.command",
          idempotency_key: "action-123",
          issued_at: "2026-07-18T10:00:01.000Z",
          schema_version: "slack-action-envelope/v2",
        }),
      ),
    /version is unsupported/,
  );
  assert.throws(
    () =>
      decodeSlackActionEnvelope(
        raw({
          action: "execute",
          command: "case.command",
          idempotency_key: "action-123",
          issued_at: "2026-07-18T10:00:01.000Z",
          schema_version: "slack-action-envelope/v1",
          unexpected: "value",
        }),
      ),
    /unknown fields/,
  );
  assert.throws(
    () =>
      encodeSlackActionEnvelope({
        action: "execute",
        command: "case.command",
        idempotency_key: "action-123",
        issued_at: "2026-07-18T10:00:01.000Z",
        parameters: { payload: "x".repeat(513) },
        schema_version: "slack-action-envelope/v1",
      }),
    /payload is invalid/,
  );
  assert.throws(
    () =>
      encodeSlackActionEnvelope({
        action: "execute",
        command: "case.command",
        idempotency_key: "action-123",
        issued_at: "2026-07-18T10:00:01Z",
        schema_version: "slack-action-envelope/v1",
      }),
    /canonical ISO-8601 timestamp/,
  );
  assert.throws(
    () =>
      encodeSlackActionEnvelope({
        action: "execute",
        command: "case.command",
        idempotency_key: "action-123",
        issued_at: "2026-07-18T10:00:01.000Z",
        parameters: {
          first: "x".repeat(512),
          second: "y".repeat(512),
          third: "z".repeat(269),
        },
        schema_version: "slack-action-envelope/v1",
      }),
    /encoded value exceeds the supported size/,
  );
});
