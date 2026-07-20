import assert from "node:assert/strict";
import { describe, test } from "node:test";

import {
  redactSecurityText,
  redactSecurityTextWithReceipt,
  SecurityRedactionInputError,
} from "../src/security/redaction.js";

describe("security text redaction", () => {
  test("redacts recognized credential-shaped values", () => {
    const slackLike = ["xoxb", "synthetic", "fixture"].join("-");
    const cloudLike = ["AK", "IA", "A".repeat(16)].join("");
    const privateKeyLike = [
      ["-----BEGIN ", "RSA", " PRIVATE KEY-----"].join(""),
      "synthetic fixture body",
      ["-----END ", "RSA", " PRIVATE KEY-----"].join(""),
    ].join("\n");
    const assignmentLike = ["api_key", "=", "synthetic-fixture"].join("");

    assert.equal(
      redactSecurityText(
        [slackLike, cloudLike, privateKeyLike, assignmentLike].join("\n"),
      ),
      [
        "[redacted_slack_token]",
        "[redacted_cloud_access_key]",
        "[redacted_private_key]",
        "api_key=[redacted_secret]",
      ].join("\n"),
    );
  });

  test("redacts quoted assignments and every repeated value", () => {
    const input = [
      ["token", ": ", '"first-fixture"'].join(""),
      ["PASSWORD", "=", "second-fixture"].join(""),
      ["bearer", ":", "third-fixture"].join(""),
    ].join("; ");

    assert.equal(
      redactSecurityText(input),
      "token=[redacted_secret]; PASSWORD=[redacted_secret]; bearer=[redacted_secret]",
    );
  });

  test("returns deterministic redaction metadata and caller-selected labels", () => {
    const input = [
      ["xoxb", "synthetic", "fixture"].join("-"),
      ["AK", "IA", "A".repeat(16)].join(""),
      ["token", "=", "synthetic-fixture"].join(""),
    ].join("\n");

    assert.deepEqual(redactSecurityTextWithReceipt(input, {
      labels: {
        cloud_access_key: "[redacted_access_key]",
        slack_token: "[redacted_token]",
      },
    }), {
      redacted_text: [
        "[redacted_token]",
        "[redacted_access_key]",
        "token=[redacted_secret]",
      ].join("\n"),
      redaction_classes: ["assigned_secret", "cloud_access_key", "slack_token"],
      redaction_count: 3,
      schema_version: "security-redaction-receipt/v1",
    });
  });

  test("preserves ordinary security text and identifier names", () => {
    const input =
      "Check the secret path reference, token rotation status, and API key owner.";

    assert.equal(redactSecurityText(input), input);
  });

  test("rejects non-string and oversized runtime input without partial output", () => {
    assert.throws(
      () => redactSecurityText(7 as unknown as string),
      SecurityRedactionInputError,
    );
    assert.throws(
      () => redactSecurityText("a".repeat(65_537)),
      /exceeds 65536 code units/,
    );
  });
});
