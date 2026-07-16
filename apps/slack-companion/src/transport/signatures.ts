import { createHmac, timingSafeEqual } from "node:crypto";

export const DEFAULT_SLACK_SIGNATURE_MAX_SKEW_SECONDS = 300;

export type SlackSignatureVerification =
  | { verified: true }
  | {
      reason:
        | "invalid_signature"
        | "invalid_timestamp"
        | "stale_timestamp";
      verified: false;
    };

export interface SlackSignatureInput {
  max_skew_seconds?: number;
  now: Date;
  raw_body: Uint8Array;
  request_signature: string;
  request_timestamp: string;
}

/**
 * Verifies Slack's v0 signature over the exact request bytes. The signing
 * secret exists only for this call and is not captured or retained.
 */
export function verifySlackRequestSignature(
  input: SlackSignatureInput,
  signingSecret: string | Uint8Array,
): SlackSignatureVerification {
  const timestamp = parseTimestamp(input.request_timestamp);
  if (timestamp === undefined) {
    return { reason: "invalid_timestamp", verified: false };
  }

  const maxSkew =
    input.max_skew_seconds ?? DEFAULT_SLACK_SIGNATURE_MAX_SKEW_SECONDS;
  if (!Number.isSafeInteger(maxSkew) || maxSkew < 0) {
    throw new Error("max_skew_seconds must be a non-negative safe integer");
  }

  const now = Math.floor(input.now.getTime() / 1_000);
  if (!Number.isSafeInteger(now)) {
    throw new Error("now must be a valid date");
  }
  if (Math.abs(now - timestamp) > maxSkew) {
    return { reason: "stale_timestamp", verified: false };
  }

  const suppliedMatch = /^v0=([a-f0-9]{64})$/i.exec(input.request_signature);
  if (suppliedMatch === null) {
    return { reason: "invalid_signature", verified: false };
  }

  const rawBody = Buffer.from(
    input.raw_body.buffer,
    input.raw_body.byteOffset,
    input.raw_body.byteLength,
  );
  const expected = createHmac("sha256", signingSecret)
    .update("v0:")
    .update(input.request_timestamp)
    .update(":")
    .update(rawBody)
    .digest();
  const supplied = Buffer.from(suppliedMatch[1], "hex");

  if (!timingSafeEqual(expected, supplied)) {
    return { reason: "invalid_signature", verified: false };
  }
  return { verified: true };
}

function parseTimestamp(value: string): number | undefined {
  if (!/^\d+$/.test(value)) {
    return undefined;
  }
  const timestamp = Number(value);
  return Number.isSafeInteger(timestamp) ? timestamp : undefined;
}
