import {
  MAX_SLACK_MULTIPART_PARTS,
  type SlackMultipartAcceptanceV1,
  type SlackMultipartPartProjectionV1,
  type SlackMultipartProjectionV1,
} from "./multipart.js";
import {
  contentBoundSlackIdentifier,
  MAX_SLACK_SECTION_LENGTH,
  normalizeSlackText,
  projectSlackBlocks,
  requireSlackKey,
  sha256,
  type SlackBlockV1,
} from "./blocks.js";

export const MAX_SLACK_MESSAGE_PART_LENGTH = 2_800;
export const MAX_SLACK_MESSAGE_PARTS = MAX_SLACK_MULTIPART_PARTS;
export const MAX_SLACK_MESSAGE_SOURCE_LENGTH =
  MAX_SLACK_MESSAGE_PART_LENGTH * MAX_SLACK_MESSAGE_PARTS;

export interface SlackMessagePayloadV1 {
  readonly blocks: readonly SlackBlockV1[];
  readonly link_names: false;
  readonly mrkdwn: false;
  readonly parse: "none";
  readonly text: string;
  /** These false flags disable destination-side link previews; this projector performs no I/O. */
  readonly unfurl_links: false;
  readonly unfurl_media: false;
}

export interface SlackMessagePartPlanV1 {
  readonly payload: SlackMessagePayloadV1;
  readonly payload_digest: `sha256:${string}`;
  readonly sequence: number;
}

export interface SlackMessagePlanV1 {
  readonly message_key: string;
  readonly part_count: number;
  readonly parts: readonly SlackMessagePartPlanV1[];
  readonly schema_version: "slack-message-plan/v1";
  readonly source_digest: `sha256:${string}`;
}

export interface SlackMessagePartProjectionV1 {
  readonly acceptance?: SlackMultipartAcceptanceV1;
  readonly client_message_id: string;
  readonly part_id: string;
  readonly payload: SlackMessagePayloadV1;
  readonly payload_digest: `sha256:${string}`;
  readonly payload_ref: string;
  readonly schema_version: "slack-message-part-projection/v1";
  readonly sequence: number;
  readonly state: SlackMultipartPartProjectionV1["state"];
}

export interface SlackMessageProjectionV1 {
  readonly delivery_id: string;
  readonly destination_ref: string;
  readonly part_count: number;
  readonly parts: readonly SlackMessagePartProjectionV1[];
  readonly projection_id: string;
  readonly run_id: string;
  readonly schema_version: "slack-message-projection/v1";
  readonly state: SlackMultipartProjectionV1["state"];
}

export class SlackMessageProjectionError extends Error {}

/** Builds the payload bytes that must be stored before a durable delivery plan. */
export function planSlackMessage(
  messageKey: string,
  sourceText: string,
): SlackMessagePlanV1 {
  const key = requireSlackKey(messageKey, "message key");
  const normalized = normalizeSlackText(
    sourceText,
    "message source text",
    MAX_SLACK_MESSAGE_SOURCE_LENGTH,
  );
  const chunks = splitSlackMessageText(normalized);
  if (chunks.length > MAX_SLACK_MESSAGE_PARTS) {
    throw new SlackMessageProjectionError(
      `Slack message cannot exceed ${MAX_SLACK_MESSAGE_PARTS} parts.`,
    );
  }
  const parts = chunks.map((text, index) => {
    const sequence = index + 1;
    const payload = buildPayload(key, sequence, text);
    return Object.freeze({
      payload,
      payload_digest: `sha256:${sha256(JSON.stringify(payload))}` as const,
      sequence,
    });
  });
  return Object.freeze({
    message_key: key,
    part_count: parts.length,
    parts: Object.freeze(parts),
    schema_version: "slack-message-plan/v1",
    source_digest: `sha256:${sha256(normalized)}`,
  });
}

/** Joins stored payload truth to durable receipt identities and resume state. */
export function projectSlackMessages(
  delivery: SlackMultipartProjectionV1,
  plan: SlackMessagePlanV1,
): SlackMessageProjectionV1 {
  if (delivery.schema_version !== "slack-multipart-projection/v1") {
    throw new SlackMessageProjectionError(
      "Slack multipart projection version is unsupported.",
    );
  }
  if (plan.schema_version !== "slack-message-plan/v1") {
    throw new SlackMessageProjectionError(
      "Slack message plan version is unsupported.",
    );
  }
  const messageKey = requireSlackKey(plan.message_key, "message key");
  if (
    !Array.isArray(plan.parts)
    || !Array.isArray(delivery.parts)
    || plan.part_count !== plan.parts.length
    || delivery.part_count !== delivery.parts.length
    || plan.part_count !== delivery.part_count
    || plan.part_count < 1
    || plan.part_count > MAX_SLACK_MESSAGE_PARTS
    || delivery.parts.length > MAX_SLACK_MESSAGE_PARTS
  ) {
    throw new SlackMessageProjectionError(
      "Slack message plan and durable delivery part counts must match.",
    );
  }
  const sourceDigest = requireSha256(
    plan.source_digest,
    "message source_digest",
  );
  validateStoredPlanParts(plan.parts);
  const reconstructedSource = plan.parts
    .map((part) => part.payload.text)
    .join("");
  const normalizedSource = normalizeSlackText(
    reconstructedSource,
    "message source text",
    MAX_SLACK_MESSAGE_SOURCE_LENGTH,
  );
  if (sourceDigest !== `sha256:${sha256(normalizedSource)}`) {
    throw new SlackMessageProjectionError(
      "Slack message source digest does not match its parts.",
    );
  }
  const parts = plan.parts.map((planned, index) => {
    const durable = delivery.parts[index];
    const expectedSequence = index + 1;
    if (
      durable === undefined
      || planned.sequence !== expectedSequence
      || durable.sequence !== expectedSequence
    ) {
      throw new SlackMessageProjectionError(
        "Slack message part sequences must be contiguous.",
      );
    }
    const payloadDigest = requireSha256(
      planned.payload_digest,
      "message payload_digest",
    );
    const payload = canonicalPayload(
      planned.payload,
      messageKey,
      expectedSequence,
    );
    const actualDigest = `sha256:${sha256(JSON.stringify(payload))}`;
    if (payloadDigest !== actualDigest || durable.payload_digest !== payloadDigest) {
      throw new SlackMessageProjectionError(
        "Slack message payload digest does not match durable delivery truth.",
      );
    }
    const acceptance = durable.acceptance === undefined
      ? undefined
      : Object.freeze({
          accepted_at: durable.acceptance.accepted_at,
          destination_receipt: durable.acceptance.destination_receipt,
        });
    return Object.freeze({
      ...(acceptance === undefined ? {} : { acceptance }),
      client_message_id: requireSlackKey(
        durable.client_message_id,
        "message client_message_id",
      ),
      part_id: requireSlackKey(durable.part_id, "message part_id"),
      payload,
      payload_digest: payloadDigest,
      payload_ref: durable.payload_ref,
      schema_version: "slack-message-part-projection/v1" as const,
      sequence: expectedSequence,
      state: durable.state,
    });
  });
  const frozenParts = Object.freeze(parts);
  const truth = {
    delivery_id: delivery.delivery_id,
    destination_ref: delivery.destination_ref,
    part_count: frozenParts.length,
    parts: frozenParts,
    run_id: delivery.run_id,
    schema_version: "slack-message-projection/v1" as const,
    state: delivery.state,
  };
  return Object.freeze({
    ...truth,
    projection_id: contentBoundSlackIdentifier(
      "message",
      delivery.delivery_id,
      truth,
    ),
  });
}

function splitSlackMessageText(text: string): string[] {
  const codePoints = Array.from(text);
  const chunks: string[] = [];
  let offset = 0;
  while (offset < codePoints.length) {
    let end = Math.min(offset + MAX_SLACK_MESSAGE_PART_LENGTH, codePoints.length);
    if (end < codePoints.length) {
      const earliestBreak = offset + Math.floor(MAX_SLACK_MESSAGE_PART_LENGTH / 2);
      for (let index = end - 1; index >= earliestBreak; index -= 1) {
        if (codePoints[index] === "\n" || codePoints[index] === " ") {
          end = index + 1;
          break;
        }
      }
    }
    chunks.push(codePoints.slice(offset, end).join(""));
    offset = end;
  }
  return chunks;
}

function buildPayload(
  messageKey: string,
  sequence: number,
  text: string,
): SlackMessagePayloadV1 {
  const blockProjection = projectSlackBlocks({
    projection_key: `${messageKey}:part:${sequence}`,
    sections: [text],
  });
  return Object.freeze({
    blocks: blockProjection.blocks,
    link_names: false as const,
    mrkdwn: false as const,
    parse: "none" as const,
    text,
    unfurl_links: false as const,
    unfurl_media: false as const,
  });
}

function canonicalPayload(
  payload: SlackMessagePayloadV1,
  messageKey: string,
  sequence: number,
): SlackMessagePayloadV1 {
  const normalized = normalizeSlackText(
    payload.text,
    "message payload text",
    MAX_SLACK_MESSAGE_PART_LENGTH,
  );
  const expected = buildPayload(messageKey, sequence, normalized);
  if (
    normalized !== payload.text
    || Array.from(payload.text).length > MAX_SLACK_SECTION_LENGTH
    || JSON.stringify(payload) !== JSON.stringify(expected)
  ) {
    throw new SlackMessageProjectionError(
      "Slack message payload is not the supported safe shape.",
    );
  }
  return expected;
}

/**
 * Rejects malformed persisted payloads before joining text, copying arrays, or
 * serializing caller-owned records. Canonical reconstruction below remains the
 * authority for the exact payload bytes.
 */
function validateStoredPlanParts(
  parts: readonly SlackMessagePartPlanV1[],
): void {
  let totalCodeUnits = 0;
  for (let index = 0; index < parts.length; index += 1) {
    const part = parts[index];
    requireExactRecord(
      part,
      ["payload", "payload_digest", "sequence"],
      `message part ${index + 1}`,
    );
    if (part.sequence !== index + 1) {
      throw new SlackMessageProjectionError(
        "Slack message part sequences must be contiguous.",
      );
    }
    requireSha256(part.payload_digest, "message payload_digest");
    const textLength = validateStoredPayload(part.payload, index + 1);
    totalCodeUnits += textLength;
    if (totalCodeUnits > MAX_SLACK_MESSAGE_SOURCE_LENGTH * 2) {
      throw new SlackMessageProjectionError(
        "Slack message source text is invalid.",
      );
    }
  }
}

function validateStoredPayload(
  payload: SlackMessagePayloadV1,
  sequence: number,
): number {
  requireExactRecord(
    payload,
    [
      "blocks",
      "link_names",
      "mrkdwn",
      "parse",
      "text",
      "unfurl_links",
      "unfurl_media",
    ],
    `message payload ${sequence}`,
  );
  const textLength = requireRawStringBound(
    payload.text,
    MAX_SLACK_MESSAGE_PART_LENGTH * 2,
    "message payload text",
  );
  if (
    payload.link_names !== false
    || payload.mrkdwn !== false
    || payload.parse !== "none"
    || payload.unfurl_links !== false
    || payload.unfurl_media !== false
  ) {
    throw new SlackMessageProjectionError(
      "Slack message payload is not the supported safe shape.",
    );
  }
  if (!Array.isArray(payload.blocks) || payload.blocks.length !== 1) {
    throw new SlackMessageProjectionError(
      "Slack message payload must contain exactly one section block.",
    );
  }
  const block = payload.blocks[0];
  requireExactRecord(
    block,
    ["block_id", "text", "type"],
    "message payload section block",
  );
  if (block.type !== "section") {
    throw new SlackMessageProjectionError(
      "Slack message payload must contain exactly one section block.",
    );
  }
  requireRawStringBound(block.block_id, 255, "message payload block_id");
  requireExactRecord(
    block.text,
    ["emoji", "text", "type"],
    "message payload section text",
  );
  if (block.text.emoji !== false || block.text.type !== "plain_text") {
    throw new SlackMessageProjectionError(
      "Slack message payload is not the supported safe shape.",
    );
  }
  requireRawStringBound(
    block.text.text,
    MAX_SLACK_SECTION_LENGTH * 2,
    "message payload section text",
  );
  return textLength;
}

function requireExactRecord(
  value: unknown,
  requiredKeys: readonly string[],
  field: string,
): asserts value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new SlackMessageProjectionError(`Slack ${field} is invalid.`);
  }
  let ownKeyCount = 0;
  for (const key in value) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) continue;
    ownKeyCount += 1;
    if (ownKeyCount > requiredKeys.length || !requiredKeys.includes(key)) {
      throw new SlackMessageProjectionError(
        `Slack ${field} contains unsupported fields.`,
      );
    }
  }
  if (
    ownKeyCount !== requiredKeys.length
    || requiredKeys.some(
      (key) => !Object.prototype.hasOwnProperty.call(value, key),
    )
  ) {
    throw new SlackMessageProjectionError(`Slack ${field} is incomplete.`);
  }
}

function requireRawStringBound(
  value: unknown,
  maximumCodeUnits: number,
  field: string,
): number {
  if (
    typeof value !== "string"
    || value.length === 0
    || value.length > maximumCodeUnits
  ) {
    throw new SlackMessageProjectionError(`Slack ${field} is invalid.`);
  }
  return value.length;
}

function requireSha256(value: string, field: string): `sha256:${string}` {
  if (!/^sha256:[0-9a-f]{64}$/.test(value)) {
    throw new SlackMessageProjectionError(`${field} is invalid.`);
  }
  return value as `sha256:${string}`;
}
